// A fixed-upstream connector, not an arbitrary URL proxy. Local-only bootstrap.
import http from 'node:http';
import fs from 'node:fs';
import { WebSocket } from 'ws';
import { signDetached, fromBase64Url, openJson, type Sealed } from '@a2n/protocol';

export interface ProviderConfig {
  handle:string; relay:string;
  identityFile:string; // local JSON {privateKey:base64url,xPrivateKey:base64url}; never published
  upstream:string;
  upstreamTokenFile?:string;
  routes:[string,string][];
  maxBytes?:number;
  timeoutMs?:number;
  heartbeatMs?:number;
}
export function validatePath(p:unknown):string {
  if(typeof p!=='string'||p.length>1024||!p.startsWith('/')||p.startsWith('//')||p.includes('\\')||p.includes('#')||/[\u0000-\u0020\u007f]/.test(p))throw Error('invalid_path');
  // Decode repeatedly to catch double-encoded traversal and escaped separators.
  let v=p;
  for(let i=0;i<4;i++){
    if(v.includes('\\')||v.includes('//')||v.split(/[/?]/).some(x=>x==='.'||x==='..'))throw Error('invalid_path');
    let d:string;try{d=decodeURIComponent(v);}catch{throw Error('invalid_path');}
    if(d===v)return p;v=d;
  }
  throw Error('excessive_encoding');
}
function readSecret(file:string):string {
  const st=fs.lstatSync(file);
  if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)!==0||(process.getuid&&st.uid!==process.getuid()))throw Error('secret_file_permissions');
  return fs.readFileSync(file,'utf8').trim();
}
export function prepareUpstream(c:ProviderConfig){
  const u=new URL(c.upstream);
  if(u.protocol!=='http:'||u.hostname!=='127.0.0.1'||u.username||u.password||u.pathname!=='/'||u.search||u.hash)throw Error('upstream_must_be_fixed_loopback_origin');
  for(const [m,p]of c.routes){if(!['GET','POST'].includes(m)||validatePath(p)!==p||p.includes('?'))throw Error('invalid_route');}
  return u;
}
export interface Call {method:string;path:string;headers?:Record<string,string>;bodyBase64:string}
export interface CallResult {status:number;contentType:string;bodyBase64:string}
export async function forward(c:ProviderConfig,call:Call):Promise<CallResult>{
  const upstream=prepareUpstream(c);
  const p=validatePath(call.path);
  // Query parameters are not accepted unless an exact route was explicitly configured (bootstrap: none).
  if(!c.routes.some(([m,path])=>m===call.method&&path===p))throw Error('route_not_allowed');
  const body=Buffer.from(call.bodyBase64,'base64');
  const max=c.maxBytes??1024*1024;
  if(body.length>max)return {status:413,contentType:'application/json',bodyBase64:Buffer.from('{"error":{"code":"request_body_too_large"}}').toString('base64')};
  const headers:Record<string,string>={host:upstream.host,'content-length':String(body.length)};
  // Allowlist only: no user auth, cookies, host, transfer-encoding, forwarded headers, or X-A2N headers.
  const ct=Object.entries(call.headers??{}).find(([k])=>k.toLowerCase()==='content-type')?.[1];
  if(ct){if(typeof ct!=='string'||ct.length>128||/[\r\n]/.test(ct))throw Error('invalid_content_type');headers['content-type']=ct;}
  if(c.upstreamTokenFile){const token=readSecret(c.upstreamTokenFile);if(!token||/[\r\n]/.test(token))throw Error('invalid_local_token');headers.authorization='Bearer '+token;}
  return await new Promise<CallResult>((resolve,reject)=>{
    let bytes=0;const parts:Buffer[]=[];
    const req=http.request({hostname:'127.0.0.1',port:upstream.port||80,path:p,method:call.method,headers,agent:false},res=>{
      res.on('data',(chunk:Buffer)=>{bytes+=chunk.length;if(bytes>max){req.destroy(Error('response_too_large'));return;}parts.push(chunk);});
      res.on('error',reject);
      res.on('end',()=>resolve({status:res.statusCode??502,contentType:String(res.headers['content-type']??'application/octet-stream').slice(0,128),bodyBase64:Buffer.concat(parts).toString('base64')}));
    });
    const timer=setTimeout(()=>req.destroy(Error('upstream_timeout')),c.timeoutMs??15000);
    req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end(body);
  });
}
export function startProvider(c:ProviderConfig,onEvent:(event:string)=>void=()=>{}){
  prepareUpstream(c);
  const relay=new URL(c.relay);
  if(relay.protocol!=='wss:'&&!(relay.protocol==='ws:'&&relay.hostname==='127.0.0.1'))throw Error('relay_requires_wss');
  const key=JSON.parse(readSecret(c.identityFile)) as {privateKey:string;xPrivateKey:string};
  let ws:WebSocket|undefined;let heartbeat:NodeJS.Timeout|undefined;let retry:NodeJS.Timeout|undefined;let stopped=false;let busy=false;
  function connect(){
    ws=new WebSocket(c.relay,{maxPayload:(c.maxBytes??1024*1024)*2+65536,handshakeTimeout:5000});
    ws.on('message',async raw=>{
      try{
        const b=JSON.parse(raw.toString());
        if(b.type==='challenge')ws!.send(JSON.stringify({type:'auth',handle:c.handle,signature:signDetached({challenge:b.challenge,handle:c.handle},fromBase64Url(key.privateKey),'provider:'+c.handle)}));
        else if(b.type==='ready'){
          onEvent('ready');heartbeat=setInterval(()=>{if(ws?.readyState===WebSocket.OPEN)ws.send(JSON.stringify({type:'heartbeat'}));},c.heartbeatMs??30000);
        }else if(b.type==='request'){
          if(busy){ws!.send(JSON.stringify({type:'result',id:b.id,status:429,contentType:'application/json',bodyBase64:Buffer.from('{"error":{"code":"provider_busy"}}').toString('base64')}));return;}
          busy=true;let result:CallResult;
          try{
            const payload=openJson<any>(fromBase64Url(key.xPrivateKey),b.box as Sealed,'a2n-inbox:'+b.id);
            if(b.kind==='message'){
              // Demo inbox: receipt-style acknowledgement only. Never execute message instructions.
              result={status:200,contentType:'application/json',bodyBase64:Buffer.from(JSON.stringify({received:true,reply:'Your inquiry was received. Demo only; no task executed.',message:payload.message})).toString('base64')};
            }else result=await forward(c,payload);
          }catch(e){result={status:502,contentType:'application/json',bodyBase64:Buffer.from(JSON.stringify({error:{code:'provider_request_rejected'}})).toString('base64')};onEvent('request_rejected');}
          if(ws?.readyState===WebSocket.OPEN)ws.send(JSON.stringify({type:'result',id:b.id,...result}));busy=false;
        }
      }catch{onEvent('invalid_relay_frame');ws?.close(1008,'invalid_frame');}
    });
    ws.on('error',()=>onEvent('connection_error'));
    ws.on('close',()=>{if(heartbeat)clearInterval(heartbeat);onEvent('offline');if(!stopped)retry=setTimeout(connect,1000);});
  }
  connect();
  return {stop:async()=>{stopped=true;if(retry)clearTimeout(retry);if(heartbeat)clearInterval(heartbeat);ws?.terminate();}};
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
  const configPath=process.argv[2];if(!configPath)throw Error('usage: provider.ts CONFIG');
  const c=JSON.parse(readSecret(configPath)) as ProviderConfig;
  const p=startProvider(c,e=>console.error('provider:'+e));
  for(const sig of ['SIGINT','SIGTERM'] as const)process.on(sig,()=>{void p.stop().then(()=>process.exit());});
}
