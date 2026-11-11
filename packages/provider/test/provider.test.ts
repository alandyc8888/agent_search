import { describe,it,expect } from 'vitest';
import http from 'node:http';
import { once } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { forward,validatePath,prepareUpstream,type ProviderConfig } from '../src/provider.ts';
const base:ProviderConfig={handle:'test',relay:'ws://127.0.0.1:8790/relay/v0/provider',identityFile:'unused',upstream:'http://127.0.0.1:8791',routes:[['POST','/zip/pack']],maxBytes:1024};
describe('fixed upstream / P1 controls',()=>{
  it('rejects traversal, absolute URLs, escaped separators and other origins',()=>{
    for(const p of ['http://169.254.169.254/','//127.0.0.1:22/','/../x','/%2e%2e/x','/%252e%252e/x','/zip\\..\\x','/zip/%2f%2fmetadata','/x\r\ny'])expect(()=>validatePath(p)).toThrow();
    for(const u of ['http://169.254.169.254','http://localhost','http://127.0.0.1/other','http://user@127.0.0.1'])expect(()=>prepareUpstream({...base,upstream:u})).toThrow();
  });
  it('rejects paths and query changes outside exact routes',async()=>{
    for(const p of ['/zip/pack?url=http://127.0.0.1:5432','/capabilities','/zip/extract'])await expect(forward(base,{method:'POST',path:p,bodyBase64:''})).rejects.toThrow();
  });
  it('replaces client Authorization once and ignores Host and forwarding headers',async()=>{
    const dir=fs.mkdtempSync(path.join(os.tmpdir(),'a2n-provider-test-'));
    const tokenFile=path.join(dir,'auth');const token=crypto.randomUUID();fs.writeFileSync(tokenFile,token,{mode:0o600});
    let headers:http.IncomingHttpHeaders={},raw:string[]=[];
    const server=http.createServer((req,res)=>{headers=req.headers;raw=req.rawHeaders;req.resume();req.on('end',()=>{res.setHeader('content-type','application/json');res.end('{"ok":true}');});});
    server.listen(0,'127.0.0.1');await once(server,'listening');const port=(server.address() as any).port;
    try{
      const r=await forward({...base,upstream:`http://127.0.0.1:${port}`,upstreamTokenFile:tokenFile},{method:'POST',path:'/zip/pack',headers:{Authorization:'Bearer malicious',Cookie:'stolen','Host':'169.254.169.254','Transfer-Encoding':'chunked','X-Forwarded-For':'attacker'},bodyBase64:Buffer.from('{}').toString('base64')});
      expect(r.status).toBe(200);expect(headers.authorization).toBe('Bearer '+token);expect(raw.filter(s=>s.toLowerCase()==='authorization')).toHaveLength(1);
      expect(headers.host).toBe(`127.0.0.1:${port}`);expect(headers.cookie).toBeUndefined();expect(headers['transfer-encoding']).toBeUndefined();expect(headers['x-forwarded-for']).toBeUndefined();
    }finally{await new Promise<void>(r=>server.close(()=>r()));fs.unlinkSync(tokenFile);fs.rmdirSync(dir);}
  });
  it('forwards an explicitly allowed GET with an empty body, never a provider URL',async()=>{
    let hits=0,method='',url='',body='';
    const server=http.createServer((req,res)=>{hits++;method=req.method??'';url=req.url??'';req.on('data',c=>body+=c);req.on('end',()=>{res.setHeader('content-type','application/json');res.end('{"openapi":"3.1.2"}');});});
    server.listen(0,'127.0.0.1');await once(server,'listening');
    const config={...base,upstream:`http://127.0.0.1:${(server.address() as any).port}`,routes:[['GET','/openapi.json']] as [string,string][]};
    try{
      const r=await forward(config,{method:'GET',path:'/openapi.json',headers:{},bodyBase64:''});
      expect(r.status).toBe(200);expect(Buffer.from(r.bodyBase64,'base64').toString()).toBe('{"openapi":"3.1.2"}');
      expect({hits,method,url,body}).toEqual({hits:1,method:'GET',url:'/openapi.json',body:''});
      await expect(forward(config,{method:'GET',path:'/openapi.json?url=https://outside.example',bodyBase64:''})).rejects.toThrow();
      await expect(forward(config,{method:'GET',path:'https://outside.example/openapi.json',bodyBase64:''})).rejects.toThrow();
      expect(hits).toBe(1);
    }finally{server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));}
  });
  it('returns 413 without forwarding an oversized payload',async()=>{
    expect((await forward(base,{method:'POST',path:'/zip/pack',bodyBase64:Buffer.alloc(1025).toString('base64')})).status).toBe(413);
  });
  it('does not follow redirects to internal destinations',async()=>{
    const server=http.createServer((_req,res)=>{res.writeHead(302,{location:'http://169.254.169.254/'});res.end();});server.listen(0,'127.0.0.1');await once(server,'listening');
    try{expect((await forward({...base,upstream:`http://127.0.0.1:${(server.address() as any).port}`},{method:'POST',path:'/zip/pack',bodyBase64:''})).status).toBe(302);}finally{await new Promise<void>(r=>server.close(()=>r()));}
  });
});
