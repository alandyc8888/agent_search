import {describe,it,expect} from 'vitest';
import fs from 'node:fs';
import {A2N_NS} from '../src/ard.ts';
const read=(path:string)=>fs.readFileSync(new URL('../../../'+path,import.meta.url),'utf8');
// These are narrow documentation regression checks, not DID or end-to-end transport tests.
describe('listing documentation consistency',()=>{
 it('uses the draft listing version without changing ARD or category versions',()=>{
  const spec=read('spec/listing-format.md');
  expect(spec).toContain('Provider listing format v0.1');
  expect(read('packages/protocol/src/ard.ts')).toContain('ARD v0.91');
  expect(read('packages/protocol/src/ard.ts')).toContain('spec/listing-format.md v0.1');
  expect(read('packages/protocol/src/categories.ts')).toContain('§3.2.1; controlled list v0.2');
  const example=JSON.parse(read('spec/examples/ard.example.json'));
  for(const e of example.entries)expect(e['a2n:specVersion']).toBe('0.1');
 });
 it('keeps the illustrative namespace aligned with the runtime constant',()=>{
  expect(JSON.parse(read('spec/examples/ard.example.json'))['@context'][1].a2n).toBe(A2N_NS);
 });
 it('explains current X25519 use without claiming DID resolution or E2EE',()=>{
  const spec=read('spec/listing-format.md');
  expect(spec).toContain('already uses the provider\'s X25519 key');
  expect(spec).toContain('Results use a separate per-request pickup-derived key');
  expect(spec).toContain('does not automatically resolve DID');
  expect(spec).not.toContain('reserved for a future end-to-end encrypted relay path');
 });
 it('documents the relay GET envelope and failure cleanup without inventing discovery',()=>{
  const skill=read('skills/agent-search/SKILL.md');
  const block=skill.match(/```json\n(\{"provider":"<operator-confirmed handle>"[^\n]+\})\n```/);
  expect(block).not.toBeNull();
  expect(JSON.parse(block![1])).toEqual({provider:'<operator-confirmed handle>',kind:'call',method:'GET',path:'/openapi.json',headers:{},bodyBase64:''});
  expect(skill).toContain('POST `{origin}/relay/v0/requests`');
  expect(skill).toContain('still DELETE the contract-reading request');
  expect(skill).toContain('automatic discovery and signed provider/version binding are not implemented');
  expect(skill).toContain('do not claim strong schema checks');
 });
 it('does not advertise a missing runbook, keygen or transparency verifier',()=>{
  const skill=read('skills/agent-search/SKILL.md');
  expect(skill).not.toContain('accompanying local runbook');
  expect(skill).toContain('operator controls demo lifecycle outside the agent sandbox');
  expect(read('packages/provider/README.md')).toContain('does not ship an identity-file generation CLI');
  expect(JSON.parse(read('policy/seeds.json')).$comment).toContain('does not implement a log client');
  expect(JSON.parse(read('packages/protocol/package.json')).description).toContain('No transparency-log proof verifier');
 });
 it('allows a declared-free payment fragment without claiming implemented payment or DID provisioning',()=>{
  const spec=read('spec/listing-format.md');
  const block=spec.match(/```json\n(\{"a2n:paymentMethods":\[\][^\n]+\})\n```/);
  expect(block).not.toBeNull();
  const fragment=JSON.parse(block![1]);
  expect(fragment['a2n:paymentMethods']).toEqual([]);
  expect(fragment['a2n:offerings'][0].accepts).toEqual([]);
  expect(fragment['a2n:offerings'][0].price).toEqual({mode:'fixed',amount:'0',currency:'USD',unit:'job'});
  expect(spec).toContain('not a verified quote');
  expect(spec).toContain('not** to publish hosted DID documents');
  expect(spec).toContain('not a domain, brand or certification');
 });
 it('keeps draft addresses as arrays and relay entries free of an undeclared protocol',()=>{
  expect(read('spec/listing-format.md')).toContain('An array of address objects');
  for(const entry of JSON.parse(read('spec/examples/ard.example.json')).entries){
   expect(Array.isArray(entry['a2n:address'])).toBe(true);
   for(const address of entry['a2n:address'])if(address.kind==='relay')expect(address).toEqual({kind:'relay'});
  }
 });
 it('describes echo semantics and direct URLs as design-only metadata',()=>{
  expect(read('skills/agent-search/SKILL.md')).toContain('echoes the original inquiry in `message`');
  expect(read('packages/provider/README.md')).toContain('fixed acknowledgement in `reply`');
  expect(read('spec/listing-format.md')).toContain('does not select a target from `a2n:address`');
  expect(JSON.parse(read('spec/examples/ard.example.json'))._comment).toContain('not runnable connector configuration');
 });
 it('attributes limits to their layers instead of promising a file size',()=>{
  const spec=read('spec/listing-format.md');
  expect(spec).toContain('ZIP example, not the network as a whole');
  expect(spec).toContain('including base64/JSON overhead');
  expect(spec).toContain('not a promised 1 MiB file transfer');
 });
});
