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
 it('attributes limits to their layers instead of promising a file size',()=>{
  const spec=read('spec/listing-format.md');
  expect(spec).toContain('ZIP example, not the network as a whole');
  expect(spec).toContain('including base64/JSON overhead');
  expect(spec).toContain('not a promised 1 MiB file transfer');
 });
});
