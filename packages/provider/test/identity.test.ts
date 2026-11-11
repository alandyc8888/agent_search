import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes, createPrivateKey, createPublicKey, createHash } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { once } from 'node:events';
import { generateKeyPair, toB64u } from '@a2n/protocol';
import { loadProviderIdentity } from '../src/identity.ts';
import { startProvider } from '../src/provider.ts';

const publicRaw = (raw: Uint8Array) => Buffer.from(createPublicKey(createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), raw]), format: 'der', type: 'pkcs8',
})).export({ format: 'jwk' }).x!, 'base64url');
const digest = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
function fixture(value?: unknown) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'provider-identity-test-')); fs.chmodSync(dir, 0o700);
  const dirStat = fs.lstatSync(dir), file = path.join(dir, 'identity.json');
  const ed = generateKeyPair(), raw = randomBytes(32); raw[0] |= 7; raw[31] |= 128; raw[31] &= 191;
  const identity = { privateKey: toB64u(ed.privateKey), xPrivateKey: toB64u(raw), handle: 'synthetic-only', edFingerprint: digest(ed.publicKey) };
  fs.writeFileSync(file, JSON.stringify(value ?? identity), { mode: 0o600, flag: 'wx' });
  const st = fs.lstatSync(file), links: string[] = [];
  const close = () => {
    for (const item of links) { if (path.dirname(item) !== dir || fs.realpathSync(dir) !== dir) throw Error('cleanup_path'); fs.unlinkSync(item); }
    const now = fs.lstatSync(file);
    if (now.ino !== st.ino || now.dev !== st.dev || now.uid !== process.getuid!()) throw Error('cleanup_ownership');
    fs.unlinkSync(file);
    const current = fs.lstatSync(dir);
    if (current.ino !== dirStat.ino || current.dev !== dirStat.dev || fs.realpathSync(dir) !== dir) throw Error('cleanup_directory');
    fs.rmdirSync(dir); ed.privateKey.fill(0); raw.fill(0);
  };
  return { dir, file, identity, ed, raw, links, close };
}

describe('read-only legacy provider identity', () => {
  for (const declaration of ['absent', 'correct'] as const) it(`loads ${declaration} xPub with original file bytes and metadata unchanged`, async () => {
    const f = fixture();
    try {
      if (declaration === 'correct') fs.writeFileSync(f.file, JSON.stringify({ ...f.identity, xPub: publicRaw(f.raw).toString('base64url') }));
      const before = fs.readFileSync(f.file), st = fs.statSync(f.file, { bigint: true });
      const loaded = await loadProviderIdentity(f.file);
      expect(loaded.privateKey).toBe(f.identity.privateKey);
      expect(Buffer.from(loaded.xPub).equals(publicRaw(f.raw))).toBe(true);
      expect((loaded.xPrivateKey[0] & 7) === 0 && (loaded.xPrivateKey[31] & 192) === 64).toBe(true);
      loaded.xPrivateKey.fill(0);
      const after = fs.statSync(f.file, { bigint: true });
      expect(digest(fs.readFileSync(f.file))).toBe(digest(before));
      expect(after.ino === st.ino && after.mode === st.mode && after.mtimeNs === st.mtimeNs).toBe(true);
      expect(JSON.parse(fs.readFileSync(f.file, 'utf8'))).toEqual(JSON.parse(before.toString()));
    } finally { f.close(); }
  });
  it.each([null, '', 1, {}, [], 'not-base64url'])('rejects present invalid xPub %j with no file changes', async value => {
    const f = fixture();
    try {
      fs.writeFileSync(f.file, JSON.stringify({ ...f.identity, xPub: value })); const before = fs.readFileSync(f.file), st = fs.statSync(f.file, { bigint: true });
      await expect(loadProviderIdentity(f.file)).rejects.toThrow('x25519_private_invalid');
      expect(digest(fs.readFileSync(f.file))).toBe(digest(before)); expect(fs.statSync(f.file, { bigint: true }).mtimeNs).toBe(st.mtimeNs);
    } finally { f.close(); }
  });
  it('rejects well-formed wrong xPub without repairing identity', async () => {
    const f = fixture();
    try {
      fs.writeFileSync(f.file, JSON.stringify({ ...f.identity, xPub: Buffer.alloc(32, 5).toString('base64url') }));
      const before = fs.readFileSync(f.file); await expect(loadProviderIdentity(f.file)).rejects.toThrow('x25519_public_mismatch');
      expect(digest(fs.readFileSync(f.file))).toBe(digest(before));
    } finally { f.close(); }
  });
  it('rejects symlinks, hardlinks, non-files, wrong modes, huge files and malformed UTF8', async () => {
    const f = fixture();
    try {
      const link = path.join(f.dir, 'link'); fs.symlinkSync(f.file, link); f.links.push(link);
      await expect(loadProviderIdentity(link)).rejects.toThrow('identity_file_invalid');
      const hard = path.join(f.dir, 'hard'); fs.linkSync(f.file, hard); f.links.push(hard);
      await expect(loadProviderIdentity(f.file)).rejects.toThrow('identity_file_invalid');
      fs.unlinkSync(hard); f.links.pop();
      await expect(loadProviderIdentity(f.dir)).rejects.toThrow('identity_file_invalid');
      fs.chmodSync(f.file, 0o644); await expect(loadProviderIdentity(f.file)).rejects.toThrow('identity_file_invalid'); fs.chmodSync(f.file, 0o600);
      fs.writeFileSync(f.file, Buffer.alloc(16385)); await expect(loadProviderIdentity(f.file)).rejects.toThrow('identity_file_invalid');
      fs.writeFileSync(f.file, Buffer.from([0xff, 0xfe])); await expect(loadProviderIdentity(f.file)).rejects.toThrow('identity_file_invalid');
    } finally { f.close(); }
  });
  it('rejects an invalid identity before opening any WebSocket', async () => {
    const f = fixture(), wss = new WebSocketServer({ port: 0, host: '127.0.0.1' }); await once(wss, 'listening');
    let connections = 0; wss.on('connection', () => connections++);
    try {
      fs.writeFileSync(f.file, JSON.stringify({ ...f.identity, xPub: null }));
      await expect(startProvider({ handle: 'synthetic', relay: `ws://127.0.0.1:${(wss.address() as { port: number }).port}`, identityFile: f.file, upstream: 'http://127.0.0.1:1', routes: [] })).rejects.toThrow('x25519_private_invalid');
      expect(connections).toBe(0);
    } finally { await new Promise<void>(r => wss.close(() => r())); f.close(); }
  });
});
