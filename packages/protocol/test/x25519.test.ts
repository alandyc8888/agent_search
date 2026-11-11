import { describe, expect, it } from 'vitest';
import { KeyObject, createPrivateKey, createPublicKey, randomBytes, webcrypto } from 'node:crypto';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { normalizeX25519Private, importX25519Private, exportX25519Private, generateX25519Identity,
  x25519KeyPair, pickupKeyPair, seal, open } from '../src/index.ts';

const same = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
const nativePublic = (raw: Uint8Array) => {
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), raw]), format: 'der', type: 'pkcs8' });
  return Buffer.from(createPublicKey(key).export({ format: 'jwk' }).x!, 'base64url');
};
const canonical = (raw: Uint8Array) => raw.length === 32 && (raw[0] & 7) === 0 && (raw[31] & 192) === 64;
const rawKey = () => { const key = randomBytes(32); key[0] |= 7; key[31] |= 128; key[31] &= 191; return key; };

describe('owned X25519 private serialization', () => {
  it.each([0, 255])('normalizes fixed boundary %i without altering input', value => {
    const raw = new Uint8Array(32).fill(value), before = Uint8Array.from(raw), out = normalizeX25519Private(raw);
    expect(out[0]).toBe(value === 0 ? 0 : 248); expect(out[31]).toBe(value === 0 ? 64 : 127);
    expect(same(raw, before)).toBe(true); expect(out.buffer === raw.buffer).toBe(false);
    expect(same(normalizeX25519Private(out), out)).toBe(true);
  });
  it('keeps all ignored bit combinations public-key compatible with native Node', async () => {
    const base = normalizeX25519Private(rawKey()), expected = nativePublic(base);
    for (let bits = 0; bits < 32; bits++) {
      const raw = Uint8Array.from(base); raw[0] += bits & 7; raw[31] = raw[31] % 64 + ((bits >> 3) & 1) * 128 + ((bits >> 4) & 1) * 64;
      const before = Uint8Array.from(raw), imported = await importX25519Private(raw);
      expect(same(imported.publicKey, expected) && same(nativePublic(raw), expected) && same(raw, before)).toBe(true);
      const exported = await exportX25519Private(imported.privateKey);
      expect(same(exported, base)).toBe(true); exported.fill(0);
    }
    base.fill(0);
  });
  it('rejects invalid types, shared buffers and lying own typed-array properties', () => {
    const wrongLength = new Uint8Array(33); Object.defineProperty(wrongLength, 'length', { value: 32 });
    const shared = new Uint8Array(new SharedArrayBuffer(32)); Object.defineProperty(shared, 'buffer', { value: new ArrayBuffer(32) });
    for (const value of [null, undefined, [], {}, new ArrayBuffer(32), new DataView(new ArrayBuffer(32)), new Uint8Array(31), wrongLength, shared, new Proxy(new Uint8Array(32), {})]) {
      expect(() => normalizeX25519Private(value)).toThrow('x25519_private_invalid');
    }
  });
  it('owns its import before await and never touches Buffer neighbors', async () => {
    const all = Buffer.alloc(80, 165), raw = rawKey(); raw.copy(all, 16); const before = Buffer.from(all);
    const view = all.subarray(16, 48), expected = nativePublic(view), out = normalizeX25519Private(view);
    out.fill(0); expect(same(all, before)).toBe(true);
    const pending = importX25519Private(view); view.fill(0);
    expect(same((await pending).publicKey, expected)).toBe(true);
    expect(same(all.subarray(0, 16), before.subarray(0, 16)) && same(all.subarray(48), before.subarray(48))).toBe(true);
  });
  it('distinguishes missing public declaration from present invalid declarations', async () => {
    const raw = rawKey(), text = raw.toString('base64url'), pub = nativePublic(raw).toString('base64url');
    expect(same((await importX25519Private(text)).publicKey, nativePublic(raw))).toBe(true);
    expect(same((await importX25519Private(text, pub)).publicKey, nativePublic(raw))).toBe(true);
    for (const value of [undefined, null, '', 1, {}, pub + '=', ' ' + pub]) await expect(importX25519Private(text, value)).rejects.toThrow('x25519_private_invalid');
    await expect(importX25519Private(text, Buffer.alloc(32, 5).toString('base64url'))).rejects.toThrow('x25519_public_mismatch');
    for (const value of [text + '=', ' ' + text, text.slice(1), text + '\n']) await expect(importX25519Private(value)).rejects.toThrow('x25519_private_invalid');
    raw.fill(0);
  });
  for (const [name, algorithm, usages] of [
    ['Ed25519', 'Ed25519', ['sign', 'verify']],
    ['P-256', { name: 'ECDH', namedCurve: 'P-256' }, ['deriveBits']],
    ['X448', 'X448', ['deriveBits']],
  ] as const) {
    it(`rejects renamed real ${name} before private serialization`, async () => {
      const pair = await webcrypto.subtle.generateKey(algorithm as webcrypto.AlgorithmIdentifier, true, [...usages]) as CryptoKeyPair;
      const before = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', pair.privateKey));
      const pubBefore = Buffer.from(await webcrypto.subtle.exportKey('spki', pair.publicKey));
      pair.privateKey.algorithm.name = 'X25519';
      await expect(exportX25519Private(pair.privateKey)).rejects.toThrow('x25519_key_operation_failed');
      const after = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', pair.privateKey));
      expect(same(before, after)).toBe(true);
      expect(pubBefore.equals(Buffer.from(await webcrypto.subtle.exportKey('spki', pair.publicKey)))).toBe(true);
      before.fill(0); after.fill(0);
    });
  }
  it('uses native type for real X keys and intrinsic getters for permissions', async () => {
    const key = (await importX25519Private(rawKey())).privateKey;
    key.algorithm.name = 'Ed25519';
    for (const name of ['type', 'extractable', 'algorithm']) Object.defineProperty(key, name, { get() { throw Error('untrusted_metadata'); } });
    const out = await exportX25519Private(key);
    expect(canonical(out) && KeyObject.from(key).asymmetricKeyType === 'x25519').toBe(true); out.fill(0);
    const blocked = await webcrypto.subtle.generateKey('X25519', false, ['deriveBits']) as CryptoKeyPair;
    Object.defineProperty(blocked.privateKey, 'extractable', { value: true });
    for (const invalid of [blocked.privateKey, blocked.publicKey, {}, Object.create(CryptoKey.prototype)]) {
      await expect(exportX25519Private(invalid)).rejects.toThrow('x25519_key_operation_failed');
    }
  });
  it('generates canonical independent bytes and reimports with the same public key', async () => {
    const generated = await generateX25519Identity();
    try {
      expect(canonical(generated.privateKey)).toBe(true);
      const imported = await importX25519Private(generated.privateKey, Buffer.from(generated.publicKey).toString('base64url'));
      expect(same(imported.publicKey, generated.publicKey) && same(nativePublic(generated.privateKey), generated.publicKey)).toBe(true);
    } finally { generated.privateKey.fill(0); }
  });
});

describe('legacy sealed-box boundaries stay compatible', () => {
  it('normalizes key generation and preserves pickup public keys', () => {
    for (let i = 0; i < 32; i++) {
      const generated = x25519KeyPair(), token = randomBytes(32).toString('base64url');
      const oldRaw = hkdf(sha256, new TextEncoder().encode(token), new Uint8Array(0), new TextEncoder().encode('a2n-pickup-x25519-v1'), 32);
      const picked = pickupKeyPair(token);
      expect(canonical(generated.privateKey) && same(nativePublic(generated.privateKey), generated.publicKey)).toBe(true);
      expect(canonical(picked.privateKey) && same(picked.publicKey, x25519.getPublicKey(oldRaw))).toBe(true);
      generated.privateKey.fill(0); oldRaw.fill(0); picked.privateKey.fill(0);
    }
  });
  it('opens the same box using raw legacy and canonical keys without mutating callers', () => {
    const raw = rawKey(), before = Buffer.from(raw), normalized = normalizeX25519Private(raw), message = Buffer.from('synthetic compatibility payload');
    const box = seal(nativePublic(raw), message, 'compatibility-only');
    expect(same(open(raw, box, 'compatibility-only'), message) && same(open(normalized, box, 'compatibility-only'), message)).toBe(true);
    expect(same(raw, before)).toBe(true);
    expect(() => open(raw, box, 'wrong-info')).toThrow();
    expect(same(raw, before)).toBe(true); raw.fill(0); before.fill(0); normalized.fill(0);
  });
});
