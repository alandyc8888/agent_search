import { describe, expect, it, vi } from 'vitest';
import { createPublicKey, verify } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { base58 } from '@scure/base';
import { answerRegistrationChallenge, decodeProviderDidKey, encodeProviderDidKey, encodePublicRegistrationChallenge, parseProofJson } from '../src/index.ts';
import { checkChallenge, decodeProofBinary, proofOrigin, verifyRegistrationSignature, verifyStrictProofEdSignature } from '../src/provider-proof-internal.ts';
import { B64, H, J, JSON_BYTES, NOW, ORIGIN, fixture, keys, nativeProof, nativePublic, payload } from './proof-fixtures.ts';

const options = (f: Awaited<ReturnType<typeof fixture>>) => ({ expectedOrigin: ORIGIN, localEdSeed32: f.edSeed, localXPrivateKey: f.xRaw, clientNow: NOW + 1 });
const validBytes = (p: unknown) => Buffer.from(JSON.stringify(p));

describe('narrow local did:key', () => {
  // Published public test vectors: https://w3c-ccg.github.io/did-key-spec/ and digitalbazaar/ed25519-multikey.
  const cases = ['did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', 'did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP'];
  it('uses fixed raw Ed multicodec bytes without deriving X or fetching a DID', () => {
    for (const did of cases) {
      const fp = did.slice(8), independent = base58.decode(fp.slice(1)), pub = independent.subarray(2);
      expect(independent.length === 34 && independent[0] === 0xed && independent[1] === 0x01).toBe(true);
      expect(encodeProviderDidKey(pub)).toBe(did);
      expect(Buffer.from(decodeProviderDidKey(did)).equals(pub)).toBe(true);
      expect(Buffer.from(decodeProviderDidKey(did + '#' + fp)).equals(pub)).toBe(true);
    }
    const pub = Buffer.from('9bb6ee6d2ee0a2e0cfa351f13ec2dc225bc8b95537291922a96e8680ae1b69d7', 'hex');
    expect(encodeProviderDidKey(pub)).toBe('did:key:z6Mkpw72M9suPCBv48X2Xj4YKZJH9W7wzEK1aS6JioKSo89C');
  });
  it('rejects non-Ed/length/noncanonical identifier and wrong fragments without normalization', () => {
    const did = encodeProviderDidKey(keys().edPub), fp = did.slice(8);
    for (const candidate of [did + '#', did + '#other', did + '#' + fp + '#x', did + '/path', did + '?a=1', did + ' ', did.replace('did:', 'DID:'), 'did:key:z0', 'did:key:é',
      'did:key:z' + base58.encode(new Uint8Array([0xec, 0x01, ...new Uint8Array(32)])),
      'did:key:z' + base58.encode(new Uint8Array([0xed, 0x01, ...new Uint8Array(31)])),
      'did:key:z1' + fp.slice(1), null, {}, 1]) expect(() => decodeProviderDidKey(candidate)).toThrow('proof_invalid');
    expect(() => encodeProviderDidKey(new Uint8Array(31))).toThrow('proof_invalid');
  });
});

describe('registration response and strict Ed profile', () => {
  it('answers frozen response arithmetic and produces a native Node-valid detached JWS', async () => {
    const f = await fixture({ fixed: true });
    expect(H(J(f.publicPart.transcript)).toString('hex')).toBe('ba9d0e2de7abf05e4ef91f8398cb437ce89ee0e25df2bbec3451a26d19974ace');
    expect(f.expected.toString('hex')).toBe('9ae91a994228307361d4ebf0bf465b8919e3e52b3c54ef293fcf679689cb1194');
    const proof = parseProofJson(await answerRegistrationChallenge(f.bytes, options(f))) as any;
    expect(proof.xResponse === B64(f.expected) && proof.challengeId === f.publicPart.transcript.challengeId).toBe(true);
    const [header, , sig] = proof.signature.split('.');
    expect(verify(null, Buffer.from(header + '.' + J(payload(f.publicPart, proof.xResponse))), nativePublic(f.edSeed), Buffer.from(sig, 'base64url'))).toBe(true);
    expect(() => verifyRegistrationSignature(f.publicPart, proof.xResponse, proof.signature)).not.toThrow();
    f.secret.fill(0); f.edSeed.fill(0); f.xRaw.fill(0);
  });
  it('keeps all 32 ignored-bit variants of a legacy raw X private key compatible', async () => {
    const f = await fixture();
    for (let bits = 0; bits < 32; bits++) {
      const x = Uint8Array.from(f.xRaw); x[0] = (x[0] & 248) | (bits & 7); x[31] = (x[31] & 63) | ((bits >> 3 & 1) * 64) | ((bits >> 4 & 1) * 128);
      const proof = parseProofJson(await answerRegistrationChallenge(f.bytes, { ...options(f), localXPrivateKey: x })) as any;
      expect(proof.xResponse === B64(f.expected)).toBe(true); x.fill(0);
    }
    f.secret.fill(0);
  });
  it('accepts three fixed RFC8032 public vectors and rejects altered messages with native agreement', () => {
    // Public verification data from RFC8032 section 7.1 TEST 1/2/3 (secret material omitted).
    const vectors = [
      ['d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '', 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
      ['3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72', '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'],
      ['fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82', '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'],
    ];
    for (const [pubHex, msgHex, sigHex] of vectors) {
      const pub = Buffer.from(pubHex, 'hex'), msg = Buffer.from(msgHex, 'hex'), sig = Buffer.from(sigHex, 'hex');
      const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub]), type: 'spki', format: 'der' });
      expect(verify(null, msg, key, sig)).toBe(true);
      expect(() => verifyStrictProofEdSignature(sig, msg, pub)).not.toThrow();
      const bad = Buffer.concat([msg, Buffer.from([0])]);
      expect(verify(null, bad, key, sig)).toBe(false);
      expect(() => verifyStrictProofEdSignature(sig, bad, pub)).toThrow('proof_invalid');
    }
  });
  it('rejects low-order forgeries and noncanonical public/R/S without permissive fallback', async () => {
    const message = Buffer.from('synthetic non-possession demonstration'), identity = new Uint8Array(32); identity[0] = 1;
    const forgery = new Uint8Array(64); forgery[0] = 1;
    expect(ed25519.verify(forgery, message, identity)).toBe(true);
    expect(() => verifyStrictProofEdSignature(forgery, message, identity)).toThrow('proof_invalid');
    const low = [new Uint8Array(32), identity, Buffer.from('ec' + 'ff'.repeat(30) + '7f', 'hex')];
    for (const pub of low) expect(() => verifyStrictProofEdSignature(forgery, message, pub)).toThrow('proof_invalid');
    const f = await fixture(), good = ed25519.sign(message, f.edSeed);
    const noncanonicalPoint = Buffer.from('ed' + 'ff'.repeat(30) + '7f', 'hex');
    expect(() => verifyStrictProofEdSignature(good, message, noncanonicalPoint)).toThrow('proof_invalid');
    const badR = Uint8Array.from(good); badR.set(noncanonicalPoint, 0);
    expect(() => verifyStrictProofEdSignature(badR, message, f.edPub)).toThrow('proof_invalid');
    const badS = Uint8Array.from(good); badS.fill(255, 32);
    expect(() => verifyStrictProofEdSignature(badS, message, f.edPub)).toThrow('proof_invalid');
    f.secret.fill(0);
  });
  it('enforces exact protected headers, canonical header bytes/segments and signature length', async () => {
    const f = await fixture(), p = f.publicPart, good = { alg: 'EdDSA', kid: 'provider:' + f.handle, b64: false, crit: ['b64'] };
    const headers = [{ ...good, alg: 'none' }, { ...good, kid: 'provider:other' }, { ...good, b64: true }, { ...good, crit: [] },
      { ...good, crit: ['b64', 'other'] }, { ...good, unknown: 1 }, { alg: good.alg, kid: good.kid, b64: false }, { alg: good.alg, kid: good.kid, crit: ['b64'] }];
    for (const h of headers) {
      const proof = nativeProof(p, f.expected, f.edSeed, h);
      expect(() => verifyRegistrationSignature(p, proof.xResponse, proof.signature)).toThrow('proof_invalid');
    }
    for (const text of [JSON.stringify(good), '{"alg":"EdDSA","alg":"EdDSA","b64":false,"crit":["b64"],"kid":"provider:' + f.handle + '"}']) {
      const proof = nativeProof(p, f.expected, f.edSeed, undefined, text);
      expect(() => verifyRegistrationSignature(p, proof.xResponse, proof.signature)).toThrow('proof_invalid');
    }
    const goodProof = nativeProof(p, f.expected, f.edSeed), [a, , s] = goodProof.signature.split('.');
    for (const signature of [`${a}=..${s}`, `${a}.payload.${s}`, `${a}..${s}=`, `${a}..${s.slice(1)}`, `${a}..${s}.more`, `${a}..${B64(new Uint8Array(65))}`]) {
      expect(() => verifyRegistrationSignature(p, goodProof.xResponse, signature)).toThrow('proof_invalid');
    }
    f.secret.fill(0);
  });
});

describe('client independent identity, origin, data ownership and HPKE', () => {
  it('rejects crypto-consistent origin/key mismatches before opening or signing', async () => {
    const f = await fixture({ origin: 'https://other.example' }), local = keys();
    const openSpy = vi.spyOn((await import('@hpke/core')).CipherSuite.prototype, 'open');
    try {
      await expect(answerRegistrationChallenge(f.bytes, options(f))).rejects.toThrow('proof_invalid');
      const same = await fixture();
      await expect(answerRegistrationChallenge(same.bytes, { ...options(same), localEdSeed32: local.edSeed })).rejects.toThrow('proof_invalid');
      await expect(answerRegistrationChallenge(same.bytes, { ...options(same), localXPrivateKey: local.xRaw })).rejects.toThrow('proof_invalid');
      const wrongHandle = structuredClone(same.publicPart); wrongHandle.transcript.handle = 'p-' + 'f'.repeat(40);
      await expect(answerRegistrationChallenge(validBytes(wrongHandle), options(same))).rejects.toThrow('proof_invalid');
      expect(openSpy.mock.calls.length === 0).toBe(true);
    } finally { openSpy.mockRestore(); }
    f.secret.fill(0);
  });
  it('enforces exact independent canonical origin and TTL boundaries', async () => {
    for (const value of ['https://registration.example/', 'https://REGISTRATION.example', 'https://a.example:443', 'https://a.example?q=1', 'https://u:p@a.example', 'https://a.example#x', 'http://localhost', 'http://127.0.0.2', 'https://a.example/path']) expect(() => proofOrigin(value)).toThrow('proof_invalid');
    expect(proofOrigin('http://127.0.0.1:8881')).toBe('http://127.0.0.1:8881');
    const f = await fixture();
    for (const clientNow of [NOW - 1, NOW + 120000, -1, NaN, 1.1, Number.MAX_SAFE_INTEGER + 1]) await expect(answerRegistrationChallenge(f.bytes, { ...options(f), clientNow })).rejects.toThrow('proof_invalid');
    const end = await answerRegistrationChallenge(f.bytes, { ...options(f), clientNow: NOW + 119999 }); expect(end.length > 0).toBe(true);
    f.secret.fill(0);
  });
  it('rejects wrong HPKE info/AAD, ciphertext/enc modifications and suite changes', async () => {
    for (const config of [{ info: Buffer.from('wrong') }, { aad: Buffer.from('wrong') }]) {
      const f = await fixture(config); await expect(answerRegistrationChallenge(f.bytes, options(f))).rejects.toThrow('proof_invalid'); f.secret.fill(0);
    }
    const f = await fixture();
    for (const field of ['enc', 'ciphertext'] as const) {
      const p = structuredClone(f.publicPart), bytes = Buffer.from(p[field], 'base64url'); bytes[0] ^= 1; p[field] = B64(bytes);
      await expect(answerRegistrationChallenge(validBytes(p), options(f))).rejects.toThrow('proof_invalid');
    }
    for (const p of [{ ...f.publicPart, profile: 'other' }, { ...f.publicPart, suite: { ...f.publicPart.suite, mode: 1 } }, { ...f.publicPart, enc: B64(new Uint8Array(31)) }, { ...f.publicPart, enc: B64(new Uint8Array(33)) }, { ...f.publicPart, enc: B64(new Uint8Array(32)) }, { ...f.publicPart, enc: B64(Uint8Array.from([1, ...new Uint8Array(31)])) }, { ...f.publicPart, ciphertext: f.publicPart.ciphertext + '=' }]) await expect(answerRegistrationChallenge(validBytes(p), options(f))).rejects.toThrow('proof_invalid');
    f.secret.fill(0);
  });
  it('refuses malformed/noncanonical binary before permissive Buffer decoding', () => {
    const canonical = B64(new Uint8Array(32));
    for (const bad of [canonical + '=', ' ' + canonical, canonical.slice(1), canonical.slice(0, -1) + 'B', canonical.replace('A', '+'), 1]) expect(() => decodeProofBinary(bad, 32)).toThrow('proof_invalid');
  });
  it('has explicit public allowlist and rejects internal/secret/sender/expected extras instead of stripping', async () => {
    const f = await fixture(); const bytes = encodePublicRegistrationChallenge(f.publicPart), text = Buffer.from(bytes).toString();
    expect(text).not.toMatch(/expectedXProofHash|secret|senderKey|internal/);
    expect(text.includes(B64(f.expected)) || text.includes(f.expected.toString('hex')) || text.includes(B64(f.secret))).toBe(false);
    for (const key of ['expectedXProofHash', 'secret', 'senderKey', 'internal']) expect(() => encodePublicRegistrationChallenge({ ...f.publicPart, [key]: 'never-strip' })).toThrow('proof_invalid');
    const nested = structuredClone(f.publicPart) as any; nested.transcript.extra = true; expect(() => encodePublicRegistrationChallenge(nested)).toThrow('proof_invalid');
    expect(() => checkChallenge({ ...f.publicPart, get unexpected() { throw Error('not called'); } })).toThrow('proof_invalid');
    f.secret.fill(0);
  });
  it('owns bytes/options/local keys before await and never changes caller-owned neighbors', async () => {
    const f = await fixture(); const ed = Uint8Array.from(f.edSeed), x = Uint8Array.from(f.xRaw), raw = Uint8Array.from(f.bytes);
    const opts = { ...options(f), localEdSeed32: ed, localXPrivateKey: x };
    const pending = answerRegistrationChallenge(raw, opts); raw.fill(0); ed.fill(0); x.fill(0); opts.expectedOrigin = 'https://other.example'; opts.clientNow = 0;
    const proof = parseProofJson(await pending) as any; expect(proof.xResponse === B64(f.expected)).toBe(true);
    const parent = Buffer.alloc(96, 0xa5), edView = parent.subarray(32, 64); edView.set(f.edSeed); const before = Buffer.from(parent);
    await answerRegistrationChallenge(f.bytes, { ...options(f), localEdSeed32: edView }); expect(parent.equals(before)).toBe(true);
    let called = 0; const bad = { ...options(f), get expectedOrigin() { called++; return ORIGIN; } };
    await expect(answerRegistrationChallenge(f.bytes, bad)).rejects.toThrow('proof_invalid'); expect(called).toBe(0);
    f.secret.fill(0);
  });
});
