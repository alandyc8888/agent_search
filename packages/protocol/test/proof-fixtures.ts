// Synthetic test-only independent construction; no product response/hash/signing helper imports.
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign } from 'node:crypto';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import type { PublicRegistrationChallenge, RegistrationTranscript } from '../src/provider-proof-internal.ts';
export const B64 = (b: Uint8Array) => Buffer.from(b).toString('base64url');
export const H = (b: Uint8Array | string) => createHash('sha256').update(b).digest();
export const HASH = (b: Uint8Array | string) => 'sha256:' + H(b).toString('hex');
// Independent restricted test JCS, no product canonicalizer.
export function J(value: any): string {
  if (Array.isArray(value)) return '[' + value.map(J).join(',') + ']';
  if (value !== null && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + J(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
export const JSON_BYTES = (v: unknown) => Buffer.from(J(v), 'utf8');
export const NATIVE_PRIVATE = (seed: Uint8Array) => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
export const ORIGIN = 'https://registration.example';
export const NOW = 1805022000000;
export const nativeResponse = (transcript: unknown, secret: Uint8Array) => H(Buffer.concat([Buffer.from('provider-x-response/v1'), H(J(transcript)), secret]));
export const suite = () => new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
export function keys(fixed = false) {
  const edSeed = fixed ? Uint8Array.from({ length: 32 }, (_, i) => 160 + i) : Uint8Array.from(randomBytes(32));
  const xRaw = fixed ? Uint8Array.from(Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex')) : Uint8Array.from(randomBytes(32));
  const edPub = ed25519.getPublicKey(edSeed), xPub = x25519.getPublicKey(xRaw);
  return { edSeed, xRaw, edPub, xPub, handle: 'p-' + H(edPub).toString('hex').slice(0, 40) };
}
export async function fixture(options: { fixed?: boolean; origin?: string; secretLength?: number; info?: Uint8Array; aad?: Uint8Array } = {}) {
  const k = keys(options.fixed), secret = options.fixed ? Uint8Array.from({ length: options.secretLength ?? 32 }, (_, i) => 64 + i) : Uint8Array.from(randomBytes(options.secretLength ?? 32));
  const transcript: RegistrationTranscript = { protocolVersion: 'provider-registration/v1', purpose: 'provider-registration-proof/v1', action: 'register',
    origin: options.origin ?? ORIGIN, challengeId: B64(options.fixed ? Uint8Array.from({ length: 32 }, (_, i) => i) : randomBytes(32)),
    handle: k.handle, edPub: B64(k.edPub), xPub: B64(k.xPub), cardHash: HASH('synthetic-card-fixture/v1'),
    contractRawHash: HASH('synthetic-contract-fixture/v1'), routesHash: HASH('[["GET","/openapi.json"],["POST","/work"]]'),
    expectedVersion: 0, issuedAt: NOW, expiresAt: NOW + 120000,
    nonce: B64(options.fixed ? Uint8Array.from({ length: 32 }, (_, i) => 32 + i) : randomBytes(32)) };
  const s = suite(), pub = await s.kem.deserializePublicKey(k.xPub);
  const sealed = await s.seal({ recipientPublicKey: pub, info: options.info ?? Buffer.concat([Buffer.from('provider-x-pop/v1'), H(J(transcript))]) }, secret, options.aad ?? JSON_BYTES(transcript));
  const publicPart: PublicRegistrationChallenge = { transcript, profile: 'hpke-base-x25519-hkdf-sha256-aes256gcm/v1',
    suite: { kem: 32, kdf: 1, aead: 2, mode: 0 }, enc: B64(new Uint8Array(sealed.enc)), ciphertext: B64(new Uint8Array(sealed.ct)) };
  return { ...k, secret, publicPart, bytes: JSON_BYTES(publicPart), expected: nativeResponse(transcript, secret) };
}
export function payload(p: PublicRegistrationChallenge, xResponse: string) {
  return { transcript: p.transcript, profile: p.profile, suite: p.suite,
    encHash: HASH(Buffer.from(p.enc, 'base64url')), ciphertextHash: HASH(Buffer.from(p.ciphertext, 'base64url')), xResponse };
}
export function nativeProof(p: PublicRegistrationChallenge, response: Uint8Array, edSeed: Uint8Array, header?: unknown, rawHeader?: string) {
  const xResponse = B64(response);
  const protectedPart = B64(Buffer.from(rawHeader ?? J(header ?? { alg: 'EdDSA', kid: 'provider:' + p.transcript.handle, b64: false, crit: ['b64'] })));
  const sig = sign(null, Buffer.from(protectedPart + '.' + J(payload(p, xResponse))), NATIVE_PRIVATE(edSeed));
  return { challengeId: p.transcript.challengeId, xResponse, signature: `${protectedPart}..${B64(sig)}` };
}
export const nativePublic = (edSeed: Uint8Array) => createPublicKey(NATIVE_PRIVATE(edSeed));
