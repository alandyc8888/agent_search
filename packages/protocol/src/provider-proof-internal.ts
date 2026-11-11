// Implementation-only registration profile. Not package-root API, storage or admission authority.
import { createHash } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { jcs } from './crypto.ts';
import { copyProofData, ownProofBytes, parseProofHeader, proofInvalid, proofRecord } from './strict-json.ts';

export const PROOF_PROFILE = 'hpke-base-x25519-hkdf-sha256-aes256gcm/v1';
export const PROOF_SUITE = Object.freeze({ kem: 32, kdf: 1, aead: 2, mode: 0 });
export const TRANSCRIPT_KEYS = ['protocolVersion', 'purpose', 'action', 'origin', 'challengeId', 'handle', 'edPub', 'xPub',
  'cardHash', 'contractRawHash', 'routesHash', 'expectedVersion', 'issuedAt', 'expiresAt', 'nonce'] as const;
export interface RegistrationTranscript {
  protocolVersion: 'provider-registration/v1'; purpose: 'provider-registration-proof/v1'; action: 'register';
  origin: string; challengeId: string; handle: string; edPub: string; xPub: string;
  cardHash: string; contractRawHash: string; routesHash: string; expectedVersion: 0;
  issuedAt: number; expiresAt: number; nonce: string;
}
export interface PublicRegistrationChallenge {
  transcript: RegistrationTranscript; profile: typeof PROOF_PROFILE; suite: typeof PROOF_SUITE;
  enc: string; ciphertext: string;
}
export const b64Proof = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
export const proofHash = (bytes: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(bytes).digest());
export const proofHashLabel = (bytes: Uint8Array): string => 'sha256:' + Buffer.from(proofHash(bytes)).toString('hex');
export function exactProofBytes(input: unknown, length: number): Uint8Array {
  const out = ownProofBytes(input, length);
  if (out.length !== length) { out.fill(0); return proofInvalid(); }
  return out;
}
export function decodeProofBinary(value: unknown, length: number): Uint8Array {
  const encodedLength = Math.ceil(length * 4 / 3);
  if (typeof value !== 'string' || value.length !== encodedLength || !/^[A-Za-z0-9_-]+$/.test(value)) return proofInvalid();
  const out = Buffer.from(value, 'base64url');
  if (out.length !== length || out.toString('base64url') !== value) { out.fill(0); return proofInvalid(); }
  return Uint8Array.from(out);
}
export function proofJcsBytes(input: unknown): Uint8Array {
  const bytes = new TextEncoder().encode(jcs(copyProofData(input)));
  if (bytes.length > 4096) return proofInvalid();
  return bytes;
}
export function proofOrigin(input: unknown): string {
  if (typeof input !== 'string' || input.length > 256) return proofInvalid();
  try {
    const url = new URL(input);
    if (url.origin !== input || url.username || url.password || url.search || url.hash ||
        !(url.protocol === 'https:' || url.protocol === 'http:' && url.hostname === '127.0.0.1')) return proofInvalid();
    return input;
  } catch { return proofInvalid(); }
}
export function proofNow(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) return proofInvalid();
  return value;
}
export function proofHandle(edPub: Uint8Array): string { return 'p-' + Buffer.from(proofHash(edPub)).toString('hex').slice(0, 40); }
export function strictEdPublicKey(publicKey: Uint8Array): void {
  try {
    const point = ed25519.Point.fromBytes(publicKey, false);
    if (point.isSmallOrder() || !Buffer.from(point.toBytes()).equals(publicKey)) return proofInvalid();
  } catch { return proofInvalid(); }
}
export function checkTranscript(input: unknown): RegistrationTranscript {
  const t = proofRecord(copyProofData(input), TRANSCRIPT_KEYS);
  if (t.protocolVersion !== 'provider-registration/v1' || t.purpose !== 'provider-registration-proof/v1' ||
      t.action !== 'register' || t.expectedVersion !== 0) return proofInvalid();
  proofOrigin(t.origin);
  const edPub = decodeProofBinary(t.edPub, 32); strictEdPublicKey(edPub);
  decodeProofBinary(t.xPub, 32); decodeProofBinary(t.nonce, 32); decodeProofBinary(t.challengeId, 32);
  if (typeof t.handle !== 'string' || t.handle !== proofHandle(edPub)) return proofInvalid();
  for (const field of ['cardHash', 'contractRawHash', 'routesHash']) {
    if (typeof t[field] !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(t[field] as string)) return proofInvalid();
  }
  const issuedAt = proofNow(t.issuedAt), expiresAt = proofNow(t.expiresAt);
  if (issuedAt > Number.MAX_SAFE_INTEGER - 120000 || expiresAt !== issuedAt + 120000) return proofInvalid();
  return t as unknown as RegistrationTranscript;
}
export function checkChallenge(input: unknown): PublicRegistrationChallenge {
  const p = proofRecord(copyProofData(input), ['transcript', 'profile', 'suite', 'enc', 'ciphertext']);
  const suite = proofRecord(p.suite, ['kem', 'kdf', 'aead', 'mode']);
  if (p.profile !== PROOF_PROFILE || suite.kem !== 32 || suite.kdf !== 1 || suite.aead !== 2 || suite.mode !== 0) return proofInvalid();
  const transcript = checkTranscript(p.transcript);
  decodeProofBinary(p.enc, 32); decodeProofBinary(p.ciphertext, 48);
  return { transcript, profile: PROOF_PROFILE, suite: { ...PROOF_SUITE }, enc: p.enc as string, ciphertext: p.ciphertext as string };
}
export function checkProofContext(t: RegistrationTranscript, origin: string, now: number): void {
  if (t.origin !== origin || now < t.issuedAt || now >= t.expiresAt) return proofInvalid();
}
export function proofHpkeSuite(): CipherSuite {
  return new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
}
export function proofHpkeInfo(t: RegistrationTranscript): Uint8Array {
  return new Uint8Array(Buffer.concat([Buffer.from('provider-x-pop/v1', 'utf8'), proofHash(proofJcsBytes(t))]));
}
export function computeXResponse(t: RegistrationTranscript, secret32: Uint8Array): Uint8Array {
  let owned: Uint8Array | undefined, preimage: Buffer | undefined;
  try {
    owned = exactProofBytes(secret32, 32);
    preimage = Buffer.concat([Buffer.from('provider-x-response/v1', 'utf8'), proofHash(proofJcsBytes(t)), owned]);
    return proofHash(preimage);
  } finally { owned?.fill(0); preimage?.fill(0); }
}
export function registrationPayload(p: PublicRegistrationChallenge, response: string): unknown {
  decodeProofBinary(response, 32);
  return { transcript: p.transcript, profile: p.profile, suite: p.suite,
    encHash: proofHashLabel(decodeProofBinary(p.enc, 32)), ciphertextHash: proofHashLabel(decodeProofBinary(p.ciphertext, 48)), xResponse: response };
}
export function registrationHeader(handle: string): string {
  return b64Proof(proofJcsBytes({ alg: 'EdDSA', kid: 'provider:' + handle, b64: false, crit: ['b64'] }));
}
export function registrationSigningInput(header: string, p: PublicRegistrationChallenge, response: string): Uint8Array {
  return new Uint8Array(Buffer.concat([Buffer.from(header + '.', 'ascii'), proofJcsBytes(registrationPayload(p, response))]));
}
/** Implementation-only raw primitive, with the same immutable profile used by registration JWS. */
export function verifyStrictProofEdSignature(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): void {
  try {
    strictEdPublicKey(publicKey);
    if (!ed25519.verify(signature, message, publicKey, { zip215: false })) return proofInvalid();
  } catch { return proofInvalid(); }
}
/** No caller-selectable options and no legacy permissive-verifier fallback. */
export function verifyRegistrationSignature(p: PublicRegistrationChallenge, response: string, signature: unknown): void {
  try {
    if (typeof signature !== 'string' || signature.length > 1024) return proofInvalid();
    const parts = signature.split('.');
    if (parts.length !== 3 || parts[1] !== '' || !parts[0] || parts[0].length > 683 || !/^[A-Za-z0-9_-]+$/.test(parts[0])) return proofInvalid();
    const headerBytes = Buffer.from(parts[0], 'base64url');
    if (headerBytes.length > 512 || b64Proof(headerBytes) !== parts[0]) return proofInvalid();
    const parsed = parseProofHeader(headerBytes);
    const header = proofRecord(parsed, ['alg', 'kid', 'b64', 'crit']);
    if (header.alg !== 'EdDSA' || header.kid !== 'provider:' + p.transcript.handle || header.b64 !== false ||
        !Array.isArray(header.crit) || header.crit.length !== 1 || header.crit[0] !== 'b64' ||
        !Buffer.from(proofJcsBytes(parsed)).equals(headerBytes)) return proofInvalid();
    const sig = decodeProofBinary(parts[2], 64), publicKey = decodeProofBinary(p.transcript.edPub, 32);
    verifyStrictProofEdSignature(sig, registrationSigningInput(parts[0], p, response), publicKey);
  } catch { return proofInvalid(); }
}
