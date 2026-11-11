// Sealed boxes for the relay: inbox messages and results are encrypted at rest.
// Construction: X25519 ECDH with an ephemeral sender key → HKDF-SHA256 → AES-256-GCM
// (same shape as HPKE base mode with DHKEM(X25519)/HKDF-SHA256/AES-256-GCM; to be swapped for
// @hpke/core before tier 2). No new primitives.
//
// Two uses:
//  - inbox message → sealed to the provider's published X25519 key for storage and connector delivery
//  - result → sealed to a separate per-request key derived from the pickup token; the
//    stored row keeps sha256(token) and the derived public key, not the raw pickup token.
// This is storage sealing, not E2EE: the relay processes plaintext and sees the pickup
// token on authorized retrieval. It does not protect against a malicious relay.
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "node:crypto";

const enc = new TextEncoder();
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const unb64u = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));

export interface Sealed {
  v: 1;
  epk: string; // sender ephemeral X25519 public key
  iv: string;
  ct: string; // ciphertext || 16-byte tag
}

export function x25519KeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = x25519.utils.randomSecretKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

function aeadKey(shared: Uint8Array, epk: Uint8Array, rpk: Uint8Array, info: string): Uint8Array {
  const salt = new Uint8Array([...epk, ...rpk]);
  return hkdf(sha256, shared, salt, enc.encode(info), 32);
}

export function seal(recipientPub: Uint8Array, plaintext: Uint8Array, info = "a2n-seal-v1"): Sealed {
  const eph = x25519KeyPair();
  const shared = x25519.getSharedSecret(eph.privateKey, recipientPub);
  const key = aeadKey(shared, eph.publicKey, recipientPub, info);
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return { v: 1, epk: b64u(eph.publicKey), iv: b64u(iv), ct: b64u(ct) };
}

export function open(recipientPriv: Uint8Array, box: Sealed, info = "a2n-seal-v1"): Uint8Array {
  if (!box || box.v !== 1) throw new Error("bad_box");
  const epk = unb64u(box.epk);
  const rpk = x25519.getPublicKey(recipientPriv);
  const shared = x25519.getSharedSecret(recipientPriv, epk);
  const key = aeadKey(shared, epk, rpk, info);
  const raw = unb64u(box.ct);
  if (raw.length < 16) throw new Error("bad_box");
  const d = createDecipheriv("aes-256-gcm", key, unb64u(box.iv));
  d.setAuthTag(raw.subarray(raw.length - 16));
  return new Uint8Array(Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]));
}

export const sealJson = (pub: Uint8Array, v: unknown, info?: string) => seal(pub, enc.encode(JSON.stringify(v)), info);
export const openJson = <T>(priv: Uint8Array, box: Sealed, info?: string): T => JSON.parse(Buffer.from(open(priv, box, info)).toString("utf8")) as T;

// ---- pickup tokens ----

/** 256-bit random token, base64url. */
export function newPickupToken(): string {
  return b64u(randomBytes(32));
}
/** What the relay stores: a domain-separated hash, never the token. */
export function pickupTokenHash(token: string): string {
  return Buffer.from(sha256(enc.encode("a2n-pickup-id-v1:" + token))).toString("hex");
}
/** Per-request X25519 key pair derived from the token (independent of the stored hash). */
export function pickupKeyPair(token: string): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = hkdf(sha256, enc.encode(token), new Uint8Array(0), enc.encode("a2n-pickup-x25519-v1"), 32);
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}
export function hashEquals(aHex: string, bHex: string): boolean {
  const a = Buffer.from(aHex, "hex");
  const b = Buffer.from(bHex, "hex");
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

// ---- untrusted wrapping (tier 1: the relay wraps provider content on the consumer's behalf) ----

/** Neutralise anything that looks like our markers inside provider content. */
export function escapeMarkers(s: string): string {
  return s.replace(/<<<\s*A2N/gi, "‹‹‹A2N").replace(/A2N-UNTRUSTED/gi, "A2N_UNTRUSTED_ESCAPED");
}

export function wrapUntrusted(text: string, source: string): { nonce: string; text: string } {
  const nonce = b64u(randomBytes(9));
  const body = escapeMarkers(text);
  return {
    nonce,
    text:
      `<<<A2N-UNTRUSTED-BEGIN nonce=${nonce} source=${escapeMarkers(source).replace(/\s/g, "_")}>>>\n` +
      `${body}\n` +
      `<<<A2N-UNTRUSTED-END nonce=${nonce}>>>`,
  };
}
