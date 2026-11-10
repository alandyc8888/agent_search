// Canonical hashing and Ed25519 detached JWS (RFC 7515 + RFC 7797-style detached payload,
// payload = RFC 8785 JCS of the entry without trustManifest.signature). No custom crypto.
import canonicalize from "canonicalize";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

/** Lossy cleanup for non-signing ingestion/display only; never use it before signature verification. */
export function wellFormed<T>(v: T): T {
  if (typeof v === "string") return v.toWellFormed() as T;
  if (Array.isArray(v)) return v.map(wellFormed) as T;
  if (v && typeof v === "object") {
    // Define own data properties, including __proto__, without invoking prototype setters.
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k.toWellFormed(), wellFormed(x)])) as T;
  }
  return v;
}

/** Canonicalize the original JSON value. RFC 8785 rejects invalid Unicode; do not repair it. */
export function jcs(value: unknown): string {
  const s = canonicalize(value);
  if (s === undefined) throw new Error("not_canonicalizable");
  return s;
}

const enc = new TextEncoder();

export function sha256Hex(data: string | Uint8Array): string {
  const bytes = typeof data === "string" ? enc.encode(data) : data;
  return Buffer.from(sha256(bytes)).toString("hex");
}

export function hashJson(value: unknown): string {
  return "sha256:" + sha256Hex(jcs(value));
}

const b64u = (b: Uint8Array | string) => Buffer.from(typeof b === "string" ? enc.encode(b) : b).toString("base64url");
const fromB64u = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const privateKey = ed25519.utils.randomSecretKey();
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) };
}

export function publicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey);
}

/** Detached compact JWS: "<protected>..<signature>" over JCS(payload). */
export function signDetached(payload: unknown, privateKey: Uint8Array, kid: string): string {
  const header = b64u(jcs({ alg: "EdDSA", kid, b64: false, crit: ["b64"] }));
  const signingInput = enc.encode(`${header}.${jcs(payload)}`);
  const sig = ed25519.sign(signingInput, privateKey);
  return `${header}..${b64u(sig)}`;
}

export interface JwsHeader {
  alg: string;
  kid?: string;
  b64?: boolean;
  crit?: string[];
}

export function readJwsHeader(jws: string): JwsHeader | null {
  const parts = jws.split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as JwsHeader;
  } catch {
    return null;
  }
}

export function verifyDetached(payload: unknown, jws: string, publicKey: Uint8Array): boolean {
  const parts = jws.split(".");
  if (parts.length !== 3 || parts[1] !== "") return false;
  const h = readJwsHeader(jws);
  if (!h || h.alg !== "EdDSA" || h.b64 !== false) return false;
  try {
    const signingInput = enc.encode(`${parts[0]}.${jcs(payload)}`);
    return ed25519.verify(fromB64u(parts[2]), signingInput, publicKey);
  } catch {
    return false;
  }
}

export const toB64u = b64u;
export const fromBase64Url = fromB64u;
