// Private serialization adapter only. Does not change the legacy sealed-box protocol.
import { KeyObject, webcrypto } from 'node:crypto';
import { types } from 'node:util';
import { DhkemX25519HkdfSha256 } from '@hpke/core';
import { normalizeX25519Private } from './x25519-private.ts';

const kem = new DhkemX25519HkdfSha256();
const isUint8Array = types.isUint8Array;
const keyType = Object.getOwnPropertyDescriptor(CryptoKey.prototype, 'type')!.get!;
const keyExtractable = Object.getOwnPropertyDescriptor(CryptoKey.prototype, 'extractable')!.get!;
function decode32(value: unknown): Buffer {
  if (typeof value !== 'string' || value.length !== 43 || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw Error('x25519_private_invalid');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) { bytes.fill(0); throw Error('x25519_private_invalid'); }
  return bytes;
}
function checkPrivateKey(key: unknown): asserts key is CryptoKey {
  if (!types.isCryptoKey(key) || keyType.call(key) !== 'private' || !keyExtractable.call(key)) {
    throw Error('x25519_key_operation_failed');
  }
  // CryptoKey.algorithm is mutable metadata. Only the native key material establishes its curve.
  const nativeKey = KeyObject.from(key);
  if (nativeKey.type !== 'private' || nativeKey.asymmetricKeyType !== 'x25519') {
    throw Error('x25519_key_operation_failed');
  }
}
async function publicBytes(key: CryptoKey): Promise<Uint8Array> {
  let jwk: webcrypto.JsonWebKey | undefined;
  try {
    jwk = await webcrypto.subtle.exportKey('jwk', key);
    if (jwk.kty !== 'OKP' || jwk.crv !== 'X25519') throw Error();
    return Uint8Array.from(decode32(jwk.x));
  } finally {
    if (jwk && Object.hasOwn(jwk, 'd')) delete jwk.d;
  }
}

/** Missing declaration means no second argument; explicit undefined/null is invalid. */
export async function importX25519Private(input: unknown, declaredXPub?: unknown): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  let owned: Uint8Array | undefined, decoded: Buffer | undefined;
  let declared: Buffer | undefined;
  const hasDeclaration = arguments.length >= 2;
  // Acquire the private copy synchronously before the first await.
  try {
    if (hasDeclaration) declared = decode32(declaredXPub);
    if (typeof input === 'string') {
      decoded = decode32(input);
      owned = normalizeX25519Private(decoded);
    } else {
      owned = normalizeX25519Private(input);
    }
  } catch {
    decoded?.fill(0); owned?.fill(0);
    throw Error('x25519_private_invalid');
  }
  decoded?.fill(0);
  try {
    const privateKey = await kem.deserializePrivateKey(owned);
    checkPrivateKey(privateKey);
    const publicKey = await publicBytes(privateKey);
    if (hasDeclaration && (declared!.length !== publicKey.length || !Buffer.from(declared!).equals(publicKey))) {
      throw Error('x25519_public_mismatch');
    }
    return { privateKey, publicKey };
  } catch (error) {
    if (error instanceof Error && error.message === 'x25519_public_mismatch') throw Error('x25519_public_mismatch');
    throw Error('x25519_key_operation_failed');
  } finally {
    owned.fill(0);
  }
}

/** Keep the library-owned ArrayBuffer unchanged; only normalize our independent copy. */
export async function exportX25519Private(key: unknown): Promise<Uint8Array> {
  try {
    checkPrivateKey(key);
    const serialized = await kem.serializePrivateKey(key);
    if (!types.isArrayBuffer(serialized) || serialized.byteLength !== 32) throw Error();
    const view = new Uint8Array(serialized);
    if (!isUint8Array(view)) throw Error();
    return normalizeX25519Private(view);
  } catch {
    throw Error('x25519_key_operation_failed');
  }
}

/** Generate independently from Ed, then verify canonical reimport preserves generated xPub. */
export async function generateX25519Identity(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
  let owned: Uint8Array | undefined;
  let delivered = false;
  try {
    const pair = await kem.generateKeyPair();
    owned = await exportX25519Private(pair.privateKey);
    const reimported = await importX25519Private(owned);
    const originalPub = await kem.serializePublicKey(pair.publicKey);
    if (!types.isArrayBuffer(originalPub) || originalPub.byteLength !== 32 ||
        !Buffer.from(originalPub).equals(reimported.publicKey)) throw Error();
    delivered = true;
    return { privateKey: owned, publicKey: reimported.publicKey };
  } catch {
    throw Error('x25519_key_operation_failed');
  } finally {
    if (!delivered) owned?.fill(0);
  }
}
