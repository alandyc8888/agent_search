// RFC7748/RFC9180 X25519 private serialization boundary only. No DH/KDF/AEAD.
import { types } from 'node:util';

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const intrinsicLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'length')!.get!;
const intrinsicBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer')!.get!;

/** Return a fresh owned 32-byte copy. Never alter input, neighboring bytes or Ed seeds. */
export function normalizeX25519Private(raw: unknown): Uint8Array {
  try {
    if (!types.isUint8Array(raw) || intrinsicLength.call(raw) !== 32 ||
        types.isSharedArrayBuffer(intrinsicBuffer.call(raw))) throw Error();
    const owned = new Uint8Array(32);
    Uint8Array.prototype.set.call(owned, raw);
    owned[0] &= 248;
    owned[31] &= 127;
    owned[31] |= 64;
    return owned;
  } catch {
    throw Error('x25519_private_invalid');
  }
}
