// Fixed-budget registration proof data only. No repair, resolvers or caller-selected limits.
import { types } from 'node:util';

const ta = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(ta, 'byteLength')!.get!;
const backing = Object.getOwnPropertyDescriptor(ta, 'buffer')!.get!;
const utf8 = new TextEncoder();
export function proofInvalid(): never { throw Error('proof_invalid'); }

/** Capture actual view bytes, not overridable properties, before any async work. */
export function ownProofBytes(input: unknown, maximum = 4096): Uint8Array {
  try {
    if (types.isProxy(input) || !types.isUint8Array(input) || types.isSharedArrayBuffer(backing.call(input))) return proofInvalid();
    const length = byteLength.call(input);
    if (length > maximum) return proofInvalid();
    const out = new Uint8Array(length);
    Uint8Array.prototype.set.call(out, input);
    return out;
  } catch { return proofInvalid(); }
}

function validString(value: string, maximum: number): string {
  if (!value.isWellFormed() || utf8.encode(value).length > maximum) return proofInvalid();
  return value;
}

function parse(raw: unknown, bytes: number, depthLimit: number, nodeLimit: number, stringLimit: number): unknown {
  try {
    const owned = ownProofBytes(raw, bytes);
    // ignoreBOM:true retains the code point so that it is rejected rather than silently stripped.
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(owned);
    let at = 0, nodes = 0;
    function ws() { while (at < text.length && /[\x20\t\r\n]/.test(text[at])) at++; }
    function count() { if (++nodes > nodeLimit) proofInvalid(); }
    function string(): string {
      const begin = at++;
      while (at < text.length) {
        const c = text.charCodeAt(at++);
        if (c === 34) return validString(JSON.parse(text.slice(begin, at)), stringLimit);
        if (c < 32) return proofInvalid();
        if (c === 92) {
          if (at >= text.length) return proofInvalid();
          const escaped = text[at++];
          if (escaped === 'u') {
            if (!/^[0-9a-fA-F]{4}$/.test(text.slice(at, at + 4))) return proofInvalid();
            at += 4;
          } else if (!'"\\/bfnrt'.includes(escaped)) return proofInvalid();
        }
      }
      return proofInvalid();
    }
    function value(depth: number): unknown {
      if (depth > depthLimit) return proofInvalid();
      count(); ws();
      if (text[at] === '"') return string();
      if (text[at] === '{') {
        at++; ws();
        const out = Object.create(null), seen = new Set<string>();
        if (text[at] === '}') { at++; return out; }
        for (;;) {
          if (text[at] !== '"') return proofInvalid();
          count(); const key = string();
          if (seen.has(key)) return proofInvalid();
          seen.add(key); ws();
          if (text[at++] !== ':') return proofInvalid();
          Object.defineProperty(out, key, { value: value(depth + 1), enumerable: true, configurable: true, writable: true });
          ws(); const end = text[at++];
          if (end === '}') return out;
          if (end !== ',') return proofInvalid();
          ws();
        }
      }
      if (text[at] === '[') {
        at++; ws(); const out: unknown[] = [];
        if (text[at] === ']') { at++; return out; }
        for (;;) {
          out.push(value(depth + 1)); ws(); const end = text[at++];
          if (end === ']') return out;
          if (end !== ',') return proofInvalid();
        }
      }
      for (const [token, result] of [['true', true], ['false', false], ['null', null]] as const) {
        if (text.startsWith(token, at)) { at += token.length; return result; }
      }
      const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(at));
      if (!number) return proofInvalid();
      at += number[0].length;
      const result = Number(number[0]);
      if (!Number.isSafeInteger(result)) return proofInvalid();
      return result;
    }
    const result = value(1); ws();
    if (at !== text.length) return proofInvalid();
    return result;
  } catch { return proofInvalid(); }
}

export function parseProofJson(rawBytes: unknown): unknown { return parse(rawBytes, 4096, 16, 256, 2048); }
// Internal fixed header profile, not exported by the package root.
export function parseProofHeader(rawBytes: unknown): unknown { return parse(rawBytes, 512, 4, 16, 256); }

/** Only plain own-data objects/arrays; reject proxies before reflection and never invoke getters. */
export function copyProofData(input: unknown): unknown {
  let nodes = 0;
  const seen = new Set<object>();
  function copy(value: unknown, depth: number): unknown {
    if (depth > 16 || ++nodes > 256) return proofInvalid();
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'string') return validString(value, 2048);
    if (typeof value === 'number') { if (!Number.isSafeInteger(value)) return proofInvalid(); return value; }
    if (typeof value !== 'object' || types.isProxy(value) || seen.has(value)) return proofInvalid();
    const array = Array.isArray(value), proto = Object.getPrototypeOf(value);
    if (array ? proto !== Array.prototype : proto !== null && proto !== Object.prototype) return proofInvalid();
    seen.add(value);
    const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors);
    if (keys.some(key => typeof key !== 'string')) return proofInvalid();
    if (array) {
      const lengthDescriptor = descriptors.length;
      if (!lengthDescriptor || !('value' in lengthDescriptor) || !Number.isSafeInteger(lengthDescriptor.value) ||
          lengthDescriptor.value > 256 || keys.length !== lengthDescriptor.value + 1) return proofInvalid();
      const out: unknown[] = [];
      for (let i = 0; i < lengthDescriptor.value; i++) {
        const d = descriptors[String(i)];
        if (!d || !('value' in d) || !d.enumerable) return proofInvalid();
        out.push(copy(d.value, depth + 1));
      }
      seen.delete(value); return out;
    }
    const out = Object.create(null);
    for (const key of keys as string[]) {
      const d = descriptors[key];
      if (!('value' in d) || !d.enumerable || key === 'toJSON') return proofInvalid();
      if (++nodes > 256) return proofInvalid();
      validString(key, 2048);
      Object.defineProperty(out, key, { value: copy(d.value, depth + 1), enumerable: true, configurable: true, writable: true });
    }
    seen.delete(value); return out;
  }
  try { return copy(input, 1); } catch { return proofInvalid(); }
}

/** Read only this object's own data fields. No inherited properties, symbols or accessor side effects. */
export function proofRecord(input: unknown, keys: readonly string[]): Record<string, unknown> {
  try {
    if (!input || typeof input !== 'object' || types.isProxy(input) || Array.isArray(input)) return proofInvalid();
    const proto = Object.getPrototypeOf(input);
    if (proto !== null && proto !== Object.prototype) return proofInvalid();
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const actual = Reflect.ownKeys(descriptors);
    if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key))) return proofInvalid();
    const result = Object.create(null);
    for (const key of keys) {
      const d = descriptors[key];
      if (!d || !('value' in d) || !d.enumerable || key === 'toJSON') return proofInvalid();
      Object.defineProperty(result, key, { value: d.value, enumerable: true });
    }
    return result;
  } catch { return proofInvalid(); }
}
