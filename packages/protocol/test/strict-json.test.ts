import { describe, expect, it } from 'vitest';
import { parseProofJson } from '../src/index.ts';
import { copyProofData, ownProofBytes, parseProofHeader, proofRecord } from '../src/strict-json.ts';
const raw = (text: string) => new TextEncoder().encode(text);

describe('fixed registration JSON boundary', () => {
  it('preserves own __proto__/constructor data and valid paired Unicode', () => {
    const parsed = parseProofJson(raw('{"__proto__":{"safe":1},"constructor":false,"x":"\\ud83d\\ude00"}')) as any;
    expect(Object.getPrototypeOf(parsed)).toBe(null);
    expect(Object.hasOwn(parsed, '__proto__') && parsed.__proto__.safe === 1 && parsed.constructor === false && parsed.x === '😀').toBe(true);
    expect(({} as any).safe).toBeUndefined();
  });
  it.each([
    '', '\ufeff{}', '{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":1,}', '[1,]',
    '{"x":"\\ud800"}', '{"x":"\\udc00"}', '"\n"', '"\\x41"', '"\\u123"',
    '01', '+1', 'NaN', 'Infinity', '1e999', '9007199254740992', '1.1', '{} true', '{', '[', 'truefalse',
  ])('rejects invalid syntax/encoding/value %#', text => { expect(() => parseProofJson(raw(text))).toThrow('proof_invalid'); });
  it('rejects bad UTF8 rather than inserting replacement characters', () => {
    for (const bytes of [[34, 0xc0, 0xaf, 34], [34, 0xed, 0xa0, 0x80, 34], [34, 0xff, 34], [0xef, 0xbb, 0xbf, 123, 125]]) {
      expect(() => parseProofJson(Uint8Array.from(bytes))).toThrow('proof_invalid');
    }
  });
  it('enforces byte, depth, node and UTF8 string budgets independently', () => {
    expect(() => parseProofJson(raw(' '.repeat(4097)))).toThrow('proof_invalid');
    expect(() => parseProofJson(raw('['.repeat(17) + '0' + ']'.repeat(17)))).toThrow('proof_invalid');
    expect(() => parseProofJson(raw('[' + Array(256).fill('0').join(',') + ']'))).toThrow('proof_invalid');
    expect(() => parseProofJson(raw(JSON.stringify('€'.repeat(683))))).toThrow('proof_invalid');
    expect(typeof parseProofJson(raw(JSON.stringify('a'.repeat(2048))))).toBe('string');
    expect(() => parseProofJson(raw(JSON.stringify('a'.repeat(2049))))).toThrow('proof_invalid');
    expect(parseProofJson(raw('['.repeat(15) + '0' + ']'.repeat(15)))).toBeDefined();
  });
  it('hard-codes a smaller protected-header budget', () => {
    expect(() => parseProofHeader(raw(' '.repeat(513)))).toThrow('proof_invalid');
    expect(() => parseProofHeader(raw(JSON.stringify('a'.repeat(257))))).toThrow('proof_invalid');
    expect(() => parseProofHeader(raw('[[[[[0]]]]]'))).toThrow('proof_invalid');
  });
  it('snapshots real view bytes without invoking own getters and refuses shared/wrong views', () => {
    let accessed = 0;
    const view = raw('{}');
    for (const key of ['buffer', 'byteLength', 'length', Symbol.iterator]) Object.defineProperty(view, key, { get() { accessed++; throw Error('trap'); } });
    expect(parseProofJson(view)).toEqual({}); expect(accessed).toBe(0);
    const buffer = Buffer.from('xx{}yy'), copy = ownProofBytes(buffer.subarray(2, 4));
    buffer.fill(0); expect(Buffer.from(copy).toString()).toBe('{}');
    for (const input of [new Uint8Array(new SharedArrayBuffer(2)), {}, [], null, new DataView(new ArrayBuffer(2)), new Uint16Array(2), new Proxy(raw('{}'), {})]) {
      expect(() => parseProofJson(input)).toThrow('proof_invalid');
    }
    const detached = raw('{}'); structuredClone(detached, { transfer: [detached.buffer] });
    expect(() => parseProofJson(detached)).toThrow('proof_invalid');
  });
  it('copies only own data without invoking accessors/proxy traps/toJSON', () => {
    let traps = 0;
    const getter = { get a() { traps++; return 1; } };
    const proxy = new Proxy({}, { ownKeys() { traps++; throw Error('trap'); }, getPrototypeOf() { traps++; throw Error('trap'); } });
    const callable = { toJSON() { traps++; return {}; } };
    const symbol = { [Symbol('extra')]: 1 };
    for (const input of [getter, proxy, callable, symbol, Object.create({ a: 1 }), new Date(), { a: undefined }, { a: () => 1 }, [, 1]]) {
      expect(() => copyProofData(input)).toThrow('proof_invalid');
    }
    expect(() => proofRecord(getter, ['a'])).toThrow('proof_invalid');
    expect(() => proofRecord(proxy, [])).toThrow('proof_invalid');
    expect(traps).toBe(0);
    const circular: any = {}; circular.a = circular; expect(() => copyProofData(circular)).toThrow('proof_invalid');
    const a = { nested: { a: 1 } }, copied = copyProofData(a) as any; a.nested.a = 2; expect(copied.nested.a).toBe(1);
  });
  it('matches native JSON values for deterministic valid nested fixtures', () => {
    for (let i = 0; i < 100; i++) {
      const value = { i, nested: [true, false, null, 'é/😀\\\"', { x: i * 31 }], ['k' + i]: -i };
      expect(parseProofJson(raw(JSON.stringify(value)))).toEqual(JSON.parse(JSON.stringify(value)));
    }
  });
});
