import { describe, expect, it } from "vitest";
import canonicalize from "canonicalize";
import {
  compareRequirements, generateKeyPair, hashJson, hiddenCharFindings, jcs,
  signDetached, verifyDetached, wellFormed, type PaymentRequirement,
} from "../src/index.ts";

const known = { network: "eip155:8453", asset: "0xAbCd", payTo: "0x1234567890ABCDEF1234567890ABCDEF12345678" };
const live: PaymentRequirement = { ...known, scheme: "exact", amount: "1000", source: "header" };

describe("canonical signing input", () => {
  it.each(["\uD800", "\uDC00", "x\uD800y"])("rejects lone surrogates instead of repairing %j", (bad) => {
    const kp = generateKeyPair();
    for (const value of [{ text: bad }, { [bad]: "value" }, { nested: [bad] }]) {
      expect(() => jcs(value)).toThrow();
      expect(() => hashJson(value)).toThrow();
      expect(() => signDetached(value, kp.privateKey, "local")).toThrow();
    }
    const signature = signDetached({ text: "\uFFFD" }, kp.privateKey, "local");
    expect(verifyDetached({ text: bad }, signature, kp.publicKey)).toBe(false);
  });

  it("keeps literal replacement characters and valid Unicode pairs unchanged", () => {
    const value = { text: "\uFFFD\uD83D\uDE00", "\uD83D\uDE00": ["é", "e\u0301"] };
    expect(jcs(value)).toBe(canonicalize(value));
    expect(hashJson({ text: "é" })).not.toBe(hashJson({ text: "e\u0301" }));
    const kp = generateKeyPair();
    expect(verifyDetached(value, signDetached(value, kp.privateKey, "local"), kp.publicKey)).toBe(true);
  });

  it("preserves __proto__ as own data for hashing, signing and non-signing cleanup", () => {
    const original = JSON.parse('{"safe":1,"__proto__":{"changed":true}}');
    const cleaned = wellFormed(original);
    expect(Object.hasOwn(cleaned, "__proto__")).toBe(true);
    expect(Object.getPrototypeOf(cleaned)).toBe(Object.prototype);
    expect(jcs(original)).toBe(canonicalize(original));
    expect(hashJson(original)).not.toBe(hashJson({ safe: 1 }));
    const kp = generateKeyPair();
    const signature = signDetached(original, kp.privateKey, "local");
    expect(verifyDetached(original, signature, kp.publicKey)).toBe(true);
    expect(verifyDetached({ safe: 1 }, signature, kp.publicKey)).toBe(false);
    expect(verifyDetached(JSON.parse('{"safe":1,"__proto__":{"changed":false}}'), signature, kp.publicKey)).toBe(false);
  });

  it("does not drop nested special object keys", () => {
    const value = JSON.parse('{"nested":[{"__proto__":1,"constructor":2,"prototype":3}]}');
    expect(jcs(value)).toBe(canonicalize(value));
    expect(jcs(wellFormed(value))).toBe(canonicalize(value));
  });
});

describe("payment comparison is not authorization", () => {
  it("never calls an empty reference set a match", () => {
    expect(compareRequirements([live], [])).toEqual({ status: "unknown", unknown: [live], payToMismatch: [] });
  });
  it("reports no live requirements separately", () => {
    for (const reference of [[], [known]]) expect(compareRequirements([], reference)).toEqual({ status: "no_requirements", unknown: [], payToMismatch: [] });
  });
  it("requires every live network and asset to be known", () => {
    for (const extra of [{ ...live, network: "eip155:1" }, { ...live, asset: "other" }]) {
      const result = compareRequirements([live, extra], [known]);
      expect(result.status).toBe("unknown");
      expect(result.unknown).toEqual([extra]);
      expect(result.payToMismatch).toEqual([]);
    }
  });
  it("compares EVM recipient case insensitively even for direct callers", () => {
    expect(compareRequirements([{ ...live, payTo: known.payTo.toLowerCase() }], [known]).status).toBe("match");
  });
  it("does not fold non-EVM asset or recipient case", () => {
    const reference = { network: "solana:example", asset: "AbCd", payTo: "Recipient" };
    const req = { ...live, ...reference };
    expect(compareRequirements([{ ...req, asset: "abcd" }], [reference]).status).toBe("unknown");
    expect(compareRequirements([{ ...req, payTo: "recipient" }], [reference]).status).toBe("mismatch");
    expect(compareRequirements([req], [reference]).status).toBe("match");
  });
  it("does not collide network and asset tuple separators", () => {
    expect(compareRequirements([{ ...live, network: "n", asset: "a|b" }], [{ ...known, network: "n|a", asset: "b" }]).status).toBe("unknown");
  });
  it("gives explicit address conflict priority over unknown requirements", () => {
    const changed = { ...live, payTo: "0x0000000000000000000000000000000000000000" };
    const extra = { ...live, asset: "unknown" };
    expect(compareRequirements([changed, extra], [known])).toEqual({ status: "mismatch", payToMismatch: [changed], unknown: [extra] });
  });
  it("allows multiple declared recipients only when every live recipient matches", () => {
    const second = { ...known, payTo: "0x0000000000000000000000000000000000000000" };
    expect(compareRequirements([live, { ...live, payTo: second.payTo }], [known, second]).status).toBe("match");
  });
});

describe("public hidden-character metadata", () => {
  it.each([
    ["a\u{E0041}b", "hidden_chars:unicode_tag"],
    ["a\u200Bb", "hidden_chars:zero_width"],
    ["a\u202Eb", "hidden_chars:bidi_control"],
  ])("contains reason codes without private weights: %s", (text, reasonCode) => {
    expect(hiddenCharFindings(text)).toEqual([{ reasonCode }]);
    expect(hiddenCharFindings("ordinary text 😀")).toEqual([]);
  });
});
