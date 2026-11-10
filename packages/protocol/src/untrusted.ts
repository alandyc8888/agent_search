// Basic handling of untrusted text, shared by the plugin and the index.
//
// Detection rules (injection patterns, risk classifiers, thresholds) are deliberately NOT in this
// package. They live in a private package so attackers cannot tune their text against them.
// These helpers clean or label data; they do not sandbox a model, prevent instruction following,
// enforce consent, or authorize payment. Callers must apply those controls separately.

const TAG_CHARS = /[\u{E0000}-\u{E007F}]/u;
const ZERO_WIDTH = /[\u200B-\u200F\u2060-\u2064\uFEFF\u180E]/u;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/u;

export interface ScanFinding {
  reasonCode: string;
  severity: number;
}

/** Character metadata only: no risk weights and no implicit stripping. Use stripHidden separately. */
export function hiddenCharFindings(text: string): Pick<ScanFinding, "reasonCode">[] {
  const f: Pick<ScanFinding, "reasonCode">[] = [];
  if (TAG_CHARS.test(text)) f.push({ reasonCode: "hidden_chars:unicode_tag" });
  if (ZERO_WIDTH.test(text)) f.push({ reasonCode: "hidden_chars:zero_width" });
  if (BIDI.test(text)) f.push({ reasonCode: "hidden_chars:bidi_control" });
  return f;
}

/** Remove hidden/control characters and lone surrogates before indexing or display. */
export function stripHidden(text: string): string {
  return text
    .toWellFormed()
    .replace(/[\u{E0000}-\u{E007F}]/gu, "")
    .replace(/[\u200B-\u200F\u2060-\u2064\uFEFF\u180E\u202A-\u202E\u2066-\u2069]/gu, "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
}

/** Cap and clean a field from an untrusted source (counts code points; never splits a surrogate pair). */
export function cleanField(v: unknown, max: number): string | undefined {
  if (typeof v !== "string") return undefined;
  const s = stripHidden(v).trim();
  if (!s) return undefined;
  const cps = Array.from(s);
  return cps.length > max ? cps.slice(0, max).join("") + "…" : s;
}

/** Risk combination (noisy-OR): R = 100 × (1 − Π(1 − s_i)). */
export function noisyOr(severities: number[]): number {
  let p = 1;
  for (const s of severities) p *= 1 - Math.min(1, Math.max(0, s));
  return Math.round(100 * (1 - p));
}

// Wrapping external content for a model: see wrapUntrusted() in seal.ts (nonce-delimited markers).
