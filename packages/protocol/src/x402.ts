// Parse x402 payment requirements from an untrusted 402 response.
// v2: base64 JSON in the PAYMENT-REQUIRED header. Many live servers also (or only) put
// the object in the body, and some still speak v1 (maxAmountRequired, network names).
// We read both and report where each requirement came from.

export interface PaymentRequirement {
  scheme: string;
  network: string; // CAIP-2 when we can map it, else the raw value
  amount: string; // atomic units, decimal string
  asset: string; // lowercased
  payTo: string; // lowercased for EVM
  maxTimeoutSeconds?: number;
  source: "header" | "body";
  x402Version?: number;
}

export interface Parsed402 {
  version?: number;
  requirements: PaymentRequirement[];
  errors: string[];
}

const V1_NETWORKS: Record<string, string> = {
  base: "eip155:8453",
  "base-sepolia": "eip155:84532",
  ethereum: "eip155:1",
  polygon: "eip155:137",
  "polygon-amoy": "eip155:80002",
  avalanche: "eip155:43114",
  "avalanche-fuji": "eip155:43113",
  bsc: "eip155:56",
  solana: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
  "solana-devnet": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
};

const MAX_REQ = 32;
const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length < 512;

function normAddr(a: string): string {
  return /^0x[0-9a-fA-F]{40}$/.test(a) ? a.toLowerCase() : a;
}

function fromObject(obj: unknown, source: "header" | "body", out: Parsed402): void {
  if (!obj || typeof obj !== "object") return;
  const o = obj as Record<string, unknown>;
  const version = typeof o.x402Version === "number" ? o.x402Version : undefined;
  if (version !== undefined && out.version === undefined) out.version = version;
  const accepts = Array.isArray(o.accepts) ? o.accepts.slice(0, MAX_REQ) : [];
  for (const a of accepts) {
    if (!a || typeof a !== "object") continue;
    const r = a as Record<string, unknown>;
    const amountRaw = r.amount ?? r.maxAmountRequired;
    const amount = typeof amountRaw === "number" ? String(Math.trunc(amountRaw)) : amountRaw;
    if (!isStr(r.scheme) || !isStr(r.network) || !isStr(amount) || !/^\d{1,78}$/.test(amount) || !isStr(r.asset) || !isStr(r.payTo)) {
      out.errors.push(`${source}:malformed_requirement`);
      continue;
    }
    const network = r.network.includes(":") ? r.network : (V1_NETWORKS[r.network] ?? r.network);
    out.requirements.push({
      scheme: r.scheme,
      network,
      amount,
      asset: normAddr(r.asset),
      payTo: normAddr(r.payTo),
      maxTimeoutSeconds: typeof r.maxTimeoutSeconds === "number" ? r.maxTimeoutSeconds : undefined,
      source,
      x402Version: version,
    });
  }
}

export function decodeBase64Json(s: string): unknown {
  const clean = s.trim();
  if (clean.length > 64 * 1024) throw new Error("header_too_large");
  const txt = Buffer.from(clean, "base64").toString("utf8");
  return JSON.parse(txt);
}

/** headerValue: PAYMENT-REQUIRED header (may be null). bodyText: response body, already size-capped. */
export function parse402(headerValue: string | null, bodyText: string | null): Parsed402 {
  const out: Parsed402 = { requirements: [], errors: [] };
  if (headerValue) {
    try {
      fromObject(decodeBase64Json(headerValue), "header", out);
    } catch {
      out.errors.push("header:undecodable");
    }
  }
  if (bodyText) {
    try {
      fromObject(JSON.parse(bodyText), "body", out);
    } catch {
      /* body is not JSON; fine */
    }
  }
  return out;
}

export interface KnownRequirement {
  network: string;
  asset: string;
  payTo: string;
}

export interface CompareResult {
  status: "match" | "mismatch" | "unknown" | "no_requirements";
  /** requirements whose (network, asset) matched a known one but payTo differs */
  payToMismatch: PaymentRequirement[];
  /** requirements whose (network, asset) has no reference claim */
  unknown: PaymentRequirement[];
}

/**
 * Compare live 402 requirements against what a directory (Bazaar / ard.json / signed listing) claims.
 * A match means EVERY live (network, asset, payTo) has a reference claim; an empty
 * reference or any unknown network/asset cannot match. Address conflicts take priority.
 * This compares recipient claims only, not amounts, schemes, approval or payment safety.
 */
export function compareRequirements(live: PaymentRequirement[], known: KnownRequirement[]): CompareResult {
  if (live.length === 0) return { status: "no_requirements", payToMismatch: [], unknown: [] };
  const key = (n: string, a: string) => JSON.stringify([n, normAddr(a)]);
  const knownBy = new Map<string, Set<string>>();
  for (const k of known) {
    const s = knownBy.get(key(k.network, k.asset)) ?? new Set<string>();
    s.add(normAddr(k.payTo));
    knownBy.set(key(k.network, k.asset), s);
  }
  const payToMismatch: PaymentRequirement[] = [];
  const unknown: PaymentRequirement[] = [];
  for (const r of live) {
    const s = knownBy.get(key(r.network, r.asset));
    if (!s) unknown.push(r);
    else if (!s.has(normAddr(r.payTo))) payToMismatch.push(r);
  }
  return { status: payToMismatch.length ? "mismatch" : unknown.length ? "unknown" : "match", payToMismatch, unknown };
}
