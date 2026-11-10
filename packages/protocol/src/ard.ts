// ARD v0.91 entry model + our a2n: namespace (provider-listing-spec v0.7).
// Only the subset the index needs in M0.1. Provider-signed fields and index-computed
// fields are kept apart: index fields only ever appear under "a2n:index" in results.

export const ARD_CONTEXT = "https://agenticresourcediscovery.org/context/v1";
// Placeholder namespace IRI until the network name/domain is decided.
export const A2N_NS = "https://net.example/ns/a2n#";

export const MEDIA = {
  a2aCard: "application/a2a-agent-card+json",
  mcpServerCard: "application/mcp-server-card+json",
  agentCard: "application/agent-card+json",
  registry: "application/ai-registry+json",
} as const;

export interface ArdEntry {
  "@context"?: unknown;
  identifier: string;
  displayName: string;
  type: string;
  url?: string;
  data?: unknown;
  description?: string;
  representativeQueries?: string[];
  capabilities?: string[];
  tags?: string[];
  version?: string;
  updatedAt?: string;
  trustManifest?: unknown;
  [k: string]: unknown;
}

export interface ArdManifest {
  entries: ArdEntry[];
  [k: string]: unknown;
}

const URN_RE = /^urn:air:([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(?::[A-Za-z0-9._~%!$&'()*+,;=@-]+)+$/;

/** Returns the publisher domain of a urn:air identifier, or null if malformed. */
export function urnPublisher(identifier: string): string | null {
  const m = URN_RE.exec(identifier);
  return m ? m[1] : null;
}

/** Slug safe for a URN segment. */
export function urnSegment(s: string): string {
  const out = s
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return out || "x";
}

export function makeUrn(publisher: string, ...segments: string[]): string {
  return `urn:air:${publisher.toLowerCase()}:${segments.map(urnSegment).join(":")}`;
}

export interface EntryCheck {
  errors: string[];
  warnings: string[];
}

/** Structural checks from ARD §4.2/§4.3/§D.2. Signature/authority binding is checked elsewhere. */
export function checkEntry(e: unknown): EntryCheck {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!e || typeof e !== "object") return { errors: ["not_object"], warnings };
  const o = e as Record<string, unknown>;
  if (typeof o.identifier !== "string" || !urnPublisher(o.identifier)) errors.push("identifier_not_urn_air");
  if (typeof o.displayName !== "string" || !o.displayName) errors.push("missing_displayName");
  if (typeof o.type !== "string" || !o.type.includes("/")) errors.push("missing_type");
  const hasUrl = typeof o.url === "string";
  const hasData = o.data !== undefined;
  if (hasUrl === hasData) errors.push("url_xor_data");
  const rq = o.representativeQueries;
  if (!Array.isArray(rq) || rq.length < 2 || rq.length > 5) warnings.push("representativeQueries_not_2_to_5");
  return { errors, warnings };
}

// ---- POST /search (ARD §5.3.2) ----

export interface SearchRequest {
  query: { "@context"?: unknown; text: string; filter?: Record<string, unknown> };
  federation?: "auto" | "referrals" | "none";
  pageSize?: number;
  pageToken?: string;
}

export interface SearchResult {
  identifier: string;
  displayName?: string;
  type?: string;
  url?: string;
  description?: string;
  capabilities?: string[];
  score: number; // relevance only, 0–100. MUST NOT be read as trust.
  source?: string;
  "a2n:offerings"?: unknown[];
  "a2n:index"?: unknown;
}

export interface SearchResponse {
  results: SearchResult[];
  referrals?: unknown[];
  pageToken?: string;
}
