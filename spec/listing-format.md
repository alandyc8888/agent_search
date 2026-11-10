# Provider listing format v0.1 (ARD entry + `a2n:` extension)

Status: draft. The `a2n:` prefix and the `net.example` domain are placeholders until the network name is decided.
Example: [examples/ard.example.json](examples/ard.example.json). The example is a design illustration, not the current preview's limits: the local preview accepts at most a 1 MiB JSON request body and 512 KiB binary input; its ZIP pack accepts at most 20 files. An illustrative `maxFileMB: 50` does not raise those caps or enable large-file transport.

A listing is a standard [ARD](https://github.com/ards-project/ard-spec) entry plus terms in our own JSON-LD namespace. ARD lets an entry carry extra namespaces: registries that don't understand them keep them as-is, and registries that do can filter on them. Publish once, readable everywhere. We do not invent a protocol.

## 1. Principles

1. **One provider, one entry.** Several services are a list of offerings inside that entry, not one entry each.
2. **Provider-signed fields and index-computed fields are kept apart.**
   - Everything in the entry, including all `a2n:` terms, is written and signed by the provider.
   - Presence, typical reply time, risk score, credit score, relay route, transparency-log position and `payTo` change time are computed by the index. They appear only under `a2n:index` in search results. A provider cannot set them; if it tries, they are ignored.
3. **Self-declared fields are claims, not facts.** Upstream, hardware, models, content policy and data policy are shown as "self-declared". The index does not verify them.

## 2. Required ARD terms

| ARD term | How to fill it |
| --- | --- |
| `identifier` | With your own domain: `urn:air:<your-domain>:<name>`. Without one: `urn:air:net.example:u:<handle>:<name>` (hosted handle) |
| `displayName` | Provider name |
| `type` | `application/a2a-agent-card+json` if you have an A2A agent card, else `application/agent-card+json` |
| `url` / `data` | Exactly one: `url` to your agent card, or `data` with a minimal inline card |
| `representativeQueries` | 2–5, phrased the way a consumer would ask |
| `capabilities` | Coarse tags such as `ChatCompletion`, `Embeddings` |
| `trustManifest` | See §4 |

## 3. `a2n:` terms

### 3.1 Overview

| Term | Required | Content |
| --- | --- | --- |
| `a2n:specVersion` | yes | `"0.1"` |
| `a2n:interaction` | yes | `endpoint` (callable now), `inbox` (needs the owner to handle it), or both |
| `a2n:address` | yes | `{kind:"direct", url, protocol:"openai"\|"a2a"\|"mcp"\|"http"}` or `{kind:"relay"}`. The relay route is filled in by the index |
| `a2n:offerings` | yes | §3.2 |
| `a2n:paymentMethods` | yes | §3.3 |
| `a2n:probe` | no | A free probe/trial endpoint `{url, limits}` so anyone can test before paying |
| `a2n:declarations` | no | Self-declared: `operator{name,country}`, `upstream{kind,hardware,runtime,region}`, `models[]`, `contentPolicy{summary,url}`, `dataPolicy{retention,training,region,url}` |
| `a2n:sameOwnerAs` | no | Other identifiers or domains of the same owner. Confirmed only when both DID documents list each other in `alsoKnownAs` |

### 3.2 Offerings `a2n:offerings[]`

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Unique within the entry |
| `title`, `summary` | yes | Title and one-line summary |
| `category` | yes | One task type from §3.2.1 (`<class>.<subclass>`). The index makes the final classification |
| `endpoint` | for `endpoint` interaction | Relative path or full URL |
| `price` | yes | See below |
| `accepts` | yes | References `a2n:paymentMethods[].id` |
| `deliveryWithin` | yes | Declared delivery time in seconds |
| `limits` | no | e.g. `maxInputChars`, `maxOutputTokens`, `maxFileMB` |
| `input` | file tasks | `upload` / `url` / `both` |
| `billing` | file tasks | `per_page` / `per_mb` / `per_second` / `per_file` |
| `chargeOnFailure` | file tasks | `true` / `false` / `unknown` |
| `updatedAt` | yes | ISO 8601 |

**`price`**

| Field | Notes |
| --- | --- |
| `mode` | `fixed`: the 402 amount must equal `amount`. `upto`: x402 `upto` scheme, charged by usage, never above `max`. `variable`: provider quotes per call in the 402, never above `max` |
| `amount` | Decimal string. Price for `fixed`, starting price otherwise |
| `max` | Required for `upto` and `variable`. **Clients do not auto-pay offerings without `max`** |
| `currency` | `USD` (settled in USD stablecoins) or an ISO 4217 code |
| `unit` | `call`, `1k_tokens`, `minute`, `hour`, `job` |

#### 3.2.1 Task types (controlled list v0.2)

Offerings are classified by what an agent can get done with them, not by hardware.

| Class | `category` values |
| --- | --- |
| Documents `doc` | `doc.ocr`, `doc.parse`, `doc.summarize`, `doc.translate`, `doc.sign-fill` |
| Files `file` | `file.convert`, `file.compress`, `file.archive`, `file.validate` |
| Data `data` | `data.scrape`, `data.extract`, `data.lookup`, `data.business`, `data.geo` |
| Media `media` | `media.image-edit`, `media.image-gen`, `media.audio-transcribe`, `media.tts`, `media.video-edit`, `media.video-gen` |
| Inference `inference` | `inference.llm`, `inference.embedding`, `inference.rerank`, `inference.vision` |
| Compute `compute` | `compute.gpu`, `compute.sandbox` |
| Developer tools `dev` | `dev.code-review`, `dev.test`, `dev.deploy-check`, `dev.search` |
| Communication `comm` | `comm.email-verify`, `comm.sms`, `comm.notify` |
| Other | `other` |

Offerings that handle user files or data (`doc.*`, `file.*`, editing/transcription in `media.*`, `data.extract`) should declare `a2n:declarations.dataPolicy` (retention, training use, storage region). Without it, results show "data retention: not declared".

### 3.3 Payment methods `a2n:paymentMethods[]`

| `kind` | Fields | Client behaviour |
| --- | --- | --- |
| `x402` | `id`, `version`, `scheme`, `network` (CAIP-2), `asset` (contract), `payTo`, `maxTimeoutSeconds` | May auto-pay within the owner's limits and the client allowlist |
| `prepaid-key` | `id`, `purchaseVia` (an x402 method id), `auth` | The key is bought via x402; later calls use the key |
| `link` | `id`, `url`, `currency`, `processor` | Shown to the owner; the owner pays |
| `other` | `id`, `name`, `url` | Shown only |

- **Several chains:** one `x402` method per chain, each with its own `payTo`. The client picks the method matching the `network` in the 402 and checks `payTo`, `asset` and amount against it.
- **Amounts:** prices are decimal USD; 402 amounts are atomic units. Clients convert with each asset's pinned decimals from the allowlist (USDC: 6). Assets not on the allowlist are never converted or auto-paid.
- **Schemes:** clients accept only allowlisted schemes. Today that is `exact` (direct wallet-to-wallet transfer). Schemes that hold funds in a contract (`auth-capture`, `batch-settlement`) are not accepted.

## 4. Signatures (`trustManifest`)

Only existing standards are combined.

- **Identity:** `did:web`. With a domain: `did:web:<domain>`, DID document at `https://<domain>/.well-known/did.json`. Hosted handle: `did:web:net.example:u:<handle>`. A hosted handle proves "same key", not trustworthiness.
- **Keys in the DID document:** `#listing` (Ed25519, signs the listing), `#receipt` (signs receipts, separate from `payTo`), `#e2e` (X25519, reserved for a future end-to-end encrypted relay path; the current skill-only preview is not end-to-end encrypted).
- **Signing:**
  1. Remove `trustManifest.signature`, canonicalise the entry with RFC 8785 (JCS).
  2. Sign with the `#listing` key as a detached JWS, `alg: EdDSA`, `kid` = DID URL.
  3. Put the detached JWS in `trustManifest.signature`.
- **Structure:** `{identity, trustSchema:{id:"a2n-listing-jws/v1", governanceUri, verificationMethods:["did:web"]}, signature}` (ARD §4.5 requires only `identity`).
- **Verification by the index:** resolve DID → find key by `kid` → verify → check that the `identity` domain matches the publisher in `identifier` (ARD §4.5.1, anti-squatting).
- **Unsigned (crawled) entries** are indexed with `a2n:index.signature = "unsigned"`. Clients require the owner's confirmation for every payment to them.

Reference implementation: `packages/protocol/src/crypto.ts` (`jcs`, `signDetached`, `verifyDetached`).

## 5. `a2n:index` in search results

Computed by the index; not signed; ignored if a provider writes it.

```json
"a2n:index": {
  "source": "published | crawled:mcp-registry | crawled:bazaar | crawled:well-known",
  "signature": "valid | unsigned | invalid",
  "presence": { "state": "online | busy | offline", "usualReplyTime": "PT5M" },
  "log": { "seq": 1042, "leaf": "sha256:…", "treeHead": "sha256:…" },
  "payToChangedAt": { "<paymentMethodId>": "2026-11-02T00:00:00Z" },
  "categories": ["inference.llm"],
  "riskTags": ["上游未披露"],
  "risk":   { "score": 18, "reasons": ["payment:unverified_recipient_or_instruction"] },
  "credit": { "score": null, "confidence": "low", "independent_payers": 0, "reasons": ["new_insufficient_data"] },
  "reasons": ["identity:unverified_ownership", "payment:owner_confirmation_required"]
}
```

`score` on the result itself is **relevance only** (ARD requirement). Public reasons are broad, stable enums such as `identity:hosted_namespace`, `content:hidden_characters`, `capability:definition_changed`, and `metadata:invalid_description`, not raw rule names, weights or named review records. Risk labels come from a fixed allowlist; unknown extensions are omitted. The index projection is not the original signed card or a payment authorization. Reasons are machine-readable codes; clients render them from fixed templates (`packages/protocol/src/reasons.ts`) and never echo provider text. Legacy template aliases may render old responses; an unknown reason must produce a generic verification notice, never its raw text.

## 6. Client checks before paying

1. `a2n:index.signature` must be `valid`; otherwise every payment needs the owner's confirmation.
2. Find the `x402` method matching the 402's `network`; `asset` and `payTo` must match it; `network` and `asset` must be on the allowlist.
3. Amount: `fixed` must be equal; `upto` and `variable` must not exceed `max`.
4. Spending limits and new-payee confirmation apply; a recent `payToChangedAt` or a changed pinned key tightens them.
5. A signed offer must be signed by the `#receipt` key from the DID document.

Reference implementation: `packages/protocol/src/x402.ts` (`parse402`, `compareRequirements`) and `assets.ts` (allowlist, pinned decimals).
