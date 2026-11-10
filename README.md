# agent_search

Open components for finding automatic agent services and connecting to their providers. Direct, non-custodial payment is a later goal, not a feature of this communication preview.

**Status: local synthetic-data preview, not a production release.** There is no public index, relay endpoint, or released package. The `a2n` namespace and `net.example` domain are placeholders.

## What is here

| Path | What |
| --- | --- |
| [`skills/agent-search/SKILL.md`](skills/agent-search/SKILL.md) | Tier-1 instructions for an agent's existing HTTP tools: search, call a local demo provider, and retrieve offline inquiry replies. No consumer daemon, wallet, or payment support |
| [`packages/provider`](packages/provider) | Preview provider connector: an outbound WebSocket connection, exact method/path allowlist, fixed loopback HTTP upstream, and heartbeats. See its [configuration and limitations](packages/provider/README.md) |
| [`packages/protocol`](packages/protocol) | ARD listing helpers, experimental detached-signature and sealed-box helpers, x402 response parsing, pinned asset decimals, and reason-code rendering. These helpers are not a payment authorizer or a complete client security boundary |
| [`spec/listing-format.md`](spec/listing-format.md) | Proposed provider listing format: an [ARD](https://github.com/ards-project/ard-spec) entry plus `a2n:` terms. Some fields describe future features |
| [`spec/examples`](spec/examples) | Fictitious listing examples, not proof that every illustrated feature is implemented |
| [`policy/seeds.json`](policy/seeds.json) | Public, revocable seed configuration for a future credit graph. This package does not implement a transparency-log client or enforce logging of seed changes |
| [`policy/platforms.json`](policy/platforms.json) | Public platform-policy configuration. A client must separately implement enforcement; publishing the configuration does not enforce it |

The bootstrap relay/index and its internal operations are maintained separately. Starting the provider requires an operator-supplied relay and local upstream; this repository alone is not a hosted service.

## Two installation tiers and their limits

- **Tier 1 — skill only:** the agent uses its existing HTTP tools. The intended remote transport is HTTPS; the local preview uses loopback HTTP/WS. The relay can read request and response bodies during processing. There is **no end-to-end encryption, enforced local spending limit, or automatic payment**. The skill instructs the agent not to send sensitive data, follow outside instructions, or automatically open files. These are behavioral instructions, not an OS sandbox or guaranteed injection prevention.
- **Tier 2 — skill plus a local consumer script:** intended to add end-to-end encryption, local data-handling controls, and spending-policy enforcement. **This consumer path is not implemented.**
- **Providers:** run the preview connector beside a fixed local HTTP service. It enforces its method/path allowlist, strips untrusted request headers, and injects any configured local upstream credential. It does not make an unsafe upstream safe and is not a production isolation sandbox.

The current sealed-box helper is an experimental X25519/HKDF/AES-GCM construction, **not RFC 9180 HPKE**. Having cryptographic helpers in a repository does not establish end-to-end encryption in a deployed path. Known signature-canonicalization and payment-comparison issues remain under review; do not use these helpers to authorize payments or authenticate untrusted production listings.

## Design goals

- Reuse ARD for discovery and A2A / MCP / HTTP for task calls; use established payment standards when that phase is implemented. The experimental relay framing/encryption is not a standardized interoperability protocol.
- Connect directly where possible; describe relay visibility accurately rather than promising metadata-only handling for every tier.
- Do not hold funds, guarantee delivery quality, handle refunds, or adjudicate disputes.
- Treat external content as untrusted. Delimiters and model instructions do not eliminate prompt injection or enforce local policy.
- Keep semantic relevance separate from risk and future credit evidence. Configuration entries and signatures are not endorsements.
- Do not sell ranking. Detection rules, anti-fraud parameters, server operations, and named third-party review records are outside this repository.

## Develop

Node 24+, pnpm:

```bash
pnpm install
pnpm typecheck
pnpm test
```

## License

The repository currently includes [Apache-2.0](LICENSE); the final license choice is pending project-owner confirmation.
