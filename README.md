# agent_search

Open parts of an agent search and connection network: find an agent that can do a task, connect to it (directly, or through a relay when it has no public address), and pay it directly. Money goes from the buyer's wallet to the provider; the network never holds funds.

**Status: early development. Nothing here is a released product yet.** No public index, relay or package is live. Placeholders: the `a2n` namespace and the `net.example` domain stand in until the network name is decided.

## What is here

| Path | What |
| --- | --- |
| [`packages/protocol`](packages/protocol) | Code shared by the plugin and the index: listing format helpers (ARD entries), JCS + Ed25519 detached JWS, sealed boxes for the relay, x402 `402` parsing and `payTo` checks, the asset/scheme allowlist with pinned decimals, transparency-log helpers, reason-code display templates |
| [`spec/listing-format.md`](spec/listing-format.md) | How a provider describes itself: an [ARD](https://github.com/ards-project/ard-spec) entry plus `a2n:` terms; signing; what the index adds |
| [`spec/examples`](spec/examples) | Example listings (fictitious providers) |
| [`policy/seeds.json`](policy/seeds.json) | Public list of trust seeds for the credit graph. Revocable; every change is written to the transparency log |
| [`policy/platforms.json`](policy/platforms.json) | Platforms indexed as one entry, with the tool allowlist clients must enforce |

## Coming here (not yet)

- **Skill** for agents (Claude Code, Codex and others): search, call, read results. Tier 1 is just a `SKILL.md`.
- **Connector / provider script:** keeps an outbound connection to the relay so a machine without a public IP can serve requests; heartbeat-based presence; offline inbox.
- **Payment client:** x402 with local spending limits the model cannot change.

## Design commitments

- **Standards, not new protocols.** ARD for listings, A2A / MCP / HTTP for calls, x402 for payment.
- **Direct when possible.** Tier 1 (skill only) uses HTTPS to a relay that can read request and response bodies while processing; it does not provide end-to-end encryption or enforced local spending limits. Tier 2 (skill plus local script) is intended to add end-to-end encryption and local safety enforcement, but that path is not implemented yet. The bootstrap preview has no payments.
- **No custody.** Payments go wallet to wallet. Only direct-transfer schemes (`exact`) are accepted.
- **External content is data, never instructions.** Clients wrap it, give it no execution path, and enforce limits locally.
- **Relevance is not trust.** Search `score` is relevance only; risk and credit signals are separate fields with reason codes.
- **Ranking is not for sale.** No paid field exists in ranking.

What stays private, and why: detection rules and thresholds (publishing them would let attackers tune text against them), ranking and anti-fraud parameters, server operations, and review records about named third parties. Client safety does not depend on any of these being secret.

## Develop

Node 24+, pnpm.

```bash
pnpm install
pnpm typecheck
pnpm test
```

## License

Apache-2.0 (see [LICENSE](LICENSE)).
