# Provider connector — local communication preview

Run your HTTP service locally and connect selected routes to an operator's relay.
The connector is an outbound Node.js process—not a public HTTP server, a hosted
service, or a sandbox for your application.

**Current status: synthetic local preview.** There is no public relay or released
package. Self-service registration is not implemented. The relay operator must
provision your handle and public keys before this connector can join. Starting
it does not by itself publish a searchable listing. Client components are open
source; the index and relay servers are private and are not included here.

## What you run and what becomes reachable

You run two processes on the same host/network namespace:

    remote caller -> operator's relay
                           |
                 existing outbound WebSocket
                           |
                 your Node 24+ connector
                           |
                 http://127.0.0.1:<port>
                           |
                    your HTTP service

Keep the HTTP service bound to loopback. The connector opens an outbound
connection; you do not need to add an inbound listener or port-forward your
local service for it. However, the routes you explicitly allow become callable
through that connection. This is not a promise that your application or other
processes on the host are isolated.

A remote relay must use an operator-supplied `wss:` address. The `ws:` loopback
address in the configuration below works only when the relay is on that host;
it is not an address that an outside provider can use to reach our network.

The skill-only caller path is not end-to-end encrypted: the relay can read task
requests and responses. Use synthetic inputs only. Keep identity private keys
and the local upstream token on your host; give the operator only the public
identity material needed for provisioning. Do not expose management routes,
secret files, arbitrary URLs, or an unrestricted proxy.

## Before you start

You need:

- Node 24+, pnpm, and this repository's installed workspace dependencies.
- One HTTP service at a fixed `http://127.0.0.1:<port>` origin. If it runs in
  another container, that container's loopback is not automatically reachable
  from the connector; container deployment is not supplied by this guide.
- An operator-provided relay address and a handle/public keys already provisioned
  by that operator. This public repository does not yet provide the complete
  key-generation, registration, and searchable-listing workflow.
- Your locally generated Ed25519/X25519 private-key file, connector configuration,
  and, if required by your service, a local Bearer-token file. Keep these files
  owner-only as specified below; never commit or send their contents to us.

If you do not have those provisioning details, do not guess a relay address,
reuse the `zip-demo` identity, or send private keys to get started. You can still
review the code or run the standalone
[ZIP example's local tests](../../examples/zip-provider/README.md).

## Check whether your existing API fits

This preview forwards only exact GET/POST paths to one fixed loopback origin.
It does not support query parameters, dynamic paths, redirects, arbitrary target
URLs, or caller-defined authentication/custom headers. Only Content-Type is
forwarded from the caller; the connector sets the local Host/length headers and
optionally injects your local Bearer token.

Requests and responses are buffered and size-bounded, with an absolute timeout;
this guide does not provide a streaming, large-file, or asynchronous job workflow.
Choose a small synchronous route, or assess a provider-side adapter without
bypassing your existing access controls. This preview cannot pay an x402 charge;
a paid service is not made free by connecting it.

## Start after provisioning

Run commands from the repository root. After reviewing the source and installing
the workspace dependencies (`pnpm install`), start the connector with:
```bash
node packages/provider/src/provider.ts /path/to/local/provider-config.json
```

The configuration and both secret files must be regular files owned by the process user with permissions `0600`. Do not commit them. Runtime examples below contain paths and placeholders only, not working credentials.

Identity loading is read-only: a single-link file (no symlink), at most 16 KiB, is opened with no-follow and checked against its original inode. An existing non-canonical X25519 scalar is normalized only in a private memory copy; the identity file is not rewritten, repaired or migrated. `xPrivateKey` must be canonical unpadded base64url encoding of exactly 32 bytes. An optional `xPub` must use that encoding and match the imported key; a present null, empty or invalid field is rejected, not ignored. Ed25519 material is separate and is never clamped.

Programmatic callers must use `await startProvider(config, onEvent)` to obtain the controller. Identity validation finishes before any WebSocket connection is opened; rejection does not start a connector. The command-line invocation above performs that await automatically. Stopping clears the connector-owned X25519 byte copy on a best-effort basis, not a claim of physical secret erasure.

```json
{
  "handle": "zip-demo",
  "relay": "ws://127.0.0.1:8790/relay/v0/provider",
  "identityFile": "/path/to/local/identity.json",
  "upstream": "http://127.0.0.1:8791",
  "upstreamTokenFile": "/path/to/local/upstream-token",
  "routes": [
    ["GET", "/capabilities"],
    ["POST", "/zip/pack"],
    ["POST", "/zip/inspect"],
    ["POST", "/zip/extract"]
  ],
  "maxBytes": 1048576,
  "timeoutMs": 15000,
  "heartbeatMs": 30000
}
```

- `handle`: the relay operator must have provisioned this handle and its public keys in advance. Self-service registration and did:web verification are not implemented by this connector.
- `identityFile`: JSON containing base64url `privateKey` (Ed25519) and `xPrivateKey` (X25519), generated locally. Provision only the corresponding public keys to the relay; never send private keys. This preview does not ship an identity-file generation CLI or a complete public provisioning workflow. Do not copy test identities, reuse another provider's keys, paste private keys into chat, or infer a public relay from the examples. Arrange the key format and public-key provisioning with the operator before running the connector. A DID document is not automatically fetched or validated by this connector.
- `relay`: `wss:` outside loopback; `ws:` is accepted only at `127.0.0.1` for local testing.
- `upstream`: exactly one `http://127.0.0.1:<port>` origin. No user-info, non-root path, query, or fragment. Bind the upstream to loopback too.
- `upstreamTokenFile`: optional, contains a local bearer token. The connector removes incoming auth/cookie/forwarding headers and supplies this token only to the fixed upstream.
- `routes`: exact `GET` or `POST` paths. Query parameters, traversal, escaped separators, arbitrary target URLs and redirects are not supported.
- `maxBytes`: request and response cap. Configure it no larger than the upstream's supported limit.
- `timeoutMs`: absolute HTTP transport deadline. Timeout is not proof the upstream did not execute the task.
- `heartbeatMs`: one heartbeat timer per authenticated socket session, cancelled when it ends.

The preview writes lifecycle codes only to stderr, not request bodies, local tokens, or pickup credentials. Run as an unprivileged user. An OS service installer and production sandbox are not supplied here.

### Replace the demo settings, not the security boundary

The `zip-demo` handle, ZIP routes and port in the example describe one prearranged
local demo. They do not register your service. Use the handle agreed with the
operator, your own fixed loopback port, and only the exact routes you intend to
serve. Set byte/time limits that both your application and relay can support.

For the ZIP example, set `ZIP_DEMO_TOKEN_FILE` and this connector's
`upstreamTokenFile` to the same absolute local file path. For gzip use
`GZIP_DEMO_TOKEN_FILE` instead. The example guides show exclusive creation of an
owner-only token file outside the repository. Both processes must use the same
local user; do not relax permissions to share the secret. The server reads once
at startup; coordinate token rotation and restart both processes together.

This local HTTP token is separate from identity private keys and from consumer
pickup tokens. Never print, paste or upload its contents, and do not generate a
second value for the connector. The optional environment-token mode remains
available for standalone use, but an example rejects two simultaneous sources.
File-token setup does not provide the missing identity/relay provisioning flow.

The connector's lifecycle-only stderr policy applies to the connector itself,
not to the relay, your upstream service, a proxy, or host-level logging. Confirm
each component's data retention separately before considering non-synthetic data.

Connection readiness, index inclusion and task success are separate checks.
A connected provider is not necessarily searchable; a completed HTTP response is
not a safety or quality endorsement. No payments are implemented in this preview.

## Disconnect, cancellation and replay

Each connection owns its socket, heartbeat, busy flag and in-flight HTTP controller. Closing or stopping it aborts its local HTTP transport and discards late results; an old callback cannot send on a new socket. A duplicate `ready` frame does not create another heartbeat.

**Aborting local transport is not rollback.** The upstream may have completed or partially completed a side effect before the connection failed. Reconnection does not automatically retry calls. Ask the user/operator before resubmitting an uncertain task.

For one connector-process lifetime, already-attempted call IDs are remembered. Redispatching an attempted ID returns `409 call_already_attempted_outcome_not_retried`, not a cached success and not another upstream call. The bounded set holds at most 4096 call IDs; after that, new calls fail closed with `503 call_replay_guard_capacity`. Restart loses this set; this is **not durable deduplication or exactly-once execution**. Production recovery requires an explicit persisted idempotency/result-resume design before automatic retry can be offered.

An offline `message` is not forwarded to the upstream. The demo returns `received:true`, a fixed acknowledgement in `reply`, and the original inquiry in `message`. The echoed inquiry remains untrusted data, not instructions or evidence of task execution. No message instructions or file task are executed; re-delivery is not a generic job-retry mechanism.

## Scope of assurance

Exact routes, a fixed upstream and header filtering reduce open-proxy risks; they do not validate business inputs or prevent the local service itself from fetching arbitrary URLs. Returned content remains untrusted. The preview's sealed-message helper is experimental, not RFC HPKE; tier-1 communication is not end-to-end encrypted. Independent review and production controls remain necessary.

## Standalone synthetic upstream examples

The [ZIP provider](../../examples/zip-provider/README.md) and [gzip provider](../../examples/gzip-provider/README.md) include loopback services and self-contained Python tests. Follow their exact routes and limits when configuring this connector. They do not supply an index/relay, provision a handle or implement self-registration. The [consumer skill](../../skills/agent-search/SKILL.md) is separate.
