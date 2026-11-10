# Provider connector — local communication preview

Requires Node 24+, installed workspace dependencies, a local HTTP upstream, and an operator-configured relay. It is not a standalone public service. Test with synthetic inputs only; there is no payment implementation.

## Start

```bash
node packages/provider/src/provider.ts /path/to/local/provider-config.json
```

The configuration and both secret files must be regular files owned by the process user with permissions `0600`. Do not commit them. Runtime examples below contain paths and placeholders only, not working credentials.

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
- `identityFile`: JSON containing base64url `privateKey` (Ed25519) and `xPrivateKey` (X25519), generated locally. Provision only the corresponding public keys to the relay; never send private keys.
- `relay`: `wss:` outside loopback; `ws:` is accepted only at `127.0.0.1` for local testing.
- `upstream`: exactly one `http://127.0.0.1:<port>` origin. No user-info, non-root path, query, or fragment. Bind the upstream to loopback too.
- `upstreamTokenFile`: optional, contains a local bearer token. The connector removes incoming auth/cookie/forwarding headers and supplies this token only to the fixed upstream.
- `routes`: exact `GET` or `POST` paths. Query parameters, traversal, escaped separators, arbitrary target URLs and redirects are not supported.
- `maxBytes`: request and response cap. Configure it no larger than the upstream's supported limit.
- `timeoutMs`: absolute HTTP transport deadline. Timeout is not proof the upstream did not execute the task.
- `heartbeatMs`: one heartbeat timer per authenticated socket session, cancelled when it ends.

The preview writes lifecycle codes only to stderr, not request bodies, local tokens, or pickup credentials. Run as an unprivileged user. An OS service installer and production sandbox are not supplied here.

## Disconnect, cancellation and replay

Each connection owns its socket, heartbeat, busy flag and in-flight HTTP controller. Closing or stopping it aborts its local HTTP transport and discards late results; an old callback cannot send on a new socket. A duplicate `ready` frame does not create another heartbeat.

**Aborting local transport is not rollback.** The upstream may have completed or partially completed a side effect before the connection failed. Reconnection does not automatically retry calls. Ask the user/operator before resubmitting an uncertain task.

For one connector-process lifetime, already-attempted call IDs are remembered. Redispatching an attempted ID returns `409 call_already_attempted_outcome_not_retried`, not a cached success and not another upstream call. The bounded set holds at most 4096 call IDs; after that, new calls fail closed with `503 call_replay_guard_capacity`. Restart loses this set; this is **not durable deduplication or exactly-once execution**. Production recovery requires an explicit persisted idempotency/result-resume design before automatic retry can be offered.

An offline `message` has different semantics: the preview returns a fixed acknowledgement and executes no message instructions or file task. Re-delivery of such an acknowledgement is not a generic job-retry mechanism.

## Scope of assurance

Exact routes, a fixed upstream and header filtering reduce open-proxy risks; they do not validate business inputs or prevent the local service itself from fetching arbitrary URLs. Returned content remains untrusted. The preview's sealed-message helper is experimental, not RFC HPKE; tier-1 communication is not end-to-end encrypted. Independent review and production controls remain necessary.
