# Loopback ZIP example provider

A standalone Python HTTP service for learning and synthetic local tests. It can
pack files into a ZIP, inspect archive metadata, or return selected file bytes.
Packing uses STORE only: it does not compress files to make them smaller.
Inspection does not decompress entries or verify their CRCs.

**This is the local application, not the network connector.** To use a relay you
would also run the separate Node 24+
[provider connector](../../packages/provider/README.md) and obtain provisioning
from a relay operator. Running this example does not register a provider or make
it searchable. A consumer skill is a separate component too.

## What runs locally—and what does not open publicly

- This example requires Python 3.12 on Linux and uses the standard library. An
  existing HTTP service does not need Python merely to use the Node connector.
- The server binds only to `127.0.0.1`, on port `8791` by default. Changing
  `ZIP_DEMO_PORT` changes the port, not the bind address.
- Keep it on loopback. Do not add a public listener, tunnel, or port-forward, and
  do not expose it to untrusted public uploads. In a future configured relay
  setup, allowed routes would be reachable through the outbound connector;
  loopback binding does not itself authorize remote tasks or isolate the host.
- There is no payment, wallet, billing, external API or remote-URL fetching here.
  These local tests do not establish end-to-end integration or production safety.

## Start with the self-contained tests

From this directory, run:

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_server.py

The tests start their own loopback server on an ephemeral port, generate their
own temporary token and synthetic archives, and shut down that server. You do
not need a relay, a connector, a registered identity, or a manually started server
for these tests. This does not prove the whole network works.

For a manual standalone demonstration, continue below. The server and any local
caller must use the same local HTTP token; do not print it, commit it, paste it
into a chat, or send it to a relay operator. A new terminal does not automatically
inherit a token exported in another terminal.

**Not a production sandbox.** Worker limits are not OS isolation. Retain the
limits and deployment warnings below; do not automatically open returned files.
The relay-readable caller path is not end-to-end encrypted.

## Manual standalone start

Use **Python 3.12 on Linux**, with the standard library. Worker limits use Unix `resource` facilities; other platforms are not supported by this example.

From this directory:

```bash
# Private directory outside the repository; never print or commit the capability.
umask 077
export ZIP_DEMO_TOKEN_FILE="$(python3 -c 'import os; print(os.path.join(os.path.expanduser("~"), ".agent-search-example", "zip-token"))')"
unset ZIP_DEMO_TOKEN
python3 - <<'PY'
import os
import secrets
from pathlib import Path
path = Path(os.environ['ZIP_DEMO_TOKEN_FILE'])
path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
if path.parent.is_symlink() or path.parent.stat().st_uid != os.getuid() or path.parent.stat().st_mode & 0o077:
    raise SystemExit('use an owner-only private directory')
# Exclusive create: never silently overwrite/rotate an existing token file.
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w', encoding='ascii') as stream:
    stream.write(secrets.token_urlsafe(32) + '\n')
PY
python3 server.py
```

The server binds only to `127.0.0.1`, using port `8791` by default. `ZIP_DEMO_PORT` can change the port, not the bind address. Stop it with Ctrl-C. To make a request, use a separate terminal or process with the **same securely shared token file path or environment source**; do not generate a different token there.

### Share the same local capability with the connector

Set the connector's `upstreamTokenFile` to the **same absolute file path** as `ZIP_DEMO_TOKEN_FILE`. Only the path belongs in the private connector configuration; do not put token contents in cards, relay requests, URLs, logs, command arguments or Git. The file must be readable by both processes under the same user in this local preview. Do not relax permissions to share it across different users; use a separately reviewed deployment identity/mount arrangement instead.

The server opens the file once at startup and requires a single-link ordinary file owned by its user with mode exactly `0600`, no final symlink, and at most 257 bytes (32–256 URL-safe ASCII token characters plus one optional final LF). Spaces, CRLF, extra lines and non-ASCII are rejected. Keep every parent directory private and free of symlinked/untrusted components: final-component `O_NOFOLLOW` is **not** a full path-traversal or same-user-attacker defense. Token entropy is the operator's responsibility.

The old environment-only source still works: unset `ZIP_DEMO_TOKEN_FILE` and generate `ZIP_DEMO_TOKEN` with `secrets.token_urlsafe(32)`. **Exactly one source must be present**; both set (even if one is empty), neither set, a missing/invalid file or invalid content rejects startup, with no fallback. Both sources now require URL-safe ASCII characters and a 32–256 character length; old arbitrary long/space/Unicode tokens are not supported. There is no automatic hot reload. Coordinate rotation and restart the service/connector together; editing the shared file alone can make them disagree. Environment mode remains a separate option, not a reason to copy secrets through shell history.

## HTTP interface

| Method and path | JSON input | Successful `result` |
|---|---|---|
| `GET /capabilities` | None; no authorization required | Limits and capabilities at top level; `production_ready: false` |
| `POST /zip/pack` | `{"files":[{"name":"docs/hello.txt","data_base64":"aGVsbG8="}]}` | `archive_base64`, `sha256`, `files` manifest |
| `POST /zip/inspect` | `{"archive_base64":"..."}` | Entries with integer `entry_id`, declared sizes and untrusted names; headers only, not decompressed or CRC checked |
| `POST /zip/extract` | `{"archive_base64":"...","entry_ids":[0]}` | Selected inline files, random `artifact_id`, `safe_name`, untrusted original name, heuristic content type, base64 data and SHA256 |

POST requests require `Content-Type: application/json`, one valid `Content-Length` and `Authorization: Bearer <local capability>`. Transfer-Encoding is rejected. POST requests with an Origin header or a Host other than `127.0.0.1:<port>` or `localhost:<port>` are rejected. This is not a browser-facing application.

Success uses `{"ok":true,"demo_only":true,"billing":"disabled","result":{...}}`, except for capabilities. Request errors use 400, invalid archives or worker failures use 422, missing authorization uses 401, and rejected Origin/Host uses 403. A declared HTTP body larger than 1 MiB returns **413 before reading the body**.

### Synthetic round trip

With the server running, run this from a process holding the same local token. It sends only the synthetic word `hello`, checks returned data and prints hashes, not capabilities or file contents. It does not save or execute returned files.

```bash
python3 - <<'PY'
import base64
import hashlib
import json
import os
import urllib.request
from server import load_token

port = int(os.environ.get('ZIP_DEMO_PORT', '8791'))
origin = f'http://127.0.0.1:{port}'

class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

http = urllib.request.build_opener(urllib.request.ProxyHandler({}), RejectRedirects())

def call(path, payload):
    request = urllib.request.Request(
        origin + path,
        data=json.dumps(payload).encode(),
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + load_token(),
        },
        method='POST',
    )
    with http.open(request, timeout=15) as response:
        encoded = response.read(1048577)
    assert len(encoded) <= 1048576
    envelope = json.loads(encoded)
    assert envelope['ok'] and envelope['demo_only']
    assert envelope['billing'] == 'disabled'
    return envelope['result']

plain = b'hello'
packed = call('/zip/pack', {'files': [
    {'name': 'docs/hello.txt', 'data_base64': base64.b64encode(plain).decode()}
]})
archive = base64.b64decode(packed['archive_base64'], validate=True)
assert hashlib.sha256(archive).hexdigest() == packed['sha256']
listing = call('/zip/inspect', {'archive_base64': packed['archive_base64']})
assert len(listing['entries']) == 1
selected = call('/zip/extract', {
    'archive_base64': packed['archive_base64'], 'entry_ids': [0]
})
result = selected['files'][0]
assert base64.b64decode(result['data_base64'], validate=True) == plain
assert result['sha256'] == hashlib.sha256(plain).hexdigest()
assert result['preview_allowed'] is False
print('roundtrip OK; archive sha256:', packed['sha256'])
PY
```

See the [provider connector guide](../../packages/provider/README.md) for configuration and current provisioning limits. This example does not register itself with a relay. The [consumer skill](../../skills/agent-search/SKILL.md) describes the separate skill-only path.

## Connector contract

A connector must use a fixed local origin, not a caller-selected URL. Allow only `GET /capabilities` and `POST /zip/pack`, `/zip/inspect`, `/zip/extract`. Reject ambiguous or encoded paths, traversal, double slashes and absolute URLs. Set Host to the fixed local authority. **Remove every caller-supplied Authorization header before injecting exactly one local Bearer header.** Keep the local capability out of public cards, skills, relay messages, URLs and logs; store connector credentials with owner-only file permissions.

Forward 413 without presenting it as a successful task. When the provider is offline, file-bearing POST requests must fail promptly rather than enter an offline message queue. Ordinary text enquiries can use a separate messaging mechanism; do not queue files or capabilities for later replay. A plain HTTP relay can read request contents: this example does not provide end-to-end encryption.

## Limits and defensive behavior

- HTTP body: 1 MiB including JSON/base64; cumulative binary input: 512 KiB.
- At most 100 ZIP entries; at most 20 files to pack or select. Declared expanded total: 2 MiB; actual cumulative selected output: 512 KiB; maximum expansion ratio: 100.
- Pack uses **STORE only**; it does not promise to make files smaller. Inspect/extract accept STORE and DEFLATE only.
- Rejects ZIP64, encryption, split archives, self-extractor prefixes, appended trailers, unsupported entries, unsafe paths, duplicate/casefold/Unicode-normalized names and inconsistent local/central headers. These are defensive checks, not a proof that every malformed ZIP is rejected.
- Never uses `extractall`, writes archive paths to disk, recursively extracts nested ZIPs, fetches a remote URL or executes returned content.
- Each HTTP task runs in a spawned worker with a 256 MiB address-space limit, 5-second CPU limit, disabled core dumps and a 10-second parent deadline.
- At most four active HTTP connections; excess connections close immediately. Accepted sockets have a 5-second idle timeout, a 5-second absolute header deadline and a 20-second absolute request deadline.
- No application file storage: synchronous inline in-memory results only. This is **not** a guarantee of forensic memory erasure or of retention policies elsewhere in an integrating system.
- `safe_name` is `artifact-<random identifier>.bin`, not an archive-supplied path. `name_untrusted` is metadata only. `content_type_hint` is a small signature/UTF-8 heuristic, not malware scanning or MIME validation. `mixed_script` is a limited diagnostic, not complete Unicode confusable detection. `preview_allowed` is always false; do not auto-open returned content.

## Before any real deployment

This example is limited to synthetic loopback tests. It has no independent low-privilege service account, network namespace, seccomp policy, read-only root filesystem, deployment disk quota, comprehensive fuzz audit, TLS or global DoS protection. Worker limits do not replace OS isolation. Four slow clients can occupy all connection slots; a sustained attack can keep denying legitimate requests. An integrating relay or reverse proxy needs source-based connection limits and other abuse controls, followed by a separate security review.

Do not expose this example to untrusted public uploads. It does not implement x402, signatures, receipts, pricing, billing, guarantees, refunds or production authorization.
