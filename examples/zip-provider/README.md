# Loopback ZIP example provider

A small Python HTTP service for synthetic local demonstrations. **Not a production sandbox.** No payment, wallet, external API, package installation, or remote URL fetching. This example contains only the local service; a provider connector, relay and consumer skill are separate components. End-to-end integration is not established by these unit tests.

## Requirements and quick start

Use **Python 3.12 on Linux**, with the standard library. Worker limits use Unix `resource` facilities; other platforms are not supported by this example.

From this directory:

```bash
# Generate a temporary local capability. Do not print it or commit it.
export ZIP_DEMO_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
python3 server.py
```

The server binds only to `127.0.0.1`, using port `8791` by default. `ZIP_DEMO_PORT` can change the port, not the bind address. Stop it with Ctrl-C. To make a request, use a separate terminal or process with the **same securely shared environment variable**; do not generate a different token there.

Run all tests without manually starting a server:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_server.py
```

Tests generate all ZIP archives in memory, generate a temporary authentication token at runtime, use an ephemeral loopback port and shut down their own server. There are no committed ZIP files or other binary fixtures.

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

port = int(os.environ.get('ZIP_DEMO_PORT', '8791'))
origin = f'http://127.0.0.1:{port}'

def call(path, payload):
    request = urllib.request.Request(
        origin + path,
        data=json.dumps(payload).encode(),
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + os.environ['ZIP_DEMO_TOKEN'],
        },
        method='POST',
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        envelope = json.load(response)
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
