# Loopback gzip example provider

A small Python HTTP service that **compresses** uploaded bytes to gzip for synthetic local demonstrations. It does not unpack gzip, create ZIP archives, fetch URLs or run external tools. **Not a production sandbox.** No payment, wallet, billing or package installation. A provider connector, relay and consumer skill are separate components; these tests do not establish end-to-end integration.

## Requirements and quick start

Use **Python 3.12 on Linux**, standard library only. Spawned workers use Unix `resource` limits; other platforms are not supported by this example.

From this directory:

```bash
# Private directory outside the repository; never print or commit the capability.
umask 077
export GZIP_DEMO_TOKEN_FILE="$(python3 -c 'import os; print(os.path.join(os.path.expanduser("~"), ".agent-search-example", "gzip-token"))')"
unset GZIP_DEMO_TOKEN
python3 - <<'PY'
import os
import secrets
from pathlib import Path
path = Path(os.environ['GZIP_DEMO_TOKEN_FILE'])
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

The server binds only to `127.0.0.1`, port `8793` by default. `GZIP_DEMO_PORT` changes the port, not the bind address. Stop with Ctrl-C. A client needs the **same securely shared token**, not a newly generated token. Never put it in a public card, command-line URL or relay message.

### Share the same local capability with the connector

Set the connector's `upstreamTokenFile` to the **same absolute file path** as `GZIP_DEMO_TOKEN_FILE`. Only the path belongs in the private connector configuration; do not put token contents in cards, relay requests, URLs, logs, command arguments or Git. The file must be readable by both processes under the same user in this local preview. Do not relax permissions to share it across different users; use a separately reviewed deployment identity/mount arrangement instead.

The server opens the file once at startup and requires a single-link ordinary file owned by its user with mode exactly `0600`, no final symlink, and at most 257 bytes (32–256 URL-safe ASCII token characters plus one optional final LF). Spaces, CRLF, extra lines and non-ASCII are rejected. Keep every parent directory private and free of symlinked/untrusted components: final-component `O_NOFOLLOW` is **not** a full path-traversal or same-user-attacker defense. Token entropy is the operator's responsibility.

The old environment-only source still works: unset `GZIP_DEMO_TOKEN_FILE` and generate `GZIP_DEMO_TOKEN` with `secrets.token_urlsafe(32)`. **Exactly one source must be present**; both set (even if one is empty), neither set, a missing/invalid file or invalid content rejects startup, with no fallback. Both sources now require URL-safe ASCII characters and a 32–256 character length; old arbitrary long/space/Unicode tokens are not supported. There is no automatic hot reload. Coordinate rotation and restart the service/connector together; editing the shared file alone can make them disagree. Environment mode remains a separate option, not a reason to copy secrets through shell history.

Run tests without starting a server:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_server.py
```

All tokens, random bytes and compressed data are generated at runtime. Tests start their own ephemeral loopback server and shut it down. No binary fixtures, relay configuration, internal integration harness or PDF parser is included.

## HTTP contract

| Method/path | Input | Result |
|---|---|---|
| `GET /capabilities` | None, no authorization | Top-level capabilities, limits, `production_ready: false` |
| `POST /file/gzip` | Exactly `data_base64` (nonempty standard-base64 bytes), `synthetic_only: true` | Envelope below |

Success: `{"ok":true,"demo_only":true,"billing":"disabled","result":{...}}`.

`result` includes `data_base64` (gzip bytes), `input_sha256`, `sha256` (output hash), `input_bytes`, `output_bytes`, `format: "gzip"`, `smaller` (a fact, not a promise), `safe_name: "compressed.gz"`, `preview_allowed: false`.

`synthetic_only: true` is an explicit caller acknowledgement, **not a detector or proof of synthetic content**. Do not send real private files.

POST requires `Content-Type: application/json`, a single decimal `Content-Length`, and exactly one `Authorization: Bearer <local capability>`. Any Transfer-Encoding header, duplicate JSON key, duplicate Host/Authorization or Origin header (even empty) is rejected. Host must be exactly `127.0.0.1:<port>` or `localhost:<port>`.

Statuses: 400 malformed HTTP body/JSON, 401 authorization, 403 Host/Origin, 404 unknown route, 413 body over limit (before reading it), 422 invalid task/input or worker failure. It is not a browser-facing application.

## Synthetic round trip

With the server running, use another process holding the same token source. Only generated content is sent. The client rejects redirects, checks hashes, decompresses **only its own small synthetic round-trip output**, never saves or auto-opens files, and prints metadata only.

```bash
python3 - <<'PY'
import base64
import gzip
import hashlib
import json
import os
import urllib.request
from server import load_token

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

plain = b'synthetic gzip example\n' * 32
port = int(os.environ.get('GZIP_DEMO_PORT', '8793'))
request = urllib.request.Request(
    f'http://127.0.0.1:{port}/file/gzip',
    data=json.dumps({'data_base64': base64.b64encode(plain).decode(),
                     'synthetic_only': True}).encode(),
    headers={'Content-Type': 'application/json',
             'Authorization': 'Bearer ' + load_token()},
    method='POST',
)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
with opener.open(request, timeout=15) as response:
    encoded = response.read(262145)
assert len(encoded) <= 262144
envelope = json.loads(encoded)
assert envelope['ok'] and envelope['demo_only'] and envelope['billing'] == 'disabled'
result = envelope['result']
compressed = base64.b64decode(result['data_base64'], validate=True)
assert result['input_sha256'] == hashlib.sha256(plain).hexdigest()
assert result['sha256'] == hashlib.sha256(compressed).hexdigest()
assert gzip.decompress(compressed) == plain
assert result['preview_allowed'] is False
print('roundtrip OK;', len(plain), '->', len(compressed), 'bytes; sha256:', result['sha256'])
PY
```

This hash checks transport integrity, not malware safety. Do not copy unbounded `gzip.decompress` into a consumer for arbitrary third-party data; enforce independent streaming output/ratio limits there.

See the [provider connector guide](../../packages/provider/README.md) for configuration and current provisioning limits. This example does not register itself with a relay. The [consumer skill](../../skills/agent-search/SKILL.md) describes the separate skill-only path.

## Connector integration

Configure a single fixed local origin and only `GET /capabilities`, `POST /file/gzip`. Reject ambiguous/encoded paths, traversal, double slashes and absolute URLs at the connector. Remove all caller Authorization before injecting one local Bearer; set Host to the fixed authority. Keep token/configuration files owner-only. The HTTP handler is not a replacement for the connector's exact-path checks.

Use limits covering **JSON/base64 plus envelope**, not just original bytes: input at most 64 KiB, body and response at most 256 KiB. The worker deadline is 10 seconds; choose a connector timeout allowing this plus local overhead, and respect any relay-wide cap. These are integration requirements, not a complete connector configuration or self-registration tutorial.

A provider going offline must fail file-bearing calls promptly, not queue them for replay. Cancellation does not guarantee remote task rollback; do not automatically retry. Plaintext relays can see the content. This example does not supply E2EE, x402, prices, receipts or production authorization.

## Limits and safety boundaries

- Nonempty input through 64 KiB. Compression level 6, `mtime=0`, no supplied filename. Repeatability is tested within one runtime, not promised across Python/zlib versions. Output may be larger than input.
- No server-side decompression, disk file creation, input paths, URLs, subprocesses or automatic preview. `safe_name` is just metadata; never use the constant name to overwrite an existing file. Save any later artifact in a fresh private quarantine directory.
- Spawned task workers: 256 MiB address space, 5-second CPU, core dumps disabled; parent deadline 10 seconds. Resource caps **do not isolate filesystem, network, environment or UID**.
- Four concurrent HTTP connections; excess connections close without queueing. 5-second idle/header deadline and 20-second absolute request deadline. Four slow clients can occupy all slots; no source fairness or global DoS defense.
- No application file persistence and no request-content logging. This does not guarantee forensic memory erasure or describe retention by a relay, host, proxy or consumer.

Before any real or public deployment: independent low-privilege identity, environment minimization, OS sandbox/network restrictions, read-only root, process lifecycle/quotas, abuse controls and a fresh security review. Do not expose this loopback demo to untrusted public uploads. No new license choice is made by this standalone example.
