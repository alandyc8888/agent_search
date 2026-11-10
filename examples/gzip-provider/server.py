"""Loopback-only synthetic gzip HTTP example. NOT a production sandbox."""
import base64
import binascii
import gzip
import hashlib
import hmac
import json
import multiprocessing as mp
import os
import socket
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 262144
MAX_INPUT = 65536
TASK_ROUTE = '/file/gzip'


class Invalid(ValueError):
    pass


def execute(path, body):
    if path != TASK_ROUTE:
        raise Invalid('unknown_task')
    if not isinstance(body, dict) or set(body) != {'data_base64', 'synthetic_only'} or body['synthetic_only'] is not True:
        raise Invalid('synthetic_object_required')
    value = body['data_base64']
    if not isinstance(value, str) or len(value) > 4 * ((MAX_INPUT + 2) // 3):
        raise Invalid('input_limit')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise Invalid('invalid_base64') from None
    if not raw or len(raw) > MAX_INPUT:
        raise Invalid('input_limit')
    result = gzip.compress(raw, compresslevel=6, mtime=0)
    return {
        'data_base64': base64.b64encode(result).decode(),
        'input_sha256': hashlib.sha256(raw).hexdigest(),
        'sha256': hashlib.sha256(result).hexdigest(),
        'input_bytes': len(raw), 'output_bytes': len(result),
        'format': 'gzip', 'smaller': len(result) < len(raw),
        'safe_name': 'compressed.gz', 'preview_allowed': False,
    }


def worker(conn, path, body):
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = {'ok': True, 'demo_only': True, 'billing': 'disabled', 'result': execute(path, body)}
        encoded = json.dumps(result, ensure_ascii=True).encode()
        if len(encoded) > MAX_BODY:
            raise Invalid('output_limit')
        conn.send_bytes(encoded)
    except Exception:
        conn.send_bytes(b'{"ok":false,"error":"invalid_task_or_request","demo_only":true}')
    finally:
        conn.close()


def run_task(path, body):
    context = mp.get_context('spawn')
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(child, path, body))
    process.start()
    child.close()
    try:
        if not parent.poll(10):
            return 422, b'{"ok":false,"error":"task_timeout"}'
        try:
            data = parent.recv_bytes(MAX_BODY)
        except (EOFError, OSError):
            return 422, b'{"ok":false,"error":"task_failed"}'
        return (200 if json.loads(data).get('ok') else 422), data
    finally:
        if process.is_alive():
            process.terminate()
        process.join()
        parent.close()


class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, address, handler):
        self.connection_slots = threading.BoundedSemaphore(4)
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)  # Before reading even the request line/headers.
        return connection, address

    def process_request(self, request, address):
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(request)  # Saturation is closed, never queued indefinitely.
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.connection_slots.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def abort_connection(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def setup(self):
        super().setup()
        # Absolute deadlines also stop clients drip-feeding within the idle timeout.
        self.header_deadline = threading.Timer(5, self.abort_connection)
        self.request_deadline = threading.Timer(20, self.abort_connection)
        for timer in (self.header_deadline, self.request_deadline):
            timer.daemon = True
            timer.start()

    def handle(self):
        try:
            super().handle()
        except OSError:
            pass  # Peer disconnect/deadline is expected, never log request details.

    def parse_request(self):
        result = super().parse_request()
        if result:
            self.header_deadline.cancel()
        return result

    def finish(self):
        for name in ('header_deadline', 'request_deadline'):
            timer = getattr(self, name, None)
            if timer:
                timer.cancel()
        try:
            super().finish()
        except OSError:
            pass

    def log_message(self, *args):
        pass  # No file names, request bodies, headers or capabilities in logs.

    def send(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != '/capabilities':
            self.send(404, b'{"ok":false}')
            return
        self.send(200, json.dumps({'demo_only': True, 'billing': 'disabled', 'production_ready': False, 'task': 'gzip', 'route': TASK_ROUTE, 'max_body_bytes': MAX_BODY, 'max_input_bytes': MAX_INPUT, 'synthetic_only': True}).encode())

    def do_POST(self):
        self.connection.settimeout(5)
        hosts = self.headers.get_all('Host', [])
        host = hosts[0] if len(hosts) == 1 else ''
        if 'Origin' in self.headers or host not in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'):
            self.send(403, b'{"ok":false,"error":"origin_or_host"}')
            return
        authorizations = self.headers.get_all('Authorization', [])
        supplied = authorizations[0] if len(authorizations) == 1 else ''
        if not hmac.compare_digest(supplied.encode('utf-8'), ('Bearer ' + self.server.demo_token).encode('utf-8')):
            self.send(401, b'{"ok":false,"error":"unauthorized"}')
            return
        if self.path not in (TASK_ROUTE,):
            self.send(404, b'{"ok":false}')
            return
        try:
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or 'Transfer-Encoding' in self.headers or not lengths[0].isascii() or not lengths[0].isdecimal():
                raise Invalid('length_required')
            size = int(lengths[0])
            if size > MAX_BODY:
                self.send(413, b'{"ok":false,"error":"request_body_too_large"}')
                return
            if size <= 0 or self.headers.get_content_type() != 'application/json':
                raise Invalid('invalid_body')
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise Invalid('truncated_request')
            def unique(pairs):
                d = {}
                for k, v in pairs:
                    if k in d:
                        raise Invalid('duplicate_json_key')
                    d[k] = v
                return d
            body = json.loads(raw, object_pairs_hook=unique)
            code, result = run_task(self.path, body)
            self.send(code, result)
        except Exception:
            self.send(400, b'{"ok":false,"error":"invalid_request"}')


def validate_token(token):
    # Match generated URL-safe capabilities and keep Authorization ASCII-only.
    if not isinstance(token, str) or not 32 <= len(token) <= 256 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-' for c in token):
        raise ValueError('invalid_local_token')
    return token


def load_token(environ=None):
    env = os.environ if environ is None else environ
    direct_name, file_name = 'GZIP_DEMO_TOKEN', 'GZIP_DEMO_TOKEN_FILE'
    # Presence, not truthiness: even an empty second source is ambiguous.
    if (direct_name in env) == (file_name in env):
        raise ValueError('configure_exactly_one_token_source')
    if direct_name in env:
        return validate_token(env[direct_name])
    descriptor = None
    try:
        # Open once; no separate pathname stat/read race. NONBLOCK avoids hanging on FIFOs.
        descriptor = os.open(env[file_name], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid() or before.st_nlink != 1 or not 32 <= before.st_size <= 257:
            raise ValueError('invalid_token_file')
        raw = os.read(descriptor, 258)
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(raw) != before.st_size or any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError('token_file_changed')
        # One optional final LF is permitted; do not strip arbitrary whitespace.
        if raw.endswith(b'\n'):
            raw = raw[:-1]
        return validate_token(raw.decode('ascii'))
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ValueError('invalid_token_file') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def make_server(port=8793, token=None):
    token = validate_token(token)
    server = BoundedHTTPServer(('127.0.0.1', port), Handler)
    server.demo_token = token
    return server


if __name__ == '__main__':
    try:
        local_token = load_token()
    except ValueError:
        raise SystemExit('token configuration rejected') from None
    make_server(int(os.environ.get('GZIP_DEMO_PORT', '8793')), local_token).serve_forever()
