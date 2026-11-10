"""Loopback-only synthetic ZIP HTTP prototype. NOT a production sandbox."""
import base64
import binascii
import hashlib
import hmac
import io
import json
import multiprocessing as mp
import os
import re
import secrets
import stat
import struct
import socket
import threading
import unicodedata
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 1024 * 1024
MAX_INPUT = 512 * 1024
MAX_EXPANDED = 2 * 1024 * 1024
MAX_ENTRIES = 100
MAX_FILES = 20


class Invalid(ValueError):
    pass


def safe_name(name):
    if not isinstance(name, str) or not name or len(name.encode('utf-8')) > 240:
        raise Invalid('invalid_name')
    if any(unicodedata.category(c).startswith('C') for c in name):
        raise Invalid('control_character')
    if name.startswith('/') or '\\' in name or ':' in name:
        raise Invalid('unsafe_path')
    parts = name.rstrip('/').split('/')
    if len(parts) > 8 or any(p in ('', '.', '..') for p in parts):
        raise Invalid('unsafe_path')
    # Refuse Windows-special/trailing components even on Unix.
    if any(p.endswith((' ', '.')) or re.match(r'(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)', p) for p in parts):
        raise Invalid('unsafe_path')
    return unicodedata.normalize('NFC', '/'.join(parts)).casefold()


def mixed_script(name):
    # Diagnostic only: not a complete Unicode confusable/skeleton detector.
    scripts = set()
    for char in name.rsplit('/', 1)[-1].rsplit('.', 1)[0]:
        if not char.isalpha():
            continue
        description = unicodedata.name(char, '')
        for script in ('LATIN', 'CYRILLIC', 'GREEK', 'ARABIC', 'HEBREW', 'HIRAGANA', 'KATAKANA', 'HANGUL', 'CJK'):
            if script in description:
                scripts.add(script)
                break
    return len(scripts) > 1


def content_hint(data):
    # Small conservative signature heuristic, not MIME validation or malware scanning.
    signatures = [(b'PK\x03\x04', 'application/zip'), (b'PK\x05\x06', 'application/zip'),
                  (b'%PDF-', 'application/pdf'), (b'\x89PNG\r\n\x1a\n', 'image/png'),
                  (b'\xff\xd8\xff', 'image/jpeg'), (b'GIF87a', 'image/gif'),
                  (b'GIF89a', 'image/gif'), (b'MZ', 'application/x-dosexec')]
    for prefix, mime in signatures:
        if data.startswith(prefix):
            return mime
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        return 'application/octet-stream'
    leading = text.lstrip()[:256].lower()
    if leading.startswith(('<!doctype html', '<html', '<script', '<svg', '<?xml')):
        return 'application/xml' if leading.startswith(('<?xml', '<svg')) else 'text/html'
    if all(c.isprintable() or c in '\r\n\t' for c in text):
        return 'text/plain'
    return 'application/octet-stream'


def decode(value):
    if not isinstance(value, str) or len(value) > 4 * ((MAX_INPUT + 2) // 3):
        raise Invalid('input_limit')
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise Invalid('invalid_base64') from None
    if len(data) > MAX_INPUT:
        raise Invalid('input_limit')
    return data


def check_extra(extra):
    while extra:
        if len(extra) < 4:
            raise Invalid('malformed_extra')
        kind, size = struct.unpack('<HH', extra[:4])
        if len(extra) < 4 + size:
            raise Invalid('malformed_extra')
        if kind == 1:
            raise Invalid('zip64_unsupported')
        extra = extra[4 + size:]


def preflight(data):
    # No prepended self-extractor, split archive or appended trailer.
    pos = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
    if pos < 0 or len(data) < pos + 22:
        raise Invalid('invalid_zip')
    e = struct.unpack('<4s4H2IH', data[pos:pos + 22])
    _, disk, cd_disk, on_disk, count, cd_size, cd_offset, comment = e
    if disk or cd_disk or on_disk != count:
        raise Invalid('split_zip_unsupported')
    if count == 65535 or cd_size == 0xffffffff or cd_offset == 0xffffffff:
        raise Invalid('zip64_unsupported')
    if pos + 22 + comment != len(data) or cd_offset + cd_size != pos:
        raise Invalid('noncanonical_zip')
    if count > MAX_ENTRIES or not data.startswith(b'PK\x03\x04') and count:
        raise Invalid('entry_limit_or_prefix')
    z = zipfile.ZipFile(io.BytesIO(data), allowZip64=False)
    infos = z.infolist()
    if len(infos) != count:
        raise Invalid('entry_count_mismatch')
    names = set()
    total = 0
    for item in infos:
        if item.orig_filename != item.filename:
            raise Invalid('nul_name')
        key = safe_name(item.filename)
        if key in names:
            raise Invalid('duplicate_name')
        names.add(key)
        check_extra(item.extra)
        if item.extract_version > 20 or item.flag_bits & (1 | 0x40):
            raise Invalid('encryption_or_version_unsupported')
        if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise Invalid('method_unsupported')
        mode = item.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or item.is_dir() != (kind == stat.S_IFDIR) and kind:
            raise Invalid('non_regular_entry')
        if item.header_offset < 0 or item.header_offset + 30 > cd_offset:
            raise Invalid('local_header_outside_data')
        local = data[item.header_offset:item.header_offset + 30]
        fields = struct.unpack('<4s5H3I2H', local)
        if fields[0] != b'PK\x03\x04' or fields[3] != item.compress_type or fields[2] != item.flag_bits:
            raise Invalid('header_mismatch')
        if not item.flag_bits & 8 and fields[6:9] != (item.CRC, item.compress_size, item.file_size):
            raise Invalid('size_or_crc_header_mismatch')
        nlen, elen = fields[-2:]
        start = item.header_offset + 30
        raw_name = data[start:start + nlen]
        encoding = 'utf-8' if item.flag_bits & 0x800 else 'cp437'
        if raw_name.decode(encoding) != item.orig_filename:
            raise Invalid('name_mismatch')
        if start + nlen + elen + item.compress_size > cd_offset:
            raise Invalid('entry_outside_data')
        check_extra(data[start + nlen:start + nlen + elen])
        total += item.file_size
        if total > MAX_EXPANDED or item.file_size > 100 * max(1, item.compress_size):
            raise Invalid('expansion_limit')
    return z, infos


def execute(path, body):
    if not isinstance(body, dict):
        raise Invalid('object_required')
    if path == '/zip/pack':
        if set(body) != {'files'} or not isinstance(body['files'], list) or not 1 <= len(body['files']) <= MAX_FILES:
            raise Invalid('files_required')
        out = io.BytesIO()
        names, manifest, total = set(), [], 0
        with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as z:
            for f in body['files']:
                if not isinstance(f, dict) or set(f) != {'name', 'data_base64'}:
                    raise Invalid('invalid_file')
                key = safe_name(f['name'])
                if f['name'].endswith('/') or key in names:
                    raise Invalid('duplicate_or_directory')
                names.add(key)
                data = decode(f['data_base64'])
                total += len(data)
                if total > MAX_INPUT:
                    raise Invalid('input_limit')
                z.writestr(f['name'], data)
                manifest.append({'name': f['name'], 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        data = out.getvalue()
        if len(data) > MAX_INPUT:
            raise Invalid('output_limit')
        # Validate our own headers too. No disk extraction anywhere.
        check, _ = preflight(data)
        check.close()
        return {'archive_base64': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest(), 'files': manifest}
    if path not in ('/zip/inspect', '/zip/extract'):
        raise Invalid('unknown_endpoint')
    allowed = {'archive_base64'} if path.endswith('inspect') else {'archive_base64', 'entry_ids'}
    if set(body) != allowed:
        raise Invalid('invalid_fields')
    data = decode(body['archive_base64'])
    z, infos = preflight(data)
    try:
        if path.endswith('inspect'):
            return {'verification': 'headers-only; not decompressed or CRC-verified', 'entries': [{'entry_id': i, 'name': f.filename, 'declared_bytes': f.file_size, 'compressed_bytes': f.compress_size, 'directory': f.is_dir(), 'mixed_script': mixed_script(f.filename)} for i, f in enumerate(infos)]}
        selected = body['entry_ids']
        if not isinstance(selected, list) or not 1 <= len(selected) <= MAX_FILES or any(type(i) is not int or not 0 <= i < len(infos) for i in selected) or len(set(selected)) != len(selected):
            raise Invalid('invalid_selection')
        files, total = [], 0
        for i in selected:
            f = infos[i]
            if f.is_dir():
                raise Invalid('select_files_only')
            chunks, size = [], 0
            with z.open(f) as source:
                while True:
                    chunk = source.read(16384)
                    if not chunk:
                        break
                    size += len(chunk)
                    total += len(chunk)
                    if total > MAX_INPUT or size > 100 * max(1, f.compress_size):
                        raise Invalid('actual_expansion_limit')
                    chunks.append(chunk)
            plain = b''.join(chunks)
            if len(plain) != f.file_size:
                raise Invalid('size_mismatch')
            artifact = secrets.token_hex(16)
            files.append({'artifact_id': artifact, 'safe_name': 'artifact-' + artifact + '.bin', 'name_untrusted': f.filename, 'mixed_script': mixed_script(f.filename), 'content_type_hint': content_hint(plain), 'content_type_basis': 'heuristic signature/UTF-8 only; not validated; never authorizes preview', 'preview_allowed': False, 'data_base64': base64.b64encode(plain).decode(), 'sha256': hashlib.sha256(plain).hexdigest()})
        return {'files': files, 'verification': 'selected entries decompressed and CRC-checked; unselected content not validated', 'auto_extract': False}
    finally:
        z.close()


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
        conn.send_bytes(b'{"ok":false,"error":"invalid_archive_or_request","demo_only":true}')
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
        self.send(200, json.dumps({'demo_only': True, 'billing': 'disabled', 'input': 'json-base64-upload-only', 'max_body_bytes': MAX_BODY, 'max_input_bytes': MAX_INPUT, 'max_declared_expanded_bytes': MAX_EXPANDED, 'max_selected_output_bytes': MAX_INPUT, 'max_entries': MAX_ENTRIES, 'max_files': MAX_FILES, 'pack_method': 'STORE', 'read_methods': ['STORE', 'DEFLATE'], 'tasks': ['/zip/pack', '/zip/inspect', '/zip/extract'], 'persistence': 'no application file storage; synchronous in-memory prototype; not a forensic erase guarantee', 'production_ready': False}).encode())

    def do_POST(self):
        self.connection.settimeout(5)
        host = self.headers.get('Host', '')
        if self.headers.get('Origin') or host not in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'):
            self.send(403, b'{"ok":false,"error":"origin_or_host"}')
            return
        supplied = self.headers.get('Authorization', '')
        if not hmac.compare_digest(supplied, 'Bearer ' + self.server.demo_token):
            self.send(401, b'{"ok":false,"error":"unauthorized"}')
            return
        if self.path not in ('/zip/pack', '/zip/inspect', '/zip/extract'):
            self.send(404, b'{"ok":false}')
            return
        try:
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or self.headers.get('Transfer-Encoding'):
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
    direct_name, file_name = 'ZIP_DEMO_TOKEN', 'ZIP_DEMO_TOKEN_FILE'
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


def make_server(port=8791, token=None):
    token = validate_token(token)
    server = BoundedHTTPServer(('127.0.0.1', port), Handler)
    server.demo_token = token
    return server


if __name__ == '__main__':
    try:
        local_token = load_token()
    except ValueError:
        raise SystemExit('token configuration rejected') from None
    make_server(int(os.environ.get('ZIP_DEMO_PORT', '8791')), local_token).serve_forever()
