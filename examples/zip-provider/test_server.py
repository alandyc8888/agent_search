import base64
import io
import json
import stat
import struct
import socket
import secrets
import time
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from server import execute, Invalid, MAX_ENTRIES, MAX_INPUT, make_server, run_task


def enc(data):
    return base64.b64encode(data).decode()


def archive(items, compression=zipfile.ZIP_STORED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=compression) as z:
        for name, data in items:
            z.writestr(name, data)
    return out.getvalue()


class ZipTests(unittest.TestCase):
    def test_roundtrip(self):
        packed = execute('/zip/pack', {'files': [{'name': 'docs/hello.txt', 'data_base64': enc(b'hello')}, {'name': 'bytes.bin', 'data_base64': enc(bytes(range(256)))}]})
        inspect = execute('/zip/inspect', {'archive_base64': packed['archive_base64']})
        self.assertEqual(len(inspect['entries']), 2)
        self.assertIn('headers-only', inspect['verification'])
        result = execute('/zip/extract', {'archive_base64': packed['archive_base64'], 'entry_ids': [1]})
        self.assertEqual(base64.b64decode(result['files'][0]['data_base64']), bytes(range(256)))
        self.assertFalse(result['auto_extract'])

    def test_deflate(self):
        data = archive([('a.txt', b'abcdef' * 20)], zipfile.ZIP_DEFLATED)
        out = execute('/zip/extract', {'archive_base64': enc(data), 'entry_ids': [0]})
        self.assertEqual(base64.b64decode(out['files'][0]['data_base64']), b'abcdef' * 20)

    def reject(self, data, path='/zip/inspect'):
        with self.assertRaises((Invalid, zipfile.BadZipFile, UnicodeError)):
            execute(path, {'archive_base64': enc(data)})

    def test_paths(self):
        for name in ['../a', '/etc/passwd', 'a/../../b', 'C:/evil', 'a\\b', 'a//b', 'a/./b', 'nul.txt', 'a\x01b', 'a./b']:
            with self.subTest(name=name):
                self.reject(archive([(name, b'x')]))

    def test_duplicates(self):
        for names in [('A.txt', 'a.txt'), ('caf\u00e9.txt', 'cafe\u0301.txt'), ('dir', 'dir/')]:
            with self.subTest(names=names):
                self.reject(archive([(n, b'x') for n in names]))

    def test_symlink(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as z:
            item = zipfile.ZipInfo('link')
            item.create_system = 3
            item.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(item, b'/etc/passwd')
        self.reject(out.getvalue())

    def test_expansion_ratio(self):
        self.reject(archive([('bomb', b'0' * 200000)], zipfile.ZIP_DEFLATED))

    def test_entry_limit(self):
        self.reject(archive([(str(i), b'') for i in range(MAX_ENTRIES + 1)]))

    def test_input_limit(self):
        with self.assertRaises(Invalid):
            execute('/zip/pack', {'files': [{'name': 'a', 'data_base64': enc(b'0' * (MAX_INPUT + 1))}]})

    def test_invalid_base64(self):
        with self.assertRaises(Invalid):
            execute('/zip/inspect', {'archive_base64': '!bad!'})

    def test_truncated_and_prefixed(self):
        data = archive([('a', b'hello')])
        for bad in [data[:-10], b'MZ'+data, data+b'trailer']:
            self.reject(bad)

    def test_unsupported_compression(self):
        self.reject(archive([('a', b'abc')], zipfile.ZIP_BZIP2))

    def test_encryption_bit(self):
        data = bytearray(archive([('a', b'abc')]))
        flags = struct.unpack_from('<H', data, 6)[0]
        struct.pack_into('<H', data, 6, flags | 1)
        cd = data.index(b'PK\x01\x02')
        struct.pack_into('<H', data, cd + 8, flags | 1)
        self.reject(bytes(data))

    def test_split_archive(self):
        data = bytearray(archive([('a', b'abc')]))
        end = data.rindex(b'PK\x05\x06')
        struct.pack_into('<H', data, end+4, 1)
        self.reject(bytes(data))

    def test_zip64(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as z:
            item = zipfile.ZipInfo('a')
            item.extra = struct.pack('<HHQQ', 1, 16, 3, 3)
            z.writestr(item, b'abc')
        self.reject(out.getvalue())

    def test_crc(self):
        data = bytearray(archive([('a', b'hello')]))
        data[31] ^= 1
        with self.assertRaises(zipfile.BadZipFile):
            execute('/zip/extract', {'archive_base64': enc(data), 'entry_ids': [0]})

    def test_nested_not_recursive(self):
        inner = archive([('../unsafe', b'x')])
        outer = archive([('nested.zip', inner)])
        result = execute('/zip/extract', {'archive_base64': enc(outer), 'entry_ids': [0]})
        self.assertEqual(base64.b64decode(result['files'][0]['data_base64']), inner)

    def test_unknown_fields_and_selection(self):
        data = enc(archive([('a', b'x')]))
        for body in [{'archive_base64': data, 'url': 'https://example.com'}, {'archive_base64': data, 'entry_ids': [True]}, {'archive_base64': data, 'entry_ids': [0, 0]}, {'archive_base64': data, 'entry_ids': [2]}]:
            with self.assertRaises(Invalid):
                execute('/zip/extract', body)

    def test_safe_name_and_content_hint(self):
        blob = archive([('pretend.txt', b'<!doctype html><script>bad()</script>')])
        result = execute('/zip/extract', {'archive_base64': enc(blob), 'entry_ids': [0]})['files'][0]
        self.assertRegex(result['safe_name'], r'^artifact-[0-9a-f]{32}\.bin$')
        self.assertEqual(result['content_type_hint'], 'text/html')
        self.assertFalse(result['preview_allowed'])

    def test_mixed_script(self):
        blob = archive([('r\u0435adme.txt', b'hi'), ('readme.txt', b'hi')])
        entries = execute('/zip/inspect', {'archive_base64': enc(blob)})['entries']
        self.assertTrue(entries[0]['mixed_script'])
        self.assertFalse(entries[1]['mixed_script'])

    def test_worker(self):
        status, raw = run_task('/zip/pack', {'files': [{'name': 'a', 'data_base64': enc(b'hello')}]})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)['billing'], 'disabled')


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.token = secrets.token_urlsafe(32)
        cls.server = make_server(0, cls.token)
        cls.url = 'http://127.0.0.1:' + str(cls.server.server_port)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def request(self, path, body=None, auth=True, extra=None):
        headers = {'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = 'Bearer ' + self.token
        headers.update(extra or {})
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        try:
            r = urllib.request.urlopen(urllib.request.Request(self.url+path, data=data, headers=headers), timeout=15)
        except urllib.error.HTTPError as e:
            r = e
        return r.code, json.loads(r.read())

    def test_capabilities(self):
        code, data = self.request('/capabilities', auth=False)
        self.assertEqual(code, 200)
        self.assertFalse(data['production_ready'])

    def test_no_auth(self):
        self.assertEqual(self.request('/zip/pack', {}, auth=False)[0], 401)

    def test_browser_origin_rejected(self):
        self.assertEqual(self.request('/zip/pack', {}, extra={'Origin': 'https://evil.example'})[0], 403)

    def test_duplicate_json(self):
        self.assertEqual(self.request('/zip/pack', b'{"files":[],"files":[]}')[0], 400)

    def test_oversize_413_before_body(self):
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2) as s:
            s.sendall((f'POST /zip/pack HTTP/1.0\r\nHost: 127.0.0.1:{self.server.server_port}\r\nAuthorization: Bearer {self.token}\r\nContent-Type: application/json\r\nContent-Length: 1048577\r\n\r\n').encode())
            self.assertIn(b' 413 ', s.recv(4096).split(b'\r\n', 1)[0])

    def test_slow_header_does_not_block_and_expires(self):
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=7) as slow:
            started = time.monotonic()
            slow.sendall(b'GET /capabilities HTTP/1.0\r\nHost: ')
            self.assertEqual(self.request('/capabilities', auth=False)[0], 200)
            self.assertLess(time.monotonic()-started, 2)
            self.assertEqual(slow.recv(1024), b'')
            self.assertLess(time.monotonic()-started, 7)

    def test_connection_slots_bounded(self):
        sockets = []
        try:
            for _ in range(4):
                s = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2)
                sockets.append(s)
                s.sendall(b'GET /capabilities HTTP/1.0\r\nHost: ')
            with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2) as extra:
                extra.sendall(b'GET /capabilities HTTP/1.0\r\n\r\n')
                try:
                    self.assertEqual(extra.recv(1024), b'')
                except ConnectionResetError:
                    pass
        finally:
            for s in sockets:
                s.close()
            # Synchronize with request-thread completion without busy polling.
            for _ in range(4):
                self.assertTrue(self.server.connection_slots.acquire(timeout=7))
            for _ in range(4):
                self.server.connection_slots.release()

    def test_http_roundtrip(self):
        code, data = self.request('/zip/pack', {'files': [{'name': 'tiny.txt', 'data_base64': enc(b'hello')} ]})
        self.assertEqual(code, 200)
        code, result = self.request('/zip/extract', {'archive_base64': data['result']['archive_base64'], 'entry_ids': [0]})
        self.assertEqual(code, 200)
        self.assertEqual(base64.b64decode(result['result']['files'][0]['data_base64']), b'hello')


if __name__ == '__main__':
    unittest.main(verbosity=2)
