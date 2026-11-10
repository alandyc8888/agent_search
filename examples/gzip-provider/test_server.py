import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import base64
import gzip
import hashlib
import http.client
import json
import secrets
import socket
import threading
import time
import unittest
from server import load_token, Invalid, MAX_BODY, MAX_INPUT, execute, make_server, run_task


def payload(raw):
    return {'data_base64': base64.b64encode(raw).decode(), 'synthetic_only': True}


class TaskTests(unittest.TestCase):
    def check_roundtrip(self, raw):
        result = execute('/file/gzip', payload(raw))
        compressed = base64.b64decode(result['data_base64'], validate=True)
        self.assertEqual(gzip.decompress(compressed), raw)
        self.assertEqual(result['input_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['sha256'], hashlib.sha256(compressed).hexdigest())
        self.assertEqual(result['input_bytes'], len(raw))
        self.assertEqual(result['output_bytes'], len(compressed))
        self.assertEqual(compressed[4:8], bytes(4))
        self.assertEqual(result['safe_name'], 'compressed.gz')
        self.assertFalse(result['preview_allowed'])

    def test_text_roundtrip(self):
        self.check_roundtrip(b'synthetic example\n' * 100)

    def test_binary_roundtrip(self):
        self.check_roundtrip(bytes(range(256)) * 4)

    def test_limit_random_roundtrip(self):
        self.check_roundtrip(secrets.token_bytes(MAX_INPUT))

    def test_not_guaranteed_smaller(self):
        result = execute('/file/gzip', payload(b'a'))
        self.assertFalse(result['smaller'])
        self.assertGreater(result['output_bytes'], result['input_bytes'])

    def test_deterministic_same_runtime(self):
        self.assertEqual(execute('/file/gzip', payload(b'abc')), execute('/file/gzip', payload(b'abc')))

    def test_bad_base64_and_types(self):
        for value in ('!!!!', 'a', '', None, 1, [], 'é'):
            with self.subTest(value=value), self.assertRaises(Invalid):
                execute('/file/gzip', {'data_base64': value, 'synthetic_only': True})

    def test_input_above_limit(self):
        with self.assertRaises(Invalid):
            execute('/file/gzip', payload(b'x' * (MAX_INPUT + 1)))

    def test_exact_shape(self):
        for body in (None, [], {}, {'synthetic_only': True}, dict(payload(b'x'), url='https://example.com'), dict(payload(b'x'), filename='../x')):
            with self.subTest(body=body), self.assertRaises(Invalid):
                execute('/file/gzip', body)

    def test_marker_is_literal_true(self):
        for marker in (False, 1, 'true', None):
            with self.subTest(marker=marker), self.assertRaises(Invalid):
                execute('/file/gzip', dict(payload(b'x'), synthetic_only=marker))

    def test_only_compression_route(self):
        for route in ('/file/gunzip', '/file/gzip?x=1', '/pdf/text', 'http://example.com/file/gzip'):
            with self.subTest(route=route), self.assertRaises(Invalid):
                execute(route, payload(b'x'))

    def test_worker_success(self):
        status, raw = run_task('/file/gzip', payload(b'hello'))
        envelope = json.loads(raw)
        self.assertEqual(status, 200)
        self.assertTrue(envelope['demo_only'])
        self.assertEqual(envelope['billing'], 'disabled')

    def test_worker_failure(self):
        status, raw = run_task('/file/gzip', {})
        self.assertEqual(status, 422)
        self.assertFalse(json.loads(raw)['ok'])

    def test_missing_token(self):
        for token in (None, 'short'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                make_server(0, token)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.token = secrets.token_urlsafe(32)
        cls.server = make_server(0, cls.token)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def request(self, path='/file/gzip', body=None, auth=True, extra=None, method='POST'):
        headers = {'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = 'Bearer ' + self.token
        headers.update(extra or {})
        data = body if isinstance(body, bytes) else json.dumps(payload(b'hello') if body is None else body).encode()
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        try:
            connection.request(method, path, body=None if method == 'GET' else data, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read()), dict(response.getheaders())
        finally:
            connection.close()

    def raw_status(self, extra_headers, length='2'):
        headers = [f'Host: 127.0.0.1:{self.port}', 'Authorization: Bearer ' + self.token,
                   'Content-Type: application/json', 'Content-Length: ' + length] + extra_headers
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as connection:
            connection.sendall(('POST /file/gzip HTTP/1.0\r\n' + '\r\n'.join(headers) + '\r\n\r\n{}').encode())
            return int(connection.recv(4096).split(b'\r\n', 1)[0].split()[1])

    def test_capabilities(self):
        status, result, _ = self.request('/capabilities', auth=False, method='GET')
        self.assertEqual(status, 200)
        self.assertFalse(result['production_ready'])
        self.assertEqual(result['route'], '/file/gzip')
        self.assertEqual(result['max_input_bytes'], MAX_INPUT)

    def test_http_roundtrip(self):
        status, envelope, headers = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(gzip.decompress(base64.b64decode(envelope['result']['data_base64'])), b'hello')
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')

    def test_unauthorized(self):
        self.assertEqual(self.request(auth=False)[0], 401)
        self.assertEqual(self.request(extra={'Authorization': 'Bearer incorrect'})[0], 401)

    def test_origin_even_empty_rejected(self):
        for origin in ('https://example.com', ''):
            with self.subTest(origin=origin):
                self.assertEqual(self.request(extra={'Origin': origin})[0], 403)

    def test_wrong_host(self):
        self.assertEqual(self.request(extra={'Host': 'example.com'})[0], 403)

    def test_duplicate_host(self):
        self.assertEqual(self.raw_status([f'Host: 127.0.0.1:{self.port}']), 403)

    def test_duplicate_authorization(self):
        self.assertEqual(self.raw_status(['Authorization: Bearer ' + self.token]), 401)

    def test_duplicate_content_length(self):
        self.assertEqual(self.raw_status(['Content-Length: 2']), 400)

    def test_transfer_encoding_even_empty(self):
        for encoding in ('chunked', ''):
            with self.subTest(encoding=encoding):
                self.assertEqual(self.raw_status(['Transfer-Encoding: ' + encoding]), 400)

    def test_invalid_lengths(self):
        for length in ('-1', '+2', '1.0', 'no'):
            with self.subTest(length=length):
                self.assertEqual(self.raw_status([], length=length), 400)

    def test_oversize_before_body(self):
        self.assertEqual(self.raw_status([], length=str(MAX_BODY + 1)), 413)

    def test_duplicate_json(self):
        self.assertEqual(self.request(body=b'{"synthetic_only":true,"synthetic_only":true}')[0], 400)

    def test_wrong_content_type(self):
        self.assertEqual(self.request(extra={'Content-Type': 'text/plain'})[0], 400)

    def test_invalid_task_returns_422(self):
        self.assertEqual(self.request(body={})[0], 422)

    def test_routes_not_broadened(self):
        for path in ('/pdf/text', '/file/gunzip', '/file/gzip?x=1', '/file/%67zip', '/file/../file/gzip'):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request('/missing', method='GET')[0], 404)

    def test_slow_header_expires(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=7) as slow:
            started = time.monotonic()
            slow.sendall(b'GET /capabilities HTTP/1.0\r\nHost: ')
            self.assertEqual(self.request('/capabilities', auth=False, method='GET')[0], 200)
            self.assertEqual(slow.recv(1024), b'')
            self.assertLess(time.monotonic() - started, 7)

    def test_four_connection_limit(self):
        connections = []
        try:
            for _ in range(4):
                connection = socket.create_connection(('127.0.0.1', self.port), timeout=2)
                connections.append(connection)
                connection.sendall(b'GET /capabilities HTTP/1.0\r\nHost: ')
            with socket.create_connection(('127.0.0.1', self.port), timeout=2) as extra:
                extra.sendall(b'GET /capabilities HTTP/1.0\r\n\r\n')
                try:
                    self.assertEqual(extra.recv(1024), b'')
                except ConnectionResetError:
                    pass
        finally:
            for connection in connections:
                connection.close()
            for _ in range(4):
                self.assertTrue(self.server.connection_slots.acquire(timeout=7))
            for _ in range(4):
                self.server.connection_slots.release()


class TokenFileTests(unittest.TestCase):
    prefix = 'GZIP_DEMO'

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'capability'
        self.token = secrets.token_urlsafe(32)
        self.path.write_bytes(self.token.encode())
        self.path.chmod(0o600)

    def tearDown(self):
        self.directory.cleanup()

    def env(self):
        return {self.prefix + '_TOKEN_FILE': str(self.path)}

    def test_file_with_and_without_lf(self):
        self.assertEqual(load_token(self.env()), self.token)
        self.path.write_bytes((self.token + '\n').encode())
        self.assertEqual(load_token(self.env()), self.token)

    def test_environment_source_and_conflict(self):
        self.assertEqual(load_token({self.prefix + '_TOKEN': self.token}), self.token)
        for env in ({}, {self.prefix + '_TOKEN': ''}, {self.prefix + '_TOKEN_FILE': ''},
                    dict(self.env(), **{self.prefix + '_TOKEN': self.token}),
                    dict(self.env(), **{self.prefix + '_TOKEN': ''})):
            with self.subTest(keys=list(env)), self.assertRaises(ValueError):
                load_token(env)

    def test_permissions(self):
        for mode in (0o644, 0o640, 0o400, 0o700, 0o660):
            self.path.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(ValueError):
                load_token(self.env())
        self.path.chmod(0o600)

    def test_symlink_directory_fifo_and_missing(self):
        directory = Path(self.directory.name)
        link = directory / 'link'
        link.symlink_to(self.path)
        fifo = directory / 'fifo'
        os.mkfifo(fifo, 0o600)
        for path in (link, directory, fifo, directory / 'absent'):
            with self.subTest(kind=path.name), self.assertRaises(ValueError):
                load_token({self.prefix + '_TOKEN_FILE': str(path)})

    def test_hardlink(self):
        second = Path(self.directory.name) / 'second'
        os.link(self.path, second)
        with self.assertRaises(ValueError):
            load_token(self.env())

    def test_wrong_owner(self):
        actual = os.fstat
        def changed(fd):
            st = actual(fd)
            return SimpleNamespace(**{field: (st.st_uid + 1 if field == 'st_uid' else getattr(st, field))
                for field in ('st_mode', 'st_uid', 'st_nlink', 'st_size')})
        with mock.patch('server.os.fstat', side_effect=changed), self.assertRaises(ValueError):
            load_token(self.env())

    def test_content_and_size_limits(self):
        for raw in (b'', b'x' * 31, b'x' * 258, b'x' * 32 + b'\r\n', b'x' * 32 + b'\n\n',
                    b'x' * 32 + b' ', b'x' * 32 + b'\x00', b'x' * 32 + b'\xff'):
            self.path.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                load_token(self.env())
        self.path.write_bytes(b'x' * 256 + b'\n')
        self.assertEqual(len(load_token(self.env())), 256)

    def test_file_changed_during_read(self):
        actual = os.read
        def changed(fd, length):
            raw = actual(fd, length)
            self.path.write_bytes((self.token + 'x').encode())
            return raw
        with mock.patch('server.os.read', side_effect=changed), self.assertRaises(ValueError):
            load_token(self.env())

    def test_error_does_not_include_path_or_contents(self):
        private_name = str(Path(self.directory.name) / 'PRIVATE-LOCATION')
        try:
            load_token({self.prefix + '_TOKEN_FILE': private_name})
        except ValueError as error:
            self.assertEqual(str(error), 'invalid_token_file')
            self.assertNotIn(private_name, str(error))
            self.assertNotIn(self.token, str(error))
        else:
            self.fail('expected rejection')

    def test_file_token_authenticates_http(self):
        server = make_server(0, load_token(self.env()))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=15)
        try:
            connection.request('POST', '/file/gzip', body=json.dumps(payload(b'hello')),
                               headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.token})
            response = connection.getresponse()
            result = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertTrue(result['ok'])
        finally:
            connection.close()
            server.shutdown()
            thread.join()
            server.server_close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
