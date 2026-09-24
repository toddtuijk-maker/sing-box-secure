import importlib.util
import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portable


class PortableTests(unittest.TestCase):
    def test_validation(self):
        for host in ('', 'a;rm', 'https://a.com', 'a/../../etc'):
            with self.assertRaises(ValueError):
                portable.initial_state(host, {})
        with self.assertRaises(ValueError):
            portable.initial_state('example.com', {'VLESS_PORT': '80'})
        with self.assertRaises(ValueError):
            portable.initial_state('example.com', {'VLESS_PORT': '41781'})
        for port in ('0', '65536', 'bad', '41781'):
            with self.assertRaises(ValueError):
                portable.initial_state('example.com', {'VLESS_PUBLIC_PORT': port})

    def test_nat_export_and_legacy_state(self):
        state = portable.initial_state('192.0.2.1', {'VLESS_PORT': '12331', 'VLESS_PUBLIC_PORT': '40563',
            'VLESS_WS_PORT': '12861', 'VLESS_WS_PUBLIC_PORT': '40511'})
        state.update(private_key='private', public_key='public')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'cert.pem').write_text('test certificate')
            config = portable.server_config(state, root)
            self.assertEqual(config['inbounds'][0]['listen_port'], 12331)
            with patch.object(portable, 'pem_fingerprint', return_value='a' * 64):
                portable.export_clients(root, state, config)
                outbounds = json.loads((root / 'sbox.json').read_text())['outbounds']
                proxies = json.loads((root / 'clmi.yaml').read_text())['proxies']
                for tag, expected in [('vless', 40563), ('vless-ws', 40511), ('vmess', 29687)]:
                    self.assertEqual(next(x['server_port'] for x in outbounds if x['tag'] == tag), expected)
                    self.assertEqual(next(x['port'] for x in proxies if x['name'] == tag), expected)
                links = base64.b64decode((root / 'jhsub.txt').read_text()).decode()
                self.assertIn('@192.0.2.1:40563?', links)
                self.assertIn('@192.0.2.1:40511?', links)
                del state['public_ports']
                portable.export_clients(root, state, config)
                links = base64.b64decode((root / 'jhsub.txt').read_text()).decode()
                self.assertIn('@192.0.2.1:12331?', links)

    def test_independent_credentials(self):
        state = portable.initial_state('127.0.0.1', {})
        keys = [v for k, v in state.items() if k.endswith(('_uuid', '_password'))]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertFalse(any(secret in state['path'] for secret in keys))

    def test_actual_core_and_persistence(self):
        binary = os.environ.get('SING_BOX_CHECK')
        if not binary:
            self.skipTest('Set SING_BOX_CHECK for real core validation')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            portable.initialize(root, binary, '127.0.0.1')
            initial = (root / 'portable-state.json').read_bytes()
            portable.initialize(root, binary, '')
            self.assertEqual(initial, (root / 'portable-state.json').read_bytes())
            for name in ('sb.json', 'sbox.json'):
                result = subprocess.run([binary, 'check', '-c', str(root / name)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            yaml = json.loads((root / 'clmi.yaml').read_text())
            self.assertEqual(len(yaml['proxies']), 5)
            for proxy in yaml['proxies']:
                self.assertFalse(proxy.get('skip-cert-verify', False))
            if os.environ.get('MIHOMO_CHECK'):
                result = subprocess.run([os.environ['MIHOMO_CHECK'], '-t', '-f', str(root / 'clmi.yaml'), '-d', str(root)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_tls_proxy_roundtrips(self):
        binary = os.environ.get('SING_BOX_CHECK')
        if not binary:
            self.skipTest('Set SING_BOX_CHECK for local encrypted TCP/QUIC round trips')
        def free_port():
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                return sock.getsockname()[1]
        def ready(port, process):
            for _ in range(100):
                if process.poll() is not None:
                    self.fail('Core exited before listening')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        return
                except OSError:
                    time.sleep(.05)
            self.fail('Core startup timeout')
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'isolated-proxy-roundtrip-ok')
        http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=http.serve_forever, daemon=True)
        worker.start()
        processes = []
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                env = {kind.upper() + '_PORT': str(free_port()) for kind in portable.DEFAULT_PORTS}
                env.update(VLESS_WS_PORT=str(free_port()), VMESS_TLS='1')
                with patch.dict(os.environ, env):
                    portable.initialize(root, binary, '127.0.0.1')
                if os.environ.get('MIHOMO_CHECK'):
                    result = subprocess.run([os.environ['MIHOMO_CHECK'], '-t', '-f', str(root / 'clmi.yaml'), '-d', str(root)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                with open(root / 'test.log', 'w+') as log:
                    server = subprocess.Popen([binary, 'run', '-D', str(root), '-c', str(root / 'sb.json')], stdout=log, stderr=log)
                    processes.append(server)
                    try:
                        ready(int(env['ANYTLS_PORT']), server)
                        outbounds = json.loads((root / 'sbox.json').read_text())['outbounds']
                        candidates = []
                        mihomo = json.loads((root / 'clmi.yaml').read_text())
                        for outbound in outbounds:
                            if outbound['type'] in ('selector', 'direct') or outbound['tag'] == 'vless':
                                continue  # Reality needs a real public handshake target; not faked here.
                            candidates.append(('sing-box', outbound['tag'], outbound, True))
                            if outbound['tag'] == 'anytls':
                                wrong = json.loads(json.dumps(outbound))
                                wrong['tls']['server_name'] = 'wrong.invalid'
                                candidates.append(('sing-box', outbound['tag'], wrong, False))
                            if os.environ.get('MIHOMO_CHECK'):
                                proxy = next(p for p in mihomo['proxies'] if p['name'] == outbound['tag'])
                                candidates.append(('mihomo', outbound['tag'], proxy, True))
                                if outbound['tag'] == 'anytls':
                                    candidates.append(('mihomo', outbound['tag'], {**proxy, 'fingerprint': '0' * 64}, False))
                        for engine, tag, proxy, expected in candidates:
                            with self.subTest(engine=engine, protocol=tag, valid_certificate=expected):
                                port = free_port()
                                if engine == 'sing-box':
                                    config = {'log': {'level': 'warn'}, 'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}], 'outbounds': [proxy]}
                                    args = [binary, 'run', '-D', str(root), '-c', str(root / 'test-client.json')]
                                else:
                                    config = {'mixed-port': port, 'allow-lan': False, 'bind-address': '127.0.0.1', 'mode': 'rule', 'log-level': 'warning', 'proxies': [proxy], 'rules': ['MATCH,' + tag]}
                                    args = [os.environ['MIHOMO_CHECK'], '-f', str(root / 'test-client.json'), '-d', str(root)]
                                portable.write_private(root / 'test-client.json', json.dumps(config))
                                client = subprocess.Popen(args, stdout=log, stderr=log)
                                processes.append(client)
                                try:
                                    ready(port, client)
                                    with socket.create_connection(('127.0.0.1', port), timeout=10) as connection:
                                        authority = '127.0.0.1:' + str(http.server_port)
                                        connection.sendall(('GET http://' + authority + '/ HTTP/1.1\r\nHost: ' + authority + '\r\nConnection: close\r\n\r\n').encode())
                                        data = b''
                                        while True:
                                            try:
                                                part = connection.recv(4096)
                                            except ConnectionResetError:
                                                break  # A complete response can end with a reset on Windows.
                                            if not part:
                                                break
                                            data += part
                                        log.flush()
                                        if expected:
                                            self.assertIn(b'isolated-proxy-roundtrip-ok', data, (root / 'test.log').read_text()[-2000:])
                                        else:
                                            self.assertIn(b'502', data)
                                            self.assertNotIn(b'isolated-proxy-roundtrip-ok', data)
                                finally:
                                    client.terminate()
                                    client.wait(timeout=10)
                    finally:
                        for proc in processes:
                            if proc.poll() is None:
                                proc.terminate()
                                proc.wait(timeout=10)
                        log.flush()
                        log.seek(0)
                        diagnostics = log.read()
                        if 'FATAL' in diagnostics:
                            self.fail(diagnostics[-2000:])
        finally:
            http.shutdown()
            http.server_close()
            worker.join()


if __name__ == '__main__':
    unittest.main()
