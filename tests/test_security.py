"""Run with python3 -m unittest discover -s tests -v. No production changes."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import ssl
import string
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('secure', ROOT / 'secure.py')
secure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(secure)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_tokens_and_domains(self):
        for token in ('', '../secret', 'a' * 31, 'a' * 129, 'a' * 32 + '?'):
            with self.assertRaises(ValueError):
                secure.validate_token(token)
        self.assertEqual(secure.validate_token('a' * 32), 'a' * 32)
        for domain in ('a..b', 'https://a.com', 'x;rm', '*.a.com'):
            with self.assertRaises(ValueError):
                secure.validate_domain(domain)

    def test_subscription_allowlist(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), secure.make_handler('a' * 32, {'sbox.json': b'private'}))
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            base = 'http://127.0.0.1:' + str(server.server_port)
            with urllib.request.urlopen(base + '/' + 'a' * 32 + '/sbox.json') as response:
                self.assertEqual(response.read(), b'private')
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
            for path in ('/', '/wrong/sbox.json', '/' + 'a' * 32 + '/sbox.json?q=1', '/' + 'a' * 32 + '/..%2Fprivate.key', '/' + 'a' * 32 + '/private.key'):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(base + path)
                self.assertEqual(caught.exception.code, 404)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_credentials_exported_per_protocol(self):
        protocols = {'vless': {'uuid': 'vless-only'}, 'vmess': {'uuid': 'vmess-only'}, 'hysteria2': {'password': 'hy-only'}, 'tuic': {'uuid': 'tuic-only', 'password': 'tuic-password'}, 'anytls': {'password': 'any-only'}}
        server = {'inbounds': [dict(type=p, users=[creds]) for p, creds in protocols.items()]}
        client = {'outbounds': [dict(type=p, uuid='old-shared', password='old-shared', tls={'enabled': True, 'insecure': True}) for p in protocols]}
        (self.root / 'sb.json').write_text(json.dumps(server))
        (self.root / 'sbox.json').write_text(json.dumps(client))
        (self.root / 'clmi.yaml').write_text('proxies:\n' + ''.join('- name: ' + p + '\n  type: ' + p + '\n  uuid: old\n  password: old\n  skip-cert-verify: true\n' for p in protocols))
        secure.trust_exports(self.root)
        outbounds = secure.read_json(self.root / 'sbox.json')['outbounds']
        for outbound in outbounds:
            for key, value in protocols[outbound['type']].items():
                self.assertEqual(outbound[key], value)
            self.assertFalse(outbound['tls']['insecure'])
        yaml = (self.root / 'clmi.yaml').read_text()
        self.assertNotIn('skip-cert-verify: true', yaml)
        self.assertIn('uuid: "vmess-only"', yaml)
        self.assertIn('password: "tuic-password"', yaml)

    def test_identity_validation_leaves_original_intact(self):
        source = json.dumps({'inbounds': [{'type': 'vmess', 'users': [{'uuid': 'private-uuid'}], 'transport': {'path': '/old'}}]}, indent=2)
        for name in ('sb.json', 'sb10.json', 'sb11.json'):
            (self.root / name).write_text(source)
        with patch.object(secure.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'check')):
            with self.assertRaises(subprocess.CalledProcessError):
                secure.change_identity(self.root, '/new')
        self.assertEqual((self.root / 'sb.json').read_text(), source)
        with patch.object(secure.subprocess, 'run'):
            secure.change_identity(self.root, '/new')
        updated = (self.root / 'sb.json').read_text()
        self.assertEqual(updated.count('\n'), source.count('\n'))
        self.assertEqual(json.loads(updated)['inbounds'][0]['transport']['path'], '/new')
        with self.assertRaises(ValueError):
            secure.change_identity(self.root, '/private-uuid')

    def test_server_templates_parse(self):
        source = (ROOT / 'sb.sh').read_text(encoding='utf-8')
        source = source.split('inssbjsonser(){', 1)[1].split('\nsbservice(){', 1)[0]
        templates = re.findall(r'cat > /etc/s-box/(sb(?:10|11)\.json) <<EOF\n(.*?)\nEOF', source, re.S)
        self.assertEqual(len(templates), 2)
        values = dict(port_vl_re='25809', port_vm_ws='29687', port_hy2='32695', port_tu='41781', port_an='16134', uuid='11111111-1111-4111-8111-111111111111', vm_uuid='22222222-2222-4222-8222-222222222222', tu5_uuid='33333333-3333-4333-8333-333333333333', hy2_password='hy2-test', tu5_password='tuic-test', an_password='any-test', ws_path='/independent-test-path', ym_vl_re='www.apple.com', ym_vm_ws='www.bing.com', tlsyn='false', ipv='prefer_ipv4', private_key='AEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEEA', short_id='12345678', endip='162.159.192.1', v6='2606:4700:110:8abc::1', pvk='AEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEEA=', res='[1,2,3]')
        values['pvk'] = base64.b64encode(bytes(range(32))).decode()
        values['private_key'] = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
        for protocol in ('vmess_ws', 'hy2', 'tuic', 'an'):
            values['certificatec_' + protocol] = str(self.root / 'cert.pem').replace('\\', '/')
            values['certificatep_' + protocol] = str(self.root / 'private.key').replace('\\', '/')
        for name, template in templates:
            data = json.loads(string.Template(template).substitute(values))
            inbounds = data['inbounds']
            self.assertEqual(inbounds[1]['users'][0]['uuid'], values['vm_uuid'])
            self.assertNotIn(values['uuid'], inbounds[1]['transport']['path'])
            self.assertEqual(inbounds[3]['users'][0]['password'], values['tu5_password'])
            checker = os.environ.get('SING_BOX_LEGACY_CHECK' if name == 'sb10.json' else 'SING_BOX_CHECK')
            if checker:
                openssl = os.environ.get('OPENSSL', 'openssl')
                subprocess.run([openssl, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', str(self.root / 'private.key'), '-out', str(self.root / 'cert.pem'), '-days', '1', '-subj', '/CN=www.bing.com', '-addext', 'subjectAltName=DNS:www.bing.com'], check=True, capture_output=True)
                config = self.root / name
                config.write_text(json.dumps(data))
                check = subprocess.run([checker, 'check', '-D', str(self.root), '-c', str(config)], capture_output=True, text=True, timeout=60)
                self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_actual_client_template_branches(self):
        bash = os.environ.get('BASH_TEST') or shutil.which('bash')
        if not bash:
            self.skipTest('bash not installed')
        source = (ROOT / 'sb.sh').read_text(encoding='utf-8')
        function = 'sb_client(){' + source.split('sb_client(){', 1)[1].split('\ncfargo_ym(){', 1)[0]
        function = function.replace('/etc/s-box', self.root.as_posix())
        values = dict(an_ins='false', hy2_ins='false', tu5_ins='false', an_name='www.bing.com', hy2_name='www.bing.com', tu5_name='www.bing.com', vm_name='www.bing.com', vl_name='www.apple.com', an_port='16134', hy2_port='32695', tu5_port='41781', vm_port='29687', vl_port='25809', argo='test.trycloudflare.com', argogd='tunnel.example.com', cl_an_ip='127.0.0.1', cl_hy2_ip='127.0.0.1', cl_tu5_ip='127.0.0.1', hostname='test', public_key=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('='), sb_an_ip='127.0.0.1', sbnh='1.14', server_ipcl='127.0.0.1', short_id='12345678', tls='false', uuid='11111111-1111-4111-8111-111111111111', vmadd_argo='127.0.0.1', vmadd_local='127.0.0.1', ws_path='/test', cmhy2pt='', hy2_ports='', sbhy2pt='')
        (self.root / 'sb.json').write_text('{"inbounds": []}')
        for mode in range(4):
            with self.subTest(argo_mode=mode):
                processes = ('cloudflared tunnel run\n' if mode & 1 else '') + ('cloudflared tunnel --url http://localhost:29687\n' if mode & 2 else '')
                script = '\n'.join(k + '=' + shlex.quote(v) for k, v in values.items()) + '\n'
                script += 'ps(){ printf %s ' + shlex.quote(processes) + '; }; jq(){ case "$*" in *tls.enabled*) echo false;; *) echo 29687;; esac; };\n'
                script += function + '\nsb_client\n'
                result = subprocess.run([bash], input=script, text=True, capture_output=True, encoding='utf-8')
                self.assertEqual(result.returncode, 0, result.stderr)
                secure.trust_exports(self.root)
                data = secure.read_json(self.root / 'sbox.json')
                self.assertIn('outbounds', data)
                if os.environ.get('SING_BOX_CHECK'):
                    check = subprocess.run([os.environ['SING_BOX_CHECK'], 'check', '-c', str(self.root / 'sbox.json')], text=True, capture_output=True)
                    self.assertEqual(check.returncode, 0, check.stdout + check.stderr)


if __name__ == '__main__':
    unittest.main()
