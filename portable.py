#!/usr/bin/env python3
"""Rootless/no-init Linux container runner; stdlib only, GPL-3.0.

No package installation, firewall changes, cron, systemd, TUN or host networking.
Server traffic needs only ordinary TCP/UDP sockets. Persist --data across restarts.
"""
import argparse
import base64
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time
import urllib.parse
import uuid

from secure import pem_fingerprint, read_json, validate_domain, write_private

DEFAULT_PORTS = {'vless': 25809, 'vmess': 29687, 'hysteria2': 32695, 'tuic': 41781, 'anytls': 16134}


def parse_host(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return validate_domain(value)


def initial_state(host, environment):
    ports = {kind: int(environment.get(kind.upper() + '_PORT', default)) for kind, default in DEFAULT_PORTS.items()}
    if environment.get('VLESS_WS_PORT'):
        ports['vless-ws'] = int(environment['VLESS_WS_PORT'])
    if any(not 1024 <= port <= 65535 for port in ports.values()) or len(set(ports.values())) != len(ports):
        raise ValueError('Distinct unprivileged ports in 1024-65535 required')
    public_ports = {kind: int(environment.get(kind.upper().replace('-', '_') + '_PUBLIC_PORT', port))
                    for kind, port in ports.items()}
    if any(not 1 <= port <= 65535 for port in public_ports.values()) or len(set(public_ports.values())) != len(public_ports):
        raise ValueError('Distinct public ports in 1-65535 required')
    return {'host': parse_host(host), 'ports': ports, 'public_ports': public_ports,
            'vless_uuid': str(uuid.uuid4()), 'vmess_uuid': str(uuid.uuid4()), 'tuic_uuid': str(uuid.uuid4()),
            'vless_ws_uuid': str(uuid.uuid4()), 'vless_ws_path': '/' + secrets.token_hex(24),
            'hysteria2_password': secrets.token_urlsafe(32), 'tuic_password': secrets.token_urlsafe(32),
            'anytls_password': secrets.token_urlsafe(32), 'path': '/' + secrets.token_hex(24),
            'short_id': secrets.token_hex(8), 'reality_sni': validate_domain(environment.get('REALITY_SNI', 'www.apple.com')),
            'vmess_tls': environment.get('VMESS_TLS', '1') == '1'}


def server_config(state, root):
    tls = {'enabled': True, 'server_name': state['host'], 'certificate_path': str(root / 'cert.pem'), 'key_path': str(root / 'private.key')}
    inbounds = []
    for kind, port in state['ports'].items():
        item = {'type': kind, 'tag': kind + '-in', 'listen': '::', 'listen_port': port}
        if kind == 'vless-ws':
            item['type'] = 'vless'
            item['users'] = [{'uuid': state['vless_ws_uuid']}]
            item['transport'] = {'type': 'ws', 'path': state['vless_ws_path']}
            item['tls'] = {**tls}
        elif kind == 'vless':
            item['users'] = [{'uuid': state['vless_uuid'], 'flow': 'xtls-rprx-vision'}]
            item['tls'] = {'enabled': True, 'server_name': state['reality_sni'], 'reality': {
                'enabled': True, 'handshake': {'server': state['reality_sni'], 'server_port': 443},
                'private_key': state['private_key'], 'short_id': [state['short_id']]}}
        elif kind == 'vmess':
            item['users'] = [{'uuid': state['vmess_uuid']}]
            item['transport'] = {'type': 'ws', 'path': state['path']}
            item['tls'] = {**tls, 'enabled': state['vmess_tls']}
        elif kind == 'tuic':
            item['users'] = [{'uuid': state['tuic_uuid'], 'password': state['tuic_password']}]
            item['congestion_control'] = 'bbr'
            item['tls'] = {**tls, 'alpn': ['h3']}
        else:
            item['users'] = [{'password': state[kind + '_password']}]
            item['tls'] = {**tls}
            if kind == 'hysteria2':
                item['tls']['alpn'] = ['h3']
        inbounds.append(item)
    return {'log': {'level': 'warn', 'timestamp': True}, 'inbounds': inbounds,
            'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}


def export_clients(root, state, config):
    """Generate pinned full profiles; generic URI formats cannot encode every trust option."""
    pem = (root / 'cert.pem').read_text()
    fingerprint = pem_fingerprint(pem)
    host = state['host']
    outbounds, proxies, links = [], [], []
    uri_host = '[' + host + ']' if ':' in host else host
    for inbound in config['inbounds']:
        kind = inbound['type']
        tag = inbound['tag'].removesuffix('-in')
        credentials = inbound['users'][0]
        port = state.get('public_ports', {}).get(tag, inbound['listen_port'])
        outbound = {'type': kind, 'tag': tag, 'server': host, 'server_port': port, **credentials}
        proxy = {'name': tag, 'type': kind, 'server': host, 'port': port, 'udp': True, **credentials}
        if kind == 'vless' and 'reality' in inbound['tls']:
            tls = inbound['tls']
            outbound['tls'] = {'enabled': True, 'server_name': tls['server_name'], 'utls': {'enabled': True, 'fingerprint': 'chrome'},
                'reality': {'enabled': True, 'public_key': state['public_key'], 'short_id': tls['reality']['short_id'][0]}}
            proxy.update({'tls': True, 'servername': tls['server_name'], 'client-fingerprint': 'chrome',
                'reality-opts': {'public-key': state['public_key'], 'short-id': tls['reality']['short_id'][0]}})
            query = urllib.parse.urlencode({'encryption': 'none', 'flow': 'xtls-rprx-vision', 'security': 'reality', 'sni': tls['server_name'], 'fp': 'chrome', 'pbk': state['public_key'], 'sid': tls['reality']['short_id'][0], 'type': 'tcp'})
            links.append('vless://' + credentials['uuid'] + '@' + uri_host + ':' + str(port) + '?' + query + '#vless')
        else:
            enabled = inbound['tls']['enabled']
            outbound['tls'] = {'enabled': enabled, 'server_name': host, 'insecure': False, 'certificate': pem.splitlines()}
            proxy.update({'sni': host, 'skip-cert-verify': False, 'fingerprint': fingerprint})
            if kind == 'vless':
                outbound['transport'] = inbound['transport']
                proxy.update({'tls': True, 'servername': host, 'network': 'ws', 'ws-opts': {'path': inbound['transport']['path']}})
                query = urllib.parse.urlencode({'encryption': 'none', 'security': 'tls', 'sni': host, 'type': 'ws', 'path': inbound['transport']['path']})
                links.append('vless://' + credentials['uuid'] + '@' + uri_host + ':' + str(port) + '?' + query + '#vless-ws')
            elif kind == 'vmess':
                outbound['security'] = 'auto'
                outbound['transport'] = inbound['transport']
                proxy.update({'tls': enabled, 'servername': host, 'alterId': 0, 'cipher': 'auto', 'network': 'ws', 'ws-opts': {'path': inbound['transport']['path']}})
                vm = {'v': '2', 'ps': 'vmess', 'add': host, 'port': str(port), 'id': credentials['uuid'], 'aid': '0', 'net': 'ws', 'path': inbound['transport']['path'], 'host': host, 'tls': 'tls' if enabled else '', 'sni': host, 'type': 'none'}
                links.append('vmess://' + base64.b64encode(json.dumps(vm).encode()).decode())
            elif kind == 'hysteria2':
                query = urllib.parse.urlencode({'sni': host, 'insecure': '0', 'pinSHA256': fingerprint})
                links.append('hysteria2://' + credentials['password'] + '@' + uri_host + ':' + str(port) + '/?' + query + '#hysteria2')
            elif kind == 'tuic':
                outbound['tls']['alpn'] = ['h3']
                outbound['congestion_control'] = 'bbr'
                proxy['alpn'] = ['h3']
                proxy['congestion-controller'] = 'bbr'
                links.append('tuic://' + credentials['uuid'] + ':' + credentials['password'] + '@' + uri_host + ':' + str(port) + '?sni=' + host + '&insecure=0&alpn=h3#tuic')
            elif kind == 'anytls':
                links.append('anytls://' + credentials['password'] + '@' + uri_host + ':' + str(port) + '?sni=' + host + '&insecure=0#anytls')
        outbounds.append(outbound)
        proxies.append(proxy)
    tags = [item['tag'] for item in outbounds]
    client = {'log': {'level': 'warn'}, 'dns': {'servers': [{'type': 'udp', 'tag': 'bootstrap', 'server': '223.5.5.5'}, {'type': 'https', 'tag': 'remote', 'server': '1.1.1.1', 'detour': 'proxy'}], 'final': 'remote'},
        'inbounds': [{'type': 'tun', 'address': ['172.19.0.1/30'], 'auto_route': True, 'strict_route': True, 'stack': 'gvisor'}],
        'outbounds': [{'type': 'selector', 'tag': 'proxy', 'outbounds': tags, 'default': 'vless'}, *outbounds, {'type': 'direct', 'tag': 'direct'}],
        'route': {'auto_detect_interface': True, 'default_domain_resolver': 'bootstrap', 'rules': [{'action': 'sniff'}, {'protocol': 'dns', 'action': 'hijack-dns'}, {'ip_is_private': True, 'outbound': 'direct'}], 'final': 'proxy'}}
    mihomo = {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning', 'proxies': proxies,
        'proxy-groups': [{'name': 'proxy', 'type': 'select', 'proxies': tags}], 'rules': ['MATCH,proxy']}
    write_private(root / 'sbox.json', json.dumps(client, indent=2) + '\n')
    # JSON is a YAML subset; avoids a dependency and ambiguous YAML quoting.
    write_private(root / 'clmi.yaml', json.dumps(mihomo, indent=2) + '\n')
    write_private(root / 'jhsub.txt', base64.b64encode(('\n'.join(links) + '\n').encode()).decode() + '\n')
    write_private(root / 'IMPORT-NOTES.txt', 'Prefer the pinned sbox.json / clmi.yaml profiles. ALL self-signed TLS URI imports (including Hysteria2 with pinSHA256) require manual certificate trust; do not enable insecure verification. VMess without TLS should be placed behind a trusted TLS reverse proxy. Do not publish this directory.\n')


def initialize(root, binary, host):
    state_file = root / 'portable-state.json'
    if state_file.exists():
        state = read_json(state_file)
        config = read_json(root / 'sb.json')
    else:
        state = initial_state(host, os.environ)
        keys = subprocess.run([binary, 'generate', 'reality-keypair'], check=True, capture_output=True, text=True).stdout
        for label, name in [('PrivateKey', 'private_key'), ('PublicKey', 'public_key')]:
            match = re.search(label + r':\s*([A-Za-z0-9_-]+)', keys)
            if not match:
                raise ValueError('Invalid Reality key output')
            state[name] = match[1]
        cert, key = root / 'cert.pem', root / 'private.key'
        if cert.exists() != key.exists():
            raise ValueError('Supply BOTH cert.pem and private.key, or neither')
        if not cert.exists():
            try:
                ipaddress.ip_address(state['host'])
                san = 'IP:' + state['host']
            except ValueError:
                san = 'DNS:' + state['host']
            subprocess.run([os.environ.get('OPENSSL', 'openssl'), 'req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '365', '-keyout', str(key), '-out', str(cert), '-subj', '/CN=' + state['host'], '-addext', 'subjectAltName=' + san, '-addext', 'basicConstraints=critical,CA:TRUE'], check=True, capture_output=True)
        config = server_config(state, root)
        write_private(root / 'sb.json', json.dumps(config, indent=2) + '\n')
        write_private(state_file, json.dumps(state))
    subprocess.run([binary, 'check', '-D', str(root), '-c', str(root / 'sb.json')], check=True)
    export_clients(root, state, config)


def supervise(root, binary, daily_hour=3):
    stopping = False
    def on_signal(signum, frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    def start():
        proc = subprocess.Popen([binary, 'run', '-D', str(root), '-c', str(root / 'sb.json')])
        write_private(root / 'sing-box.pid', str(proc.pid))
        return proc
    def stop(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    process = start()
    last_day = datetime.now().date() if datetime.now().hour >= daily_hour else None
    try:
        while not stopping:
            code = process.poll()
            if code is not None:
                return code or 1  # Container restart policy handles unexpected exits.
            now = datetime.now()
            if now.hour >= daily_hour and now.date() != last_day:
                last_day = now.date()
                valid = subprocess.run([binary, 'check', '-D', str(root), '-c', str(root / 'sb.json')]).returncode == 0
                if valid:
                    print('Scheduled sing-box restart (local timezone).', flush=True)
                    stop(process)
                    process = start()
            time.sleep(0.5)
    finally:
        stop(process)
        (root / 'sing-box.pid').unlink(missing_ok=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default=os.environ.get('SING_BOX_BINARY', '/usr/local/bin/sing-box'))
    parser.add_argument('--data', type=Path, default=Path(os.environ.get('SB_DATA_DIR', './data')))
    parser.add_argument('--host', default=os.environ.get('PUBLIC_HOST', ''))
    parser.add_argument('--init-only', action='store_true')
    parser.add_argument('--healthcheck', action='store_true', help='Local process/TCP listeners only; not an Internet reachability test')
    parser.add_argument('--restart-hour', type=int, choices=range(24), default=3)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.data.resolve()
    if args.healthcheck:
        import socket
        os.kill(int((root / 'sing-box.pid').read_text()), 0)
        for inbound in read_json(root / 'sb.json')['inbounds']:
            if inbound['type'] not in ('hysteria2', 'tuic'):
                with socket.create_connection(('127.0.0.1', inbound['listen_port']), timeout=2):
                    pass
        return
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    # Linux advisory lock prevents competing supervisors from sharing credentials/config.
    if sys.platform == 'linux':
        import fcntl
        lock = open(root / '.runtime.lock', 'a')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    binary = str(Path(args.binary).resolve(strict=True))
    initialize(root, binary, args.host)
    print('Configuration ready in ' + str(root) + '; secrets are not printed.', flush=True)
    if not args.init_only:
        raise SystemExit(supervise(root, binary, args.restart_hour))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as exc:
        print('Startup failed: ' + type(exc).__name__ + '. Check config, data permissions, binary and port mappings.', file=sys.stderr)
        raise SystemExit(1)
