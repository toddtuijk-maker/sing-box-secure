#!/usr/bin/env python3
"""Security helpers for the GPL-3.0 fork. No third-party Python dependencies."""
import argparse
import base64
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FILES = ('sbox.json', 'clmi.yaml', 'jhsub.txt', 'v2rayn.txt')


def subscription_files(root):
    # Old installations may not have refreshed exports yet; keep their three URLs working.
    return FILES if (root / 'v2rayn.txt').is_file() else FILES[:3]


def write_private(path, value):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            f.write(value)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(path):
    # Legacy templates contain standalone // comments, not inline comments.
    text = Path(path).read_text(encoding='utf-8')
    return json.loads(re.sub(r'^\s*//.*$', '', text, flags=re.M))


def pem_fingerprint(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def v2rayn_profiles(outbounds):
    """v2rayN ConfigVersion 4: embed CA material and explicitly select sing-box.

    The ordinary HY2 URI importer in 7.24.8 turns pinSHA256 into AllowInsecure;
    its sing-box builder then drops that pin. Use the internal format and Cert,
    never that fallback. This function is shared by VPS and portable exporters.
    """
    kinds = {'vmess': 1, 'vless': 5, 'hysteria2': 7, 'tuic': 8, 'anytls': 11}
    profiles = []
    for outbound in outbounds:
        kind = outbound['type']
        if kind in ('selector', 'urltest', 'direct', 'block', 'dns'):
            continue
        if kind not in kinds:
            raise ValueError('Unsupported v2rayN export protocol')
        host = outbound['server']
        try:
            ipaddress.ip_address(host)
        except ValueError:
            validate_domain(host)
        ports = outbound.get('server_ports') or []
        port = int(outbound.get('server_port') or (ports[0].split(':')[0] if ports else 0))
        if not 1 <= port <= 65535:
            raise ValueError('Invalid public port')
        profile = {'ConfigType': kinds[kind], 'CoreType': 24, 'ConfigVersion': 4,
                   'Remarks': outbound['tag'], 'Address': host, 'Port': port,
                   'Password': outbound['uuid'] if kind in ('vless', 'vmess') else outbound['password'],
                   'Network': 'raw', 'AllowInsecure': 'false', 'MuxEnabled': False}
        extra = {}
        if kind == 'vless':
            extra.update(Flow=outbound.get('flow', ''), VlessEncryption='none')
        elif kind == 'vmess':
            extra.update(AlterId=str(outbound.get('alter_id', 0)), VmessSecurity=outbound.get('security', 'auto'))
        elif kind == 'tuic':
            profile['Username'] = outbound['uuid']
            extra['CongestionControl'] = outbound.get('congestion_control', 'bbr')
        elif kind == 'hysteria2':
            extra.update(UpMbps=outbound.get('up_mbps', 0), DownMbps=outbound.get('down_mbps', 0))
            if ports:
                extra['Ports'] = ','.join(ports)
            if outbound.get('obfs'):
                if outbound['obfs']['type'] != 'salamander':
                    raise ValueError('Unsupported HY2 obfuscation')
                extra['SalamanderPass'] = outbound['obfs']['password']
        profile['ProtoExtraObj'] = extra
        tls = outbound.get('tls', {})
        if tls.get('enabled'):
            if tls.get('insecure'):
                raise ValueError('Refusing insecure TLS export')
            profile.update(StreamSecurity='tls', Sni=tls.get('server_name', host), Alpn=','.join(tls.get('alpn') or []))
            if tls.get('utls', {}).get('enabled'):
                profile['Fingerprint'] = tls['utls']['fingerprint']
            if tls.get('reality', {}).get('enabled'):
                profile.update(StreamSecurity='reality', PublicKey=tls['reality']['public_key'], ShortId=tls['reality'].get('short_id', ''))
            else:
                pem = tls.get('certificate', '')
                if isinstance(pem, list):
                    pem = '\n'.join(pem)
                if pem:
                    pattern = r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----'
                    certificates = re.findall(pattern, pem)
                    if not certificates or re.sub(pattern, '', pem).strip():
                        raise ValueError('Export requires PEM certificates only')
                    for cert in certificates:
                        pem_fingerprint(cert)
                    profile['Cert'] = '\n'.join(certificates) + '\n'
                elif tls.get('certificate_path'):
                    raise ValueError('Embed certificate before exporting')
        transport = outbound.get('transport', {})
        if transport:
            network = transport['type']
            if network not in ('ws', 'grpc', 'httpupgrade'):
                raise ValueError('Unsupported v2rayN transport')
            profile['Network'] = network
            if network == 'grpc':
                profile['TransportExtraObj'] = {'GrpcServiceName': transport.get('service_name', '')}
            else:
                headers = transport.get('headers', {})
                host_header = headers.get('Host', headers.get('host', ''))
                if isinstance(host_header, list):
                    host_header = ','.join(host_header)
                profile['TransportExtraObj'] = {'Path': transport.get('path', '/'), 'Host': host_header}
        profiles.append((kind, profile))
    if not profiles:
        raise ValueError('No supported proxy nodes to export')
    return profiles


def export_v2rayn(root, client):
    links = []
    for kind, profile in v2rayn_profiles(client['outbounds']):
        payload = base64.urlsafe_b64encode(json.dumps(profile, ensure_ascii=False, separators=(',', ':')).encode()).decode().rstrip('=')
        links.append('v2rayn://' + kind + '/' + payload)
    write_private(root / 'v2rayn.txt', '\n'.join(links) + '\n')


def trust_exports(root):
    """Trust exactly the self-signed certificate, never arbitrary certificates."""
    server = read_json(root / 'sb.json')
    users = {item['type']: item.get('users', [{}])[0] for item in server['inbounds']}
    trust = {}
    for inbound in server['inbounds']:
        tls = inbound.get('tls', {})
        if tls.get('enabled') and not tls.get('reality', {}).get('enabled'):
            cert = tls.get('certificate_path')
            if cert and Path(cert).name == 'cert.pem':
                pem = Path(cert).read_text(encoding='utf-8')
                trust[inbound['type']] = (pem, pem_fingerprint(pem))
    client = read_json(root / 'sbox.json')
    for outbound in client.get('outbounds', []):
        credentials = users.get(outbound.get('type'), {})
        for key in ('uuid', 'password'):
            if key in credentials:
                outbound[key] = credentials[key]
        tls = outbound.get('tls')
        if tls:
            tls['insecure'] = False
            if outbound['type'] in trust and tls.get('enabled'):
                tls['certificate'] = trust[outbound['type']][0].splitlines()
    write_private(root / 'sbox.json', json.dumps(client, ensure_ascii=False, indent=2) + '\n')
    export_v2rayn(root, client)
    yaml = (root / 'clmi.yaml').read_text(encoding='utf-8')
    # Generated template has one block per top-level "- name:". Do not parse arbitrary YAML.
    blocks = re.split(r'(?=^- name:)', yaml, flags=re.M)
    for index, block in enumerate(blocks):
        match = re.search(r'^  type: ([a-z0-9]+)\s*$', block, re.M)
        block = re.sub(r'(skip-cert-verify:)\s*true', r'\1 false', block)
        if match:
            for key, value in users.get(match[1], {}).items():
                if key in ('uuid', 'password'):
                    block = re.sub(r'^  ' + key + r':[^\n]*', '  ' + key + ': ' + json.dumps(value), block, flags=re.M)
        if match and match[1] in trust:
            if match[1] != 'vmess' or re.search(r'^  tls: true\s*$', block, re.M):
                block = re.sub(r'^  fingerprint:.*\n', '', block, flags=re.M)
                block = block.replace(match[0], match[0] + '\n  fingerprint: "' + trust[match[1]][1] + '"', 1)
        blocks[index] = block
    write_private(root / 'clmi.yaml', ''.join(blocks))
    # Subscription data must be read-only to all but the administrator.
    for name in FILES:
        if (root / name).exists():
            os.chmod(root / name, 0o600)


def change_identity(root, path_value=None):
    """Preserve template line layout used by legacy port/routing editors."""
    originals = {p: p.read_text(encoding='utf-8') for p in (root / 'sb10.json', root / 'sb11.json', root / 'sb.json') if p.exists()}
    active = read_json(root / 'sb.json')
    replacements = {}
    if path_value is not None:
        value = path_value or '/' + secrets.token_hex(24)
        if not re.fullmatch(r'/[A-Za-z0-9/_-]{1,128}', value):
            raise ValueError('Invalid WebSocket path')
        credentials = {str(v) for inbound in active['inbounds'] for user in inbound.get('users', []) for k, v in user.items() if k in ('uuid', 'password')}
        if any(secret in value for secret in credentials):
            raise ValueError('Path must not contain a credential')
        old = next(x['transport']['path'] for x in active['inbounds'] if x['type'] == 'vmess')
        replacements[old] = value
    else:
        owners = {}
        for inbound in [item for path in originals for item in read_json(path)['inbounds']]:
            for user in inbound.get('users', []):
                for key in ('uuid', 'password'):
                    if key not in user:
                        continue
                    owner = (inbound['type'], key)
                    if user[key] in replacements:
                        if owners[user[key]] != owner:
                            raise ValueError('Legacy shared credentials: manual migration required, no files changed')
                        continue
                    owners[user[key]] = owner
                    replacements[user[key]] = str(uuid.uuid4()) if key == 'uuid' else secrets.token_hex(24)
    rendered = {}
    for path, source in originals.items():
        for old, new in replacements.items():
            source = source.replace(json.dumps(old), json.dumps(new))
        json.loads(re.sub(r'^\s*//.*$', '', source, flags=re.M))
        rendered[path] = source
    # Validate active config before replacing any live file.
    fd, candidate = tempfile.mkstemp(suffix='.json', dir=root)
    os.close(fd)
    try:
        write_private(candidate, rendered[root / 'sb.json'])
        subprocess.run([str(root / 'sing-box'), 'check', '-D', str(root), '-c', candidate], check=True)
    finally:
        os.unlink(candidate)
    try:
        for path, source in rendered.items():
            write_private(path, source)
    except Exception:
        for path, source in originals.items():
            write_private(path, source)
        raise
    print('配置已更新；请重新导入订阅，旧凭据不再有效。')


def validate_token(token):
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', token):
        raise ValueError('Token must contain 32-128 URL-safe random characters')
    return token


def validate_domain(domain):
    if not 1 <= len(domain) <= 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in domain.split('.')):
        raise ValueError('Invalid domain')
    return domain


def sub_setup(root):
    domain = validate_domain(input('订阅域名（证书必须覆盖该域名）: ').strip())
    port = int(input('HTTPS 订阅端口 [8443]: ').strip() or '8443')
    if not 1024 <= port <= 65535:
        raise ValueError('Subscription port must be 1024-65535')
    cert = Path(input('已签发的 fullchain PEM 绝对路径: ').strip()).resolve(strict=True)
    key = Path(input('对应私钥 PEM 绝对路径: ').strip()).resolve(strict=True)
    # Check key correspondence and certificate hostname before replacing settings.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    result = subprocess.run(['openssl', 'x509', '-in', str(cert), '-checkhost', domain, '-noout'], check=True, capture_output=True, text=True)
    if not result.stdout.strip().endswith(' does match certificate'):
        raise ValueError('Certificate does not cover subscription domain')
    subprocess.run(['openssl', 'x509', '-in', str(cert), '-checkend', '86400', '-noout'], check=True)
    print('需使用客户端信任的证书；不关闭证书验证。请在云防火墙/主机防火墙放行该 TCP 端口。')
    token = secrets.token_urlsafe(32)
    # Paths, not private-key contents, in config. Serve reads certs before dropping UID.
    write_private(root / 'subscription.json', json.dumps(dict(domain=domain, port=port, token=token, cert=str(cert), key=str(key))))


def sub_urls(root):
    path = root / 'subscription.json'
    if not path.exists():
        return
    cfg = read_json(path)
    for name in subscription_files(root):
        print('https://{}:{}/{}/{}'.format(cfg['domain'], cfg['port'], cfg['token'], name))


def make_handler(token, payloads):
    validate_token(token)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log bearer URLs, client IPs or configuration contents.

        def do_GET(self):
            parts = urllib.parse.urlsplit(self.path)
            segments = parts.path.split('/')
            valid = (not parts.query and len(segments) == 3 and
                     hmac.compare_digest(segments[1].encode(), token.encode()) and segments[2] in payloads)
            if not valid:
                self.send_error(404)
                return
            body = payloads[segments[2]]
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def serve(root):
    cfg = read_json(root / 'subscription.json')
    payloads = {name: (root / name).read_bytes() for name in subscription_files(root)}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cfg['cert'], cfg['key'])

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if socket.has_dualstack_ipv6() else socket.AF_INET
        daemon_threads = True
        slots = threading.BoundedSemaphore(32)
        def server_bind(self):
            if self.address_family == socket.AF_INET6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()
        def get_request(self):
            sock, addr = super().get_request()
            sock.settimeout(10)
            return sock, addr
        def process_request(self, sock, addr):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(sock)
                return
            try:
                super().process_request(sock, addr)
            except Exception:
                self.slots.release()
                raise
        def process_request_thread(self, sock, addr):
            try:
                tls_sock = context.wrap_socket(sock, server_side=True)
                super().process_request_thread(tls_sock, addr)
            except (OSError, ssl.SSLError):
                sock.close()
            finally:
                self.slots.release()
        def handle_error(self, request, client_address):
            pass  # Do not let public scanners flood logs or reveal bearer paths.

    bind = '::' if Server.address_family == socket.AF_INET6 else '0.0.0.0'
    server = Server((bind, int(cfg['port'])), make_handler(cfg['token'], payloads))
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        import pwd
        account = pwd.getpwnam('nobody')
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    server.serve_forever()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'Redirect refused', headers, fp)


def api(path, token, data=None, method=None):
    req = urllib.request.Request('https://gitlab.com/api/v4/' + path,
                                 data=None if data is None else json.dumps(data).encode(),
                                 headers={'PRIVATE-TOKEN': token, 'Content-Type': 'application/json'},
                                 method=method)
    with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
        return json.load(response)


def register_warp(root):
    """Never fall back to someone else's shared WireGuard key."""
    private = subprocess.run(['openssl', 'genpkey', '-algorithm', 'X25519'], capture_output=True, check=True).stdout
    der_private = subprocess.run(['openssl', 'pkey', '-outform', 'DER'], input=private, capture_output=True, check=True).stdout
    der_public = subprocess.run(['openssl', 'pkey', '-pubout', '-outform', 'DER'], input=private, capture_output=True, check=True).stdout
    if len(der_private) < 32 or len(der_public) < 32:
        raise ValueError('Invalid generated key')
    from datetime import datetime, timezone
    request = urllib.request.Request('https://api.cloudflareclient.com/v0a2158/reg',
        data=json.dumps({'key': base64.b64encode(der_public[-32:]).decode(), 'tos': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')}).encode(),
        headers={'CF-Client-Version': 'a-7.21-0721', 'Content-Type': 'application/json'}, method='POST')
    with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
        data = json.loads(response.read(1048576))
    cfg = data['config']
    ipv6 = str(ipaddress.IPv6Address(cfg['interface']['addresses']['v6']))
    reserved = list(base64.b64decode(cfg['client_id'], validate=True))
    if len(reserved) != 3:
        raise ValueError('Invalid WireGuard reserved bytes')
    write_private(root / 'warp.json', json.dumps({'private_key': base64.b64encode(der_private[-32:]).decode(), 'ipv6': ipv6, 'reserved': reserved}))


def gitlab_setup(root):
    project = input('GitLab 项目路径（namespace/project）: ').strip()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+', project):
        raise ValueError('Invalid project path')
    branch = input('订阅分支 [main]: ').strip() or 'main'
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]{0,100}', branch) or '..' in branch:
        raise ValueError('Invalid branch')
    writer = getpass.getpass('服务端写入 Token（api，留在服务器）: ')
    reader = getpass.getpass('独立只读 Token（仅 read_api，将进入订阅 URL）: ')
    if hmac.compare_digest(writer, reader):
        raise ValueError('Writer and reader tokens must be different')
    scopes = set(api('personal_access_tokens/self', reader).get('scopes', []))
    if scopes != {'read_api'}:
        raise ValueError('Reader must have exactly read_api scope; broad/writable tokens refused')
    encoded = urllib.parse.quote(project, safe='')
    if api('projects/' + encoded, writer).get('visibility') != 'private':
        raise ValueError('Subscription repository must be private')
    api('projects/' + encoded, reader)
    write_private(root / 'gitlab-secure.json', json.dumps(dict(project=project, branch=branch, writer=writer, reader=reader)))
    gitlab_publish(root)


def gitlab_publish(root):
    path = root / 'gitlab-secure.json'
    if not path.exists():
        print('尚未配置安全 GitLab 订阅。旧版写令牌订阅不再自动发布，请重新配置并撤销旧令牌。')
        return
    cfg = read_json(path)
    project = urllib.parse.quote(cfg['project'], safe='')
    prefix = 'projects/' + project
    if api(prefix, cfg['writer']).get('visibility') != 'private':
        raise ValueError('Repository is no longer private; publication refused')
    scopes = set(api('personal_access_tokens/self', cfg['reader']).get('scopes', []))
    if scopes != {'read_api'}:
        raise ValueError('Read token scope changed; publication refused')
    actions = []
    for name in subscription_files(root):
        try:
            api(prefix + '/repository/files/' + name + '?ref=' + urllib.parse.quote(cfg['branch'], safe=''), cfg['writer'])
            action = 'update'
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
            action = 'create'
        actions.append(dict(action=action, file_path=name, content=(root / name).read_text(encoding='utf-8')))
    api(prefix + '/repository/commits', cfg['writer'], dict(branch=cfg['branch'], commit_message='Update private subscription', actions=actions), 'POST')
    for name, output in zip(FILES, ('sing_box_gitlab.txt', 'clash_meta_gitlab.txt', 'jh_sub_gitlab.txt', 'v2rayn_gitlab.txt')):
        if name not in subscription_files(root):
            continue
        url = 'https://gitlab.com/api/v4/' + prefix + '/repository/files/' + name + '/raw?' + urllib.parse.urlencode({'ref': cfg['branch'], 'private_token': cfg['reader']})
        write_private(root / output, url + '\n')
    print('订阅已更新，写令牌未写入订阅链接。只读令牌仍是秘密，不要公开分享。')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('trust', 'rotate', 'path', 'sub-setup', 'sub-urls', 'serve', 'gitlab-setup', 'gitlab-publish', 'warp-register'))
    parser.add_argument('--root', type=Path, default=Path('/etc/s-box'))
    parser.add_argument('--value', default='')
    args = parser.parse_args()
    os.umask(0o077)
    functions = {'trust': trust_exports, 'rotate': change_identity,
                 'path': lambda root: change_identity(root, args.value),
                 'sub-setup': sub_setup, 'sub-urls': sub_urls,
                 'serve': serve, 'gitlab-setup': gitlab_setup, 'gitlab-publish': gitlab_publish, 'warp-register': register_warp}
    try:
        functions[args.command](args.root)
    except Exception as exc:
        # URL/request reprs can contain secrets. Emit only exception class.
        print('操作未完成：' + type(exc).__name__ + '。请检查参数、证书、权限及网络；未关闭任何安全校验。', file=__import__('sys').stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
