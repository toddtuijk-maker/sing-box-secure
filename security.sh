#!/usr/bin/env bash
# Security hardening, 2026-09-23. GPL-3.0; see NOTICE and LICENSE.
# Sourced by sb.sh; no side effects on import.
secure_qr() {
    if command -v qrencode >/dev/null; then
        command qrencode -o - -t ANSIUTF8 "$1"
    else
        printf '%s\n' '二维码工具未安装；上方文本链接仍可导入。可用系统包管理器安装 qrencode。'
    fi
}
secure_download() {
    local url=$1 destination=$2 digest=$3 tmp
    [[ $url == https://* && $digest =~ ^[a-fA-F0-9]{64}$ ]] || return 1
    tmp=$(mktemp "${destination}.download.XXXXXX") || return 1
    if curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --retry 2 "$url" -o "$tmp" &&
       printf '%s  %s\n' "$digest" "$tmp" | sha256sum --check --status; then
        chmod 600 "$tmp" && mv -f -- "$tmp" "$destination"
    else
        rm -f -- "$tmp"
        printf '%s\n' 'Download/checksum verification failed; installed file unchanged.' >&2
        return 1
    fi
}

secure_release() {
    local repo=$1 tag=$2 asset=$3 dest=$4 metadata digest url
    [[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && $tag =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
    metadata=$(curl -fsSL --proto '=https' --proto-redir '=https' --max-time 30 "https://api.github.com/repos/$repo/releases/tags/$tag") || return 1
    digest=$(printf '%s' "$metadata" | jq -er --arg name "$asset" '.assets[] | select(.name==$name) | .digest | select(startswith("sha256:"))') || {
        echo 'Release has no SHA-256 digest; refusing an unverified binary.' >&2; return 1;
    }
    url=$(printf '%s' "$metadata" | jq -er --arg name "$asset" '.assets[] | select(.name==$name) | .browser_download_url') || return 1
    [[ $url == "https://github.com/$repo/releases/download/$tag/$asset" ]] || return 1
    secure_download "$url" "$dest" "${digest#sha256:}"
}

secure_core() {
    local version=$1 stage candidate config digest asset
    [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$ ]] || return 1
    stage=$(mktemp -d /etc/s-box/.core.XXXXXX) || return 1
    asset="sing-box-$version-linux-$cpu.tar.gz"
    if [[ $version == 1.10.7 ]]; then
        # Historical release had no GitHub digest. Pinned HTTPS snapshot, 2026-09-23.
        case $cpu in
            amd64) digest=1951a0785c8b4e1e21e0640227a49528ca772aec3d680061652e3d6b687e00fe;;
            arm64) digest=15b43a0a50b4e6962aca819d4f3055aaac75ca7481350d4aaebe93ed06b7af49;;
            armv7) digest=691882d609c877f97bc8d6f8645b97d12de81b6f7b89651df66489ef11b4c5d0;;
            *) rmdir "$stage"; return 1;;
        esac
        secure_download "https://github.com/SagerNet/sing-box/releases/download/v$version/$asset" "$stage/core.tar.gz" "$digest" || { rm -rf -- "$stage"; return 1; }
    elif [[ $version == 1.14.1 ]]; then
        case $cpu in
            amd64) digest=12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f;;
            arm64) digest=6060b42fa84c5dcaeae1799af7f61b0f1ae4855d9d5ddc9e02baba17154b3ae2;;
            armv7) digest=f2c8af2e3576f40f8ab0d06e1d44840e4eb6bcf410ba8d42381781cb0d6fe41b;;
            *) rmdir "$stage"; return 1;;
        esac
        secure_download "https://github.com/SagerNet/sing-box/releases/download/v$version/$asset" "$stage/core.tar.gz" "$digest" || { rm -rf -- "$stage"; return 1; }
    else
        secure_release SagerNet/sing-box "v$version" "$asset" "$stage/core.tar.gz" || { rm -rf -- "$stage"; return 1; }
    fi
    candidate="$stage/sing-box"
    tar xzf "$stage/core.tar.gz" -O "sing-box-$version-linux-$cpu/sing-box" > "$candidate" || { rm -rf -- "$stage"; return 1; }
    chmod 700 "$candidate"
    [[ $version == 1.10.* ]] && config=/etc/s-box/sb10.json || config=/etc/s-box/sb11.json
    if [[ -s $config ]] && ! "$candidate" check -D /etc/s-box -c "$config"; then
        rm -rf -- "$stage"; echo 'New core rejected the configuration; current core retained.' >&2; return 1
    fi
    if [[ -f /etc/s-box/sing-box ]]; then
        cp -p /etc/s-box/sing-box /etc/s-box/sing-box.previous || { rm -rf -- "$stage"; return 1; }
    fi
    mv -f -- "$candidate" /etc/s-box/sing-box || { rm -rf -- "$stage"; return 1; }
    rm -rf -- "$stage"
    sbnh=$(/etc/s-box/sing-box version | awk '/version/{print $NF}' | cut -d . -f 1,2)
}

secure_install_manager() {
    local source=${1:-$SB_SOURCE_DIR} file stage
    for file in sb.sh security.sh secure.py; do [[ -s $source/$file ]] || return 1; done
    bash -n "$source/sb.sh" && bash -n "$source/security.sh" || return 1
    python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$source/secure.py" || return 1
    mkdir -p /etc/s-box
    chmod 700 /etc/s-box
    # Stage all files before replacing; never download mutable main as root.
    stage=$(mktemp -d /etc/s-box/.manager.XXXXXX) || return 1
    for file in sb.sh security.sh secure.py; do cp -- "$source/$file" "$stage/$file" || { rm -rf -- "$stage"; return 1; }; done
    for file in security.sh secure.py sb.sh; do
        install -m 600 "$stage/$file" "/etc/s-box/$file" || { rm -rf -- "$stage"; return 1; }
    done
    install -m 700 "$stage/sb.sh" /usr/bin/sb || { rm -rf -- "$stage"; return 1; }
    rm -rf -- "$stage"
    printf '%s\n' '2026.09.23-security-preview' > /etc/s-box/v
}

secure_cron_remove() {
    local cronfile
    cronfile=$(mktemp) || return 1
    crontab -l 2>/dev/null | awk '!/# sing-box-secure$/ && $0 != "0 1 * * * systemctl restart sing-box;rc-service sing-box restart"' > "$cronfile"
    crontab "$cronfile"; local rc=$?; rm -f -- "$cronfile"; return "$rc"
}

secure_cron_install() {
    secure_cron_remove || return 1
    local cronfile
    cronfile=$(mktemp) || return 1
    crontab -l 2>/dev/null > "$cronfile"
    printf '%s\n' '0 3 * * * /etc/s-box/sing-box check -D /etc/s-box -c /etc/s-box/sb.json >/dev/null 2>&1 && { if command -v systemctl >/dev/null 2>&1; then systemctl restart sing-box; else rc-service sing-box restart; fi; } # sing-box-secure' >> "$cronfile"
    crontab "$cronfile"; local rc=$?; rm -f -- "$cronfile"; return "$rc"
}

secure_subscription_service() {
    if command -v systemctl >/dev/null 2>&1; then
        cat > /etc/systemd/system/sing-box-secure-sub.service <<'UNIT'
[Unit]
Description=HTTPS subscription for sing-box-secure
After=network.target
[Service]
ExecStart=/usr/bin/python3 /etc/s-box/secure.py serve
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload && systemctl enable sing-box-secure-sub && systemctl restart sing-box-secure-sub
    else
        cat > /etc/init.d/sing-box-secure-sub <<'UNIT'
#!/sbin/openrc-run
description="HTTPS subscription for sing-box-secure"
command="/usr/bin/python3"
command_args="/etc/s-box/secure.py serve"
supervisor="supervise-daemon"
respawn_delay=5
depend() { need net; }
UNIT
        chmod 700 /etc/init.d/sing-box-secure-sub
        rc-update add sing-box-secure-sub default && rc-service sing-box-secure-sub restart
    fi
}

secure_nat_cleanup() {
    local tool rule
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null || continue
        # Only our own chain. Never flush shared PREROUTING or foreign rules.
        while "$tool" -t nat -C PREROUTING -j SBSECURE 2>/dev/null; do "$tool" -t nat -D PREROUTING -j SBSECURE; done
        "$tool" -t nat -F SBSECURE 2>/dev/null || true
        "$tool" -t nat -X SBSECURE 2>/dev/null || true
    done
    if command -v systemctl >/dev/null; then systemctl disable sing-box-secure-nat 2>/dev/null || true;
    else rc-update del sing-box-secure-nat 2>/dev/null || true; fi
    rm -f /etc/systemd/system/sing-box-secure-nat.service /etc/init.d/sing-box-secure-nat
}

secure_nat_init() {
    local tool
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null || continue
        "$tool" -t nat -N SBSECURE 2>/dev/null || true
        "$tool" -t nat -C PREROUTING -j SBSECURE 2>/dev/null || "$tool" -t nat -A PREROUTING -j SBSECURE
    done
}

secure_warp_binary() {
    local digest stage
    case $cpu in
        amd64) digest=93c7c5d7cb2c82cef44de782ae030b5f8fdb15038e3e95662e451bce7d3ee531;;
        arm64) digest=4a8f0419e4b848b99017128d532bd760f6daa4a7b0bc9f59ff166105db5c6e33;;
        *) echo 'WARP-plus binary is only available for amd64/arm64.' >&2; return 1;;
    esac
    # Audited snapshot, byte-identical to Vwarp v2.2.2. See NOTICE.
    stage=$(mktemp /etc/s-box/.warp.XXXXXX) || return 1
    secure_download "https://raw.githubusercontent.com/yonggekkk/sing-box-yg/1efd60b1e1954a27b8e8be995200ca57012b1999/sbwpph_$cpu" "$stage" "$digest" || { rm -f -- "$stage"; return 1; }
    chmod 700 "$stage" && mv -f -- "$stage" /etc/s-box/sbwpph
}

secure_certificate() {
    local mode domain cert key stage
    echo '1: Import an existing trusted certificate; 2: Certbot HTTP-01; 3: Certbot manual DNS-01'
    read -r -p 'Choice [1]: ' mode
    read -r -p 'Certificate domain: ' domain
    [[ $domain =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && $domain != *..* ]] || return 1
    if [[ $mode == 2 || $mode == 3 ]]; then
        command -v certbot >/dev/null || { echo 'Install certbot from your OS package manager first; no remote script will be executed.'; return 1; }
        if [[ $mode == 2 ]]; then
            echo 'Port 80 must be reachable and free. Existing websites will not be stopped.'
            certbot certonly --standalone -d "$domain" || return 1
        else
            echo 'Manual DNS-01 requires you to publish TXT records; it has NO automatic renewal.'
            certbot certonly --manual --preferred-challenges dns -d "$domain" || return 1
        fi
        cert="/etc/letsencrypt/live/$domain/fullchain.pem"
        key="/etc/letsencrypt/live/$domain/privkey.pem"
    else
        read -r -p 'Fullchain PEM absolute path: ' cert
        read -r -p 'Private-key PEM absolute path: ' key
    fi
    [[ $cert == /* && $key == /* && -s $cert && -s $key ]] || return 1
    # Normalize without dereferencing live/ symlinks: Certbot retargets them on renewal.
    cert=$(realpath -s -- "$cert") || return 1
    key=$(realpath -s -- "$key") || return 1
    [[ $cert != /etc/s-box/certificates/cert.crt && $key != /etc/s-box/certificates/private.key ]] || return 1
    python3 - "$cert" "$key" <<'PY' || return 1
import ssl, sys
ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(sys.argv[1], sys.argv[2])
PY
    openssl x509 -in "$cert" -checkhost "$domain" -noout | grep -Fq ' does match certificate' || return 1
    openssl x509 -in "$cert" -checkend 86400 -noout || return 1
    mkdir -p /etc/s-box/certificates
    # Symlinks follow Certbot renewals. Import paths must remain present/readable.
    ln -sfn -- "$cert" /etc/s-box/certificates/cert.crt || return 1
    ln -sfn -- "$key" /etc/s-box/certificates/private.key || return 1
    printf '%s\n' "$domain" > /etc/s-box/certificates/ca.log
    echo 'Certificate selected. Reload sing-box after renewal; pinned self-signed clients must be re-exported after certificate rotation.'
}

secure_bbr() {
    local available
    modprobe tcp_bbr 2>/dev/null || true
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control) || return 1
    [[ " $available " == *' bbr '* ]] || { echo 'This kernel does not offer BBR; no kernel replacement performed.'; return 1; }
    printf '%s\n' 'net.core.default_qdisc=fq' 'net.ipv4.tcp_congestion_control=bbr' > /etc/sysctl.d/99-sing-box-secure-bbr.conf
    sysctl -p /etc/sysctl.d/99-sing-box-secure-bbr.conf
}

secure_argo_service() {
    local kind=$1 port=${2:-} service args
    [[ $kind == fixed || $kind == quick ]] || return 1
    service="sing-box-secure-argo-$kind"
    if [[ $kind == fixed ]]; then
        args='tunnel --no-autoupdate --edge-ip-version auto --protocol http2 run --token-file /etc/s-box/sbargotoken.log'
    else
        [[ $port =~ ^[0-9]{1,5}$ && $port -ge 1 && $port -le 65535 ]] || return 1
        args="tunnel --no-autoupdate --edge-ip-version auto --protocol http2 --loglevel warn --logfile /etc/s-box/argo.log --url http://localhost:$port"
        # Quick tunnel URLs are normally emitted at info level.
        args=${args/--loglevel warn/--loglevel info}
        : > /etc/s-box/argo.log
    fi
    if command -v systemctl >/dev/null; then
        cat > "/etc/systemd/system/$service.service" <<UNIT
[Unit]
Description=sing-box-secure Argo $kind
After=network-online.target
[Service]
ExecStart=/etc/s-box/cloudflared $args
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
UMask=0077
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200
[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload && systemctl enable "$service" && systemctl restart "$service"
    else
        cat > "/etc/init.d/$service" <<UNIT
#!/sbin/openrc-run
description="sing-box-secure Argo $kind"
command="/etc/s-box/cloudflared"
command_args="$args"
supervisor="supervise-daemon"
respawn_delay=5
depend() { need net; }
UNIT
        chmod 700 "/etc/init.d/$service"
        rc-update add "$service" default && rc-service "$service" restart
    fi
}

secure_argo_stop() {
    local service="sing-box-secure-argo-$1"
    [[ $1 == fixed || $1 == quick ]] || return 1
    if command -v systemctl >/dev/null; then
        systemctl disable --now "$service" 2>/dev/null || true
        rm -f -- "/etc/systemd/system/$service.service"
        systemctl daemon-reload
    else
        rc-service "$service" stop 2>/dev/null || true
        rc-update del "$service" 2>/dev/null || true
        rm -f -- "/etc/init.d/$service"
    fi
}

secure_stop_binary() {
    local binary=$1 process resolved
    [[ $binary == /etc/s-box/sbwpph || $binary == /etc/s-box/cloudflared ]] || return 1
    for process in /proc/[0-9]*/exe; do
        resolved=$(readlink "$process" 2>/dev/null) || continue
        [[ $resolved == "$binary" ]] || continue
        process=${process#/proc/}; process=${process%/exe}
        kill -TERM "$process" 2>/dev/null || true
    done
}

secure_nat_save() {
    local tool file tmp
    for tool in iptables ip6tables; do
        file="/etc/s-box/$tool-nat.rules"
        tmp=$(mktemp "$file.XXXXXX") || return 1
        if "$tool" -t nat -S SBSECURE > "$tmp" 2>/dev/null; then
            mv -f -- "$tmp" "$file" || return 1
        else rm -f -- "$tmp"; fi
    done
    cat > /etc/s-box/nat-restore.sh <<'SCRIPT'
#!/usr/bin/env bash
source /etc/s-box/security.sh
secure_nat_init || exit 1
for tool in iptables ip6tables; do
    [[ -s /etc/s-box/$tool-nat.rules ]] || continue
    "$tool" -t nat -F SBSECURE || exit 1
    while read -r -a rule; do
        [[ ${rule[0]:-} == -A && ${rule[1]:-} == SBSECURE ]] || continue
        "$tool" -t nat "${rule[@]}" || exit 1
    done < "/etc/s-box/$tool-nat.rules"
done
SCRIPT
    chmod 700 /etc/s-box/nat-restore.sh
    if command -v systemctl >/dev/null; then
        cat > /etc/systemd/system/sing-box-secure-nat.service <<'UNIT'
[Unit]
Description=Restore only sing-box-secure NAT chain
After=network-pre.target
Before=sing-box.service
[Service]
Type=oneshot
ExecStart=/etc/s-box/nat-restore.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload && systemctl enable sing-box-secure-nat
    else
        cat > /etc/init.d/sing-box-secure-nat <<'UNIT'
#!/sbin/openrc-run
description="Restore only sing-box-secure NAT chain"
start() { /etc/s-box/nat-restore.sh; }
depend() { need net; before sing-box; }
UNIT
        chmod 700 /etc/init.d/sing-box-secure-nat
        rc-update add sing-box-secure-nat default
    fi
}

secure_warp_service() {
    local port=$1 family=$2 country=${3:-} args
    [[ $port =~ ^[1-9][0-9]{0,4}$ && $port -le 65535 && $family =~ ^[46]$ ]] || return 1
    [[ -z $country || $country =~ ^[A-Z]{2}$ ]] || return 1
    args="-b 127.0.0.1:$port -$family --endpoint 162.159.192.1:2408"
    [[ -z $country ]] || args="$args --cfon --country $country"
    if command -v systemctl >/dev/null; then
        cat > /etc/systemd/system/sing-box-secure-warp.service <<UNIT
[Unit]
Description=sing-box-secure optional local WARP proxy
After=network-online.target
StartLimitIntervalSec=0
[Service]
ExecStart=/etc/s-box/sbwpph $args
WorkingDirectory=/etc/s-box
UMask=0077
NoNewPrivileges=yes
Restart=on-failure
RestartSec=10
LogRateLimitIntervalSec=30s
LogRateLimitBurst=100
[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload && systemctl enable sing-box-secure-warp && systemctl restart sing-box-secure-warp
    else
        cat > /etc/init.d/sing-box-secure-warp <<UNIT
#!/sbin/openrc-run
command="/etc/s-box/sbwpph"
command_args="$args"
directory="/etc/s-box"
supervisor="supervise-daemon"
respawn_delay=10
depend() { need net; }
UNIT
        chmod 700 /etc/init.d/sing-box-secure-warp
        rc-update add sing-box-secure-warp default && rc-service sing-box-secure-warp restart
    fi
}

secure_warp_stop() {
    if command -v systemctl >/dev/null; then
        systemctl disable --now sing-box-secure-warp 2>/dev/null || true
        rm -f /etc/systemd/system/sing-box-secure-warp.service
        systemctl daemon-reload
    else
        rc-service sing-box-secure-warp stop 2>/dev/null || true
        rc-update del sing-box-secure-warp 2>/dev/null || true
        rm -f /etc/init.d/sing-box-secure-warp
    fi
    secure_stop_binary /etc/s-box/sbwpph
}

secure_runtime_maintenance() {
    local service cronfile
    if command -v systemctl >/dev/null; then
        for service in cron crond; do
            if systemctl cat "$service.service" >/dev/null 2>&1; then
                systemctl enable --now "$service" || return 1
                break
            fi
        done
    else
        rc-update add dcron default && rc-service dcron start || return 1
    fi
    mkdir -p /etc/logrotate.d
    cat > /etc/logrotate.d/sing-box-secure <<'RULE'
/etc/s-box/argo.log {
    size 10M
    rotate 3
    missingok
    notifempty
    compress
    copytruncate
    su root root
}
RULE
    cronfile=$(mktemp) || return 1
    crontab -l 2>/dev/null | grep -v 'logrotate.*# sing-box-secure$' > "$cronfile"
    printf '%s\n' '15 * * * * /usr/sbin/logrotate -s /etc/s-box/logrotate.status /etc/logrotate.d/sing-box-secure # sing-box-secure' >> "$cronfile"
    crontab "$cronfile"; local rc=$?; rm -f -- "$cronfile"; return "$rc"
}
