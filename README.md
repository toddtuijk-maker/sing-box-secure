# sing-box-secure

Linux VPS 安全加固与无 root 容器入口。GPL-3.0 衍生项目，来源见 [NOTICE](NOTICE)。
**当前为验证预览版，不是长期稳定性认证。** 实际测试结果见 Actions；不自动部署到已有 VPS。

## 选择入口

| 环境 | 入口 | 范围 |
|---|---|---|
| root + systemd/OpenRC Linux VPS | `bash sb.sh` | 保留五协议、分流、可选 Argo/WARP、订阅菜单 |
| Docker / 非 root / 无 init Linux | `portable.py` 或 Compose | 五协议 + 可选 VLESS WS TLS，不改宿主机 |
| Serv00 / Hostuno | 原文件原样保留 | **不在本次加固验收范围，已知风险未修复，不建议直接启用** |

主脚本识别 Debian、Ubuntu、Alpine、Rocky、AlmaLinux、RHEL、CentOS Stream、Fedora，拒绝 CentOS/RHEL 7。
CI 仅检查 Debian 12、Ubuntu 24.04、Rocky 9、Alpine 3.22 的依赖安装与语法，不代表各系统整机安装均已验收。
VPS 下载支持 amd64/arm64/armv7；容器镜像支持 amd64/arm64，CI 运行 amd64。两个入口都需要 Python 3.9+；默认使用官方 1.14.1 静态 musl 内核，避免 Alpine 缺少 glibc 加载器。便携入口另需 OpenSSL。

## 协议选择

- TCP 主线：VLESS Reality Vision。需要原始 TCP 入站及可达的 Reality 握手目标，不是普通 HTTP 反代协议。
- UDP 备选：Hysteria2 / TUIC v5。供应商必须映射 UDP；限速、封锁、MTU 和丢包会影响体验，不保证更快。
- TCP 备选：AnyTLS，要求客户端内核支持，不承诺旧客户端兼容。
- 保留 VMess WS / TLS；容器默认启用 TLS。Argo 非 TLS WS 源站只应用于可信本地隧道连接。
- **新增便携入口可选 VLESS WebSocket + TLS**：独立 UUID/路径，无 Vision flow，适用于能正确转发 WebSocket/TLS 的环境；不默认引入外部 CDN。

依据 [VLESS 官方配置](https://sing-box.sagernet.org/configuration/inbound/vless/)、
[WebSocket transport](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/)、
[AnyTLS](https://sing-box.sagernet.org/configuration/inbound/anytls/)。
这不是协议速度排名；安全和可用性还取决于线路、证书、网络及客户端版本。

## VPS 安装

私有仓库请使用 GitHub 官方登录后的 git/gh 克隆，或登录 GitHub 下载完整 ZIP。不要把令牌写入命令。不再提供 `curl | bash`。

```bash
git clone https://github.com/toddtuijk-maker/sing-box-secure.git
cd sing-box-secure
# 先审核代码，再在目标 VPS 以 root 运行：
bash sb.sh
```

安装后使用 `sb`。默认固定内核 1.14.1；1.10.7 仅为旧分流功能保留，不推荐新装选择。
内核下载验证 SHA-256；其他版本必须有 GitHub 发布资产摘要。脚本更新只从管理员审核过的完整本地目录载入。
不关闭防火墙/SELinux、不替换内核、不改 DNS、不整机升级、不清空系统 NAT。
请自行开放正确的**入站** TCP/UDP。外来 /etc/s-box 会拒绝覆盖；已有安装请先备份迁移。

证书支持导入或本机 Certbot。HTTP-01 需要 80 可达；否则考虑 DNS-01。**手动 DNS-01 没有自动续期**。
续期后重载服务，禁止关闭 TLS 验证规避过期。

## 容器 / 便携运行

```bash
PUBLIC_HOST=your.example.com TZ=Asia/Shanghai docker compose up -d --build
docker compose ps
docker compose logs --tail=100
```

ARM64 加 `TARGETARCH=arm64`。使用 UID 10001、cap_drop ALL、只读根文件系统和 /tmp tmpfs；
不要求 privileged、TUN、systemd、host network。命名卷保存密钥配置，**不要删除数据卷**。
绑定目录时预先授予 UID 10001 写权限。

Compose 端口：25809/TCP Reality、29687/TCP VMess TLS WS、32695/UDP HY2、41781/UDP TUIC、
16134/TCP AnyTLS、34443/TCP VLESS WS TLS。只映射需要的端口。
仅提供 HTTP 反代的平台不能凭脚本启用原始 TCP/UDP；需自行配置可信 TLS 终止/源站连接，本项目不自动适配平台面板。

无需 Docker：

```bash
PUBLIC_HOST=your.example.com VLESS_WS_PORT=34443 \
python3 portable.py --binary /absolute/path/sing-box --data ./data
```

首次初始化变量：VLESS_PORT、VMESS_PORT、HYSTERIA2_PORT、TUIC_PORT、ANYTLS_PORT、可选 VLESS_WS_PORT，
必须互不重复且在 1024–65535；VMESS_TLS=0 仅供可信 TLS 反代源站。新的 VLESS WS 入口始终 TLS。
初始化变量**不会覆盖已有持久化配置**。修改前备份、运行内核 check、同步客户端。
普通前台进程异常退出后，由平台/服务管理器负责重新启动。

## 订阅与客户端

本地生成，无第三方转换：
`clmi.yaml` 面向 Mihomo（容器版为合法 YAML 的 JSON 子集）；
`sbox.json` 面向 sing-box 1.14 系列；
`jhsub.txt` 为 Base64 节点集合，客户端仅支持其中与自身内核匹配的协议。

旧 Clash 不支持全部协议。Clash Verge/FlClash 也取决于内核版本。
v2rayN、Shadowrocket 等尚未逐款真机验证，不能保证所有节点都可用。
完整配置嵌入自签 CA/证书指纹并保持校验开启；通用 URI 无法统一携带信任信息。
包括带 pinSHA256 的 HY2 在内，自签 TLS URI 仍需手工信任或使用受信任域名证书，
见 [Hysteria TLS 文档](https://hysteria.network/docs/getting-started/Client/)。勿开启 insecure/skip-cert-verify。

VPS 菜单提供 HTTPS 订阅：有效证书、随机令牌路径、三文件白名单、并发限制、无令牌访问日志，启动后降权。
订阅链接等同密码，不要公开。GitLab 可选私有项目推送使用独立写/只读令牌、不强推；
读令牌仍须限制账户/项目权限。Telegram 推送会将节点凭据交给 Telegram，仅在理解风险后开启。
容器默认不托管订阅，请安全取出文件或自建受保护 HTTPS；**禁止公开整个 /data**。

## 长期运行

- VPS 用 systemd/OpenRC 监管；容器前台进程退出联动及 restart policy，SIGTERM 优雅停止。
- 默认每天 **03:00（服务器/容器时区）** 检查配置后重启，会短暂断线。容器默认 UTC，示例设置上海时区。
  便携入口可用 --restart-hour 改时间；VPS 修改自己的 cron 行，重装任务会恢复默认。
- 重启前检查配置；失败保留最近有效配置；内核更新失败尝试回退。
- Compose 日志每份 10MB、3份；Argo 文件每小时检查轮转；宿主 journald 配额由管理员管理，不全局改写。
- 容器健康检查仅检查本地进程/TCP监听，不证明公网可达。Docker unhealthy 本身**不会自动重启**；进程退出才触发策略。
- 证书到期、磁盘/内存、流量额度、封锁仍需运维。03:00 重启不是以前 -1 故障的根因结论。
- Argo 固定域名更适合持久订阅；临时域名重启可变。WARP/Argo 是可选外部依赖，不建议作为唯一通道。

## 验证与边界

```bash
bash -n sb.sh && bash -n security.sh
bash tests/test_shell.sh
SING_BOX_CHECK=/path/sing-box python3 -m unittest discover -s tests -v
```

完整 CI 设置 1.14.1、1.10.7、Mihomo 校验器。检查真实内核配置、独立凭据、下载失败保留旧文件、
cron 隔离、订阅白名单、VMess TLS/HY2/TUIC/AnyTLS/VLESS WS TLS 本地实际传输、
容器停止/重启与持久化。Reality 未以假目标代替公网验收。
尚未完成真实整机重启、多运营商测速、手机逐款导入、24/72小时持续运行，见 [SECURITY.md](SECURITY.md)。
