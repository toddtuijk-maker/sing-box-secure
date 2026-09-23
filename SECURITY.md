# Security and validation boundaries

This is a hardening preview, not a certification.

In scope: Linux sb.sh, new helpers, portable container entry and security-ci.
Out of scope and unchanged: Serv00/Hostuno, app.js, index.html, workers_keep.js,
SSH.yml, serv00.yml, kp.sh and the old manual keepalive workflow. Legacy files
still contain known dangerous patterns (unauthenticated controls, execution
trust, disabled TLS verification, secret handling). Do not run those workflows
or expose their interfaces. Use only the new Linux security regression workflow.

Controls: separate credentials, independent WS paths, private files, HTTPS and
binary digests, no blanket firewall/DNS/SELinux changes, owned NAT chain only,
strict TLS exports, protected HTTPS subscriptions, narrower GitLab credentials,
configuration checks, process supervision and bounded subscription concurrency.

Remaining limitations:

- Linux legacy editors depend on generated line layout. Arbitrary formatting
  can break menu edits. Keep backups and do not reformat templates.
- Installation is not a single transaction; external failures can leave an
  incomplete owned install. Inspect before retrying; foreign installs refused.
- Full systemd/OpenRC boot, certificate renewal, WARP account registration,
  Argo accounts, Telegram and GitLab have not all been live-tested.
- Distro CI proves dependency/syntax checks, not full VM boot compatibility.
- Public Reality connectivity, mobile imports, throughput/latency under loss,
  UDP reachability and 24/72-hour memory/uptime soak require staged acceptance.
- Legacy 1.10 and opaque optional WARP binaries add supply-chain risk.
- Provider ingress/NAT/port mapping remains the administrator's responsibility.
- Self-signed rotation needs refreshed clients. Certificate renewals need
  service reload. Track expiration and protect persistent certificate files.
- Daily 03:00 restart disrupts sessions; it is not a root-cause fix.
- Never serve the entire data directory; subscription URLs are bearer secrets.

Report privately to the repository owner after removing credentials. Never
paste SSH passwords, full node links or API tokens into public issues/CI logs.
