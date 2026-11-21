# Server & website hardening kit (Vultr + Cloudflare)

Everything here is self-contained shell and config. Nothing phones home, and
nothing runs automatically: you run each piece against the hosts and zones you
own. The design goal is simple and the same for every site:

```
internet ──> Cloudflare (TLS, WAF, bot filter, rate limit, DNSSEC)
                 │  only Cloudflare IPs may reach port 443 (Vultr firewall + ufw)
                 │  only Cloudflare's client cert is accepted (Authenticated Origin Pulls)
                 ▼
             Vultr VM: nginx (Origin CA cert) ──> app on 127.0.0.1 only
             SSH: keys only, from your IP only, fail2ban
             unattended security updates, auditd, hardened sysctl, Docker on loopback
```

If an attacker finds the origin IP they get a closed port. If they hit the site
through Cloudflare they meet the WAF and rate limits first. If a new CVE lands
in a package, it is patched within a day without you doing anything.

## Layout

| Path | Run where | Purpose |
|------|-----------|---------|
| `vultr/harden-host.sh` | on each VM, as root | OS baseline: updates, SSH, ufw, fail2ban, sysctl, auditd, Docker |
| `vultr/cloudflare-allowlist.sh` | on each VM (installed by the above) | keeps ufw + nginx real_ip in sync with Cloudflare's IP ranges daily |
| `vultr/vultr-firewall.sh` | anywhere, needs `VULTR_API_KEY` | Vultr network firewall: 443 from Cloudflare, SSH from you, all else dropped |
| `cloudflare/harden-zone.sh` | anywhere, needs `CLOUDFLARE_API_TOKEN` | audit and apply TLS/HSTS/WAF/bot/DNSSEC settings on every zone, report unproxied DNS records |
| `searxng/` | on the SearXNG host | hardened compose stack, settings overlay, limiter, nginx with Origin CA + Authenticated Origin Pulls |
| `audit/external-check.sh` | your laptop | prove from outside that it worked (and re-run monthly) |

## Order of operations (per host)

Do the network edge first so a mistake on the host cannot expose it, then the
host, then verify.

1. **Cloudflare zone** (5 min, zero downtime unless noted)
   ```bash
   export CLOUDFLARE_API_TOKEN=...   # scoped token, see header of the script
   cloudflare/harden-zone.sh audit                 # see where you stand
   cloudflare/harden-zone.sh apply example.com     # one zone at a time
   ```
   * `ssl=strict` needs a valid cert on the origin. Install a Cloudflare Origin
     CA cert first (dashboard: SSL/TLS > Origin Server) or run with
     `ORIGIN_SSL_MODE=full` and tighten later.
   * Any A/AAAA record the audit lists as *unproxied* is a hole: proxy it
     (orange cloud) or move it to a name that is not guessable and firewall it.
     `mail.`/`ftp.` style records that must be unproxied are the usual
     exception; those hosts then need their own firewalling.
   * DNSSEC: if your registrar is not Cloudflare, add the printed DS record there.

2. **Vultr firewall group** (network edge, enforced before the VM)
   ```bash
   export VULTR_API_KEY=...
   vultr/vultr-firewall.sh create --name web-cloudflare --admin-cidr $(curl -s https://ifconfig.me)/32
   vultr/vultr-firewall.sh instances          # find instance ids
   vultr/vultr-firewall.sh attach <group-id> <instance-id>   # or: all
   ```
   Re-run `sync <group-id> --admin-cidr ...` when your IP changes or quarterly
   to pick up Cloudflare range changes. If your home IP is dynamic, put a
   WireGuard/Tailscale endpoint or a small bastion VM in `--admin-cidr` instead.
   Hosts that are *not* behind Cloudflare (mail, game servers, etc.) need a
   separate group with their own ports; do not attach this one to them.

3. **Host baseline** (SSH session stays alive; sshd is only reloaded after a config test)
   ```bash
   scp -r hardening root@host:/root/
   ssh root@host 'ADMIN_CIDR=203.0.113.10/32 /root/hardening/vultr/harden-host.sh --dry-run'
   ssh root@host 'ADMIN_CIDR=203.0.113.10/32 /root/hardening/vultr/harden-host.sh'
   ```
   Before you log out, open a *second* SSH session and confirm it works.
   Notes:
   * Password auth is only disabled if an `authorized_keys` file exists.
   * ufw allows 443 only from Cloudflare. Set `ALLOW_HTTP=1` only if you still
     use HTTP-01 ACME challenges (with Origin CA certs you do not need Let's
     Encrypt on the origin at all).
   * **Docker bypasses ufw.** The script sets the Docker daemon's default publish
     address to `127.0.0.1`, which fixes it for every container after a
     `systemctl restart docker`. It also prints containers that are currently
     published on `0.0.0.0` so you can fix their compose files
     (`"127.0.0.1:8080:8080"`).
   * Non-Debian hosts (Alpine, Rocky): the script will refuse or misbehave; the
     sysctl, sshd and audit rule files are still directly reusable.

4. **Application layer** (SearXNG example in `searxng/`; same pattern for anything else)
   ```bash
   cp -r hardening/searxng /opt/searxng && cd /opt/searxng
   cp .env.example .env && sed -i "s#CHANGE_ME#$(openssl rand -hex 32)#; s#search.example.com#YOUR.HOST#" .env
   docker compose up -d
   # nginx
   install -m 0600 origin.pem origin.key /etc/nginx/ssl/
   curl -fsSo /etc/nginx/ssl/cloudflare-origin-pull-ca.pem https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem
   cp nginx-proxy-snippet.conf /etc/nginx/snippets/searxng-proxy.conf
   sed "s/search.example.com/YOUR.HOST/" nginx.conf > /etc/nginx/sites-available/searxng
   ln -sf /etc/nginx/sites-available/searxng /etc/nginx/sites-enabled/
   /usr/local/sbin/cloudflare-allowlist.sh --nginx     # writes real_ip list
   nginx -t && systemctl reload nginx
   ```
   What it changes versus a stock install: limiter + bot detection on with
   Valkey, `link_token` on, image proxy on, `/stats` and `/config` not public,
   JSON/CSV/RSS output off (turn `formats` back on if you use the API), debug
   off, hashed static files, containers with all capabilities dropped and no
   public ports, per-IP rate limits in nginx as a second layer behind
   Cloudflare's.

5. **Verify from outside**
   ```bash
   audit/external-check.sh search.example.com <origin-ip>
   ```
   All checks should pass. The decisive ones are "direct HTTPS to origin
   refused" and "A records are Cloudflare edge IPs".

## Cloudflare Workers and Pages

Workers are not covered by the scripts (they have no origin to firewall) but
they are part of your attack surface. Checklist for each worker:

* Secrets via `wrangler secret put`, never in `wrangler.toml` `[vars]` or in
  the repo. Rotate anything that was ever committed.
* Workers that proxy to third-party APIs (TTS, transcription, recorders): require
  a bearer token or Cloudflare Access in front of them, and set a per-IP Rate
  Limiting rule, or a bot drains your API quota.
* Workers that accept uploads or run `fetch()` on user-supplied URLs: allowlist
  destination hosts, reject private/link-local addresses (SSRF), cap body size.
* Enable **Cloudflare Access** (Zero Trust, free for up to 50 users) on anything
  admin-only, including `*.workers.dev` previews. Disable the `workers.dev`
  route for production workers that have a custom domain.
* Turn on Workers **Logpush** or at least check the Observability tab for
  unexpected traffic once a month.

## Account hygiene (do once, ten minutes, highest value per minute)

* **2FA with hardware keys or an authenticator** on Cloudflare, Vultr, GitHub and
  the registrar. Remove SMS as a factor. Store recovery codes offline.
* Vultr: restrict API keys to your IP (Account > API > Access Control), delete
  unused keys, enable login alerts, use sub-accounts rather than sharing the
  root login.
* Cloudflare: use scoped API tokens, never the Global API Key; review
  Members and remove stale ones; enable Notifications for "WAF events spike",
  "SSL certificate expiring", "Origin error rate".
* Vultr backups or snapshots enabled on every VM (automatic backups are a
  paid add-on but cheap; snapshots are manual). Test a restore once.
* SSH: one ed25519 key per device, remove old keys from `authorized_keys`.

## Recurring

| When | What |
|------|------|
| automatic | security updates (unattended-upgrades), Cloudflare IP refresh (systemd timer) |
| weekly | `docker compose pull && docker compose up -d` for the app stack (or Watchtower with notifications) |
| monthly | `cloudflare/harden-zone.sh audit`, `audit/external-check.sh` per site, `fail2ban-client status sshd`, check `needrestart`/reboot-required |
| quarterly | `vultr-firewall.sh sync`, rotate API tokens and the SearXNG secret, review Cloudflare WAF events for false positives, prune unused Workers/DNS records/VMs |

## Threat model and what is deliberately not here

* This protects against opportunistic internet-wide scanning, credential
  stuffing, known-CVE exploitation of unpatched software, direct-to-origin WAF
  bypass, and most scraping. It does not protect against a compromised laptop
  holding your SSH key, or a vulnerability in your own application code.
* No intrusion detection beyond auditd and fail2ban. If you want alerting,
  CrowdSec (with its Cloudflare bouncer) is the lightweight next step.
* Port knocking, changing the SSH port and Cloudflare Tunnel are not used.
  Tunnel (`cloudflared`) is a good alternative to the IP allowlist if you prefer
  no inbound ports at all; the rest of the kit still applies.
