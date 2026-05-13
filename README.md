# Refactored Tunnel Kit — Deployment Guide

A WordPress-host-fronted reverse tunnel to a self-hosted **3x-ui** (Xray/VLESS) VPS, packaged as a kit generator. This document covers the full deployment from VPS setup to client config.

---

## What changed vs. the original

| Concern | Original | Refactored |
|---|---|---|
| Login bcrypt | `password_verify($input, password_hash('plaintext', ...))` — broken; password in source | `password_verify($input, $stored_hash)`; hash stored in file outside docroot |
| CSRF | none | per-session token, `hash_equals` check |
| Rate limiting | none | 5 attempts / 5 min, per-IP, file-backed sliding window |
| Session hardening | defaults | `Secure`+`HttpOnly`+`SameSite=Strict`, `session_regenerate_id` on login, 30 min idle timeout |
| Generated relay auth | none — anyone hitting `db.php` got `OK + port number` | `Authorization: Bearer <secret>` required; non-auth gets a byte-exact WP `rest_no_route` 404 |
| "Encryption" of payload | `eval(gzinflate(base64_decode(...)))` — labeled "unreadable", reverses in one line, flagged by Imunify360 / BitNinja | dropped. Uses `var_export()` to bind values; secret is generated per-kit and never reused |
| Form input sanitization | string concat into PHP source — RCE primitive | strict whitelist + `var_export()` for all bound values |
| Installer | no auth, doesn't self-delete, advertises deployment | one-shot URL token, self-deletes on success and on tampering |
| External CDNs (`cdn.tailwindcss.com`, `cdnjs`, `fonts.googleapis.com`) | every admin pageview leaks to 3 third parties | self-hosted minimal CSS, `Referrer-Policy: no-referrer` |
| `test.php` (unauthenticated probe) | leaked errno/errstr → port-scan oracle | replaced by auth-gated `probe.php` returning only `{"ok":true/false}` |
| Generated relay deadline | only 180 s idle | 180 s idle **and** 1 h hard cap |

---

## Architecture

```
                 ┌────────────────────────────────┐
                 │   Client (v2rayN / Hiddify)    │
                 │   VLESS + WS + TLS             │
                 └──────────────┬─────────────────┘
                                │  HTTPS :443 (TLS 1.3)
                                │  Authorization: Bearer <secret>
                                ▼
        ┌───────────────────────────────────────────────┐
        │  WordPress shared host                         │
        │  ┌──────────┐    ┌─────────────────────────┐  │
        │  │ blog/... │    │ wp-blog-header.php      │  │
        │  │  (cover) │    │  ↑ auth gate            │  │
        │  └──────────┘    │  ↑ WS upgrade required  │  │
        │                  └────────┬────────────────┘  │
        └───────────────────────────┼───────────────────┘
                                    │ ws:// or wss://
                                    ▼
                    ┌───────────────────────────────┐
                    │  VPS — 3x-ui Xray inbound     │
                    │  VLESS + WS, path = /video    │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                              Internet
```

Three layers of authentication before traffic reaches Xray:

1. **TLS** (client → WP host) — the browser/client validates the WP host's Let's Encrypt cert.
2. **Bearer token** (relay PHP) — `hash_equals(SECRET, $auth_header)` before any backend connection is opened.
3. **VLESS UUID** (Xray) — the standard VLESS protocol auth.

Without all three, you get a WordPress `rest_no_route` 404 indistinguishable from real WP.

---

## Files in this kit

| File | Where it lives | Purpose |
|---|---|---|
| `bootstrap.php` | docroot | Shared session/CSRF/rate-limit helpers |
| `config.example.php` | **outside docroot** as `parse_config.php` | Admin user + bcrypt hash |
| `index.php` | docroot | Login form |
| `panel.php` | docroot | Kit generator UI (auth-gated) |
| `probe.php` | docroot | Admin connectivity probe (auth-gated) |

Generated artifacts (per-kit, downloaded as `tunnel_kit.zip`):

| File | Purpose |
|---|---|
| `<filename>.php` | The relay itself. Default: `wp-blog-header.php` |
| `.htaccess` | Apache fast path + access denials |
| `installer.php` | One-shot installer with URL token |
| `README.md` | Per-kit deployment notes incl. the Bearer secret |

---

## Part 1 — VPS setup (3x-ui side)

### 1.1 Install 3x-ui

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh)
```

Pick a **non-default** panel port and a long random web base path during the prompts.

### 1.2 Lock the panel to localhost

```bash
x-ui setting -listen 127.0.0.1
systemctl restart x-ui
```

Reach the panel only via SSH tunnel from your laptop:
```bash
ssh -L 8443:127.0.0.1:54321 user@vps
# then browse http://127.0.0.1:8443/<webpath>
```

### 1.3 Reconfigure the inbound

Looking at the `inbound-sanaei-panel.txt` you shared — the inbound is currently listening on `0.0.0.0:443` with `security: "none"`. **This is suboptimal**: a plaintext WS endpoint on port 443 is an immediate red flag to anyone scanning the VPS. Two fixes, pick one:

**Option A — recommended: bind the inbound to localhost; let the WP host reach it via SSH-forward or WireGuard.**

In 3x-ui, edit the inbound:
- `Listen IP`: `127.0.0.1`
- `Port`: `10000` (or any internal port)
- `Transport`: `ws`
- `Security`: `none` (TLS is handled upstream)
- `Path`: `/video`

Then create a WireGuard tunnel between WP host and VPS (see Part 1.5).

**Option B — quick: keep public access but firewall by source IP.**

Edit the inbound:
- `Listen IP`: `0.0.0.0`
- `Port`: `8080` (move off 443)
- `Security`: `none`
- `Path`: `/video`

UFW lockdown:
```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow from <WP_HOST_IP> to any port 8080 proto tcp
ufw enable
```

This is weaker — the WP-host → VPS hop is still plaintext WS over the open internet. A passive observer between the two can read the inner Xray stream. Use option A unless you have a reason not to.

### 1.4 Verify external attack surface

From a third machine (not the WP host, not the VPS):
```bash
nmap -Pn -p 1-65535 --min-rate 5000 <vps_public_ip>
```

You should see only `:22` and (option B only) `:8080` reachable from your WP host's IP. The 3x-ui panel and Xray inbound must not respond to anyone else.

### 1.5 (Option A only) WireGuard between WP host and VPS

On both machines:
```bash
apt install -y wireguard
cd /etc/wireguard && umask 077
wg genkey | tee privkey | wg pubkey > pubkey
```

**VPS `/etc/wireguard/wg0.conf`** (10.66.66.1):
```ini
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = <vps_privkey>

[Peer]
PublicKey = <wp_host_pubkey>
AllowedIPs = 10.66.66.2/32
```

**WP host `/etc/wireguard/wg0.conf`** (10.66.66.2):
```ini
[Interface]
Address = 10.66.66.2/24
PrivateKey = <wp_host_privkey>

[Peer]
PublicKey = <vps_pubkey>
Endpoint = <vps_public_ip>:51820
AllowedIPs = 10.66.66.1/32
PersistentKeepalive = 25
```

Bring up:
```bash
wg-quick up wg0 && systemctl enable wg-quick@wg0
ping -c2 10.66.66.1   # from WP host
```

Update the 3x-ui inbound listen IP to `10.66.66.1`, and use that as `host` when generating the kit.

---

## Part 2 — Admin host setup (where the generator runs)

This is where `index.php`/`panel.php`/`probe.php`/`bootstrap.php` live. It can be the same WordPress host or a separate admin-only box.

### 2.1 Filesystem layout

```
/home/USER/
  ├── private/                          ← outside docroot
  │   └── parse_config.php          ← config (chmod 600)
  └── public_html/                      ← docroot
      ├── admin/                         ← put admin tools in a subdirectory
      │   ├── bootstrap.php
      │   ├── index.php
      │   ├── panel.php
      │   └── probe.php
      └── wp-content/                    ← real WordPress (your cover)
```

If your host doesn't allow files above docroot, put `parse_config.php` inside `/admin/` and add an `.htaccess` denying it:

```apache
<Files "parse_config.php">
    Require all denied
</Files>
```

### 2.2 Generate the admin password hash

```bash
php -r "echo password_hash('YOUR_REAL_STRONG_PASSWORD', PASSWORD_BCRYPT, ['cost'=>12]), PHP_EOL;"
```

Copy the `$2y$12$...` output into `parse_config.php` as the `admin_hash` value. **Never put the plaintext password in any PHP file.**

### 2.3 Set strict permissions

```bash
chmod 700 /home/USER/private
chmod 600 /home/USER/private/parse_config.php
chmod 644 /home/USER/public_html/admin/*.php
```

### 2.4 (Optional but recommended) Restrict the admin path by IP

In `/home/USER/public_html/admin/.htaccess`:
```apache
<RequireAll>
    Require ip 1.2.3.4              # your home/office IP
    Require ip 5.6.7.0/24
</RequireAll>
```

### 2.5 Enforce HTTPS on the admin path

The session cookie has `Secure` set, so the panel **will not work over HTTP**. Make sure your domain has Let's Encrypt configured and HTTP→HTTPS redirect is in place.

---

## Part 3 — Generate a deployment kit

1. Visit `https://yourdomain.com/admin/` and log in.
2. Fill the form:
   - **VPS host** — `10.66.66.1` (option A) or VPS public IP (option B), or your VPS hostname.
   - **VPS port** — `10000` (option A) or `8080` (option B).
   - **WS path** — `/video` (matches your 3x-ui inbound).
   - **Relay filename** — pick something that blends in. Good: `wp-blog-header.php`, `wp-load.php`, `wp-config-sample.php`. Bad: `db.php`, `wp.php`, `panel.php`, `relay.php` — those are well-known scanner targets.
3. Click **Generate kit**.
4. **Copy the Bearer secret immediately** — it's shown once and never again. Anyone with this string + the relay URL can use the tunnel.
5. **Copy the install token** — needed for the one-shot installer.
6. Download `tunnel_kit.zip`.

---

## Part 4 — Deploy on the WP host

You have two paths. Use the installer if `mod_proxy_wstunnel` is enabled; use manual otherwise.

### Path A — One-shot installer (recommended)

1. Upload **only** `installer.php` from the zip to wherever you want the relay to live, e.g. `https://yourblog.com/wp-includes/installer.php`.
2. Visit exactly **once**: `https://yourblog.com/wp-includes/installer.php?t=<INSTALL_TOKEN>`
3. You should see `OK`. The installer self-deletes and creates `<filename>.php` + `.htaccess` next to where it ran.
4. Verify with curl:
   ```bash
   curl -sI https://yourblog.com/wp-includes/wp-blog-header.php   # → 404 (good)
   curl -sI -H "Authorization: Bearer <SECRET>" \
        https://yourblog.com/wp-includes/wp-blog-header.php       # → 200, {"ok":true}
   ```
5. Confirm the installer is gone:
   ```bash
   curl -sI https://yourblog.com/wp-includes/installer.php   # → 404
   ```

If you visit the installer URL with a wrong/missing token, it self-deletes immediately. You'll need to regenerate the kit if you mistype the token.

### Path B — Manual install

Used when the host doesn't have `mod_proxy_wstunnel` (managed shared hosts often don't):

1. Upload `<filename>.php` and `.htaccess` from the zip into the same directory.
2. Delete `installer.php` from the zip — you don't need it.
3. The `.htaccess` `[P,L]` proxy rule will silently fail without `mod_proxy_wstunnel`, but the relay still works because the rewrite falls through to PHP. You're paying the PHP-FPM-worker-per-connection cost mentioned earlier.

### Verify the cover is intact

```bash
curl -sI https://yourblog.com/                      # → 200, real WordPress
curl -s  https://yourblog.com/wp-includes/wp-blog-header.php | head -1
# Should be exactly: {"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}}
```

---

## Part 5 — Client configuration

### v2rayN / NekoBox / Hiddify (manual entry)

| Field | Value |
|---|---|
| Protocol | `vless` |
| Address | `yourblog.com` *(NOT the VPS — the WP host front)* |
| Port | `443` |
| UUID | from your 3x-ui inbound (e.g. `5d26bd77-7fcc-4d72-8ca1-ebcf56187c67` from `inbound-sanaei-panel.txt`) |
| Encryption | `none` |
| Flow | *(empty — flow doesn't apply to WS)* |
| TLS | enabled |
| SNI | `yourblog.com` |
| ALPN | `http/1.1` |
| Allow insecure | off |
| Transport | `ws` |
| Path | `/wp-includes/wp-blog-header.php` *(the path on the WP host, not the Xray inbound path)* |
| Host header | `yourblog.com` |
| Custom WS headers | `Authorization: Bearer <SECRET_FROM_KIT>` |

> **Important detail:** the client's `path` is the URL path on the **WP host** (where your relay PHP lives). The kit's `WS path` field is the path on the **VPS** that Xray's inbound expects (`/video`). The relay PHP rewrites between them — you set the VPS-side path at generation time and the client-side path matches wherever you put the relay file.

### Subscription URI (manual)

```
vless://<UUID>@yourblog.com:443?encryption=none&security=tls&sni=yourblog.com&type=ws&host=yourblog.com&path=%2Fwp-includes%2Fwp-blog-header.php#tunnel
```

The Bearer header isn't representable in the URI scheme — you must add it as a custom header in the client UI after import.

### Headers in v2rayN (Windows)

- Edit server → Transport settings → **WS Header** → JSON:
  ```json
  {"Authorization": "Bearer YOUR_SECRET_HERE"}
  ```

### Headers in NekoBox / Sing-box

In the outbound config:
```json
{
  "type": "vless",
  "transport": {
    "type": "ws",
    "path": "/wp-includes/wp-blog-header.php",
    "headers": { "Authorization": "Bearer YOUR_SECRET_HERE" }
  }
}
```

---

## Part 6 — Operations

### 6.1 Rotation

The Bearer secret is per-kit. To rotate:

1. Sign into `panel.php`, regenerate a kit (same form values, new secret will be issued).
2. Re-deploy via installer **or** delete the old `<filename>.php` + `.htaccess` and upload manually.
3. Update all clients with the new Bearer header.

Do this **at minimum** every 90 days, immediately if you suspect leakage.

### 6.2 Multiple deployments

Each kit gets a fresh secret. You can run several relays simultaneously on different paths/filenames pointing at the same VPS — useful for separating users or having a hot spare. The VPS doesn't care; the relay just opens an additional WS upstream per request.

### 6.3 Removing a deployment

```bash
ssh wp-host
cd /path/to/relay/dir
rm -f wp-blog-header.php .htaccess
```

The cover WordPress site continues serving normally — the `.htaccess` rules only ever affected requests to that one filename.

### 6.4 Detection

Things that increase your detection risk, in rough order:

1. **Generic anti-malware scanners** on shared hosts (Imunify360, BitNinja, Patchstack) flag `eval(base64_decode(`, `eval(gzinflate(`, hardcoded IPs in PHP, and unusual `fsockopen` patterns. The refactored relay avoids all of these — no eval, no obfuscation, hardcoded IP is in plain `const`.
2. **Outbound connection patterns** — your WP host opening long-lived TCP sessions to a single VPS at all hours is unusual for a blog. Hosts with egress monitoring (most managed WP, some shared) will notice.
3. **Worker exhaustion** under the manual-install (PHP fallback) path. If your blog's PHP-FPM `pm.max_children` is small, a few simultaneous tunnel users will 503 the cover site — which is itself a signal.
4. **DPI traffic analysis** — packet timing and volume between client and WP host correlated with WP host and VPS. WG hides packet contents on the inner hop, not the existence of traffic. This is only relevant under serious DPI threat models (e.g. GFW, Iran's SmartFilter when escalated).

If your threat model is heavy DPI specifically: drop the WP-fronting and use **Xray-Reality** instead — it's indistinguishable from a real TLS handshake to a target site (`www.microsoft.com` etc.) and doesn't need a fronting domain. Reality is the modern answer to TLS-in-TLS detection.

### 6.5 Hosting TOS

Most managed WordPress hosts forbid using the account as a proxy (Bluehost, SiteGround, Kinsta, WP.com, GoDaddy managed WP, etc.). You may eventually be flagged by their abuse-detection systems — typically by long-lived outbound connections or elevated PHP-FPM usage — and have the account suspended. Self-hosted WordPress on a VPS you control isn't subject to this. Decide accordingly.

---

## Part 7 — Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Login form gives "Invalid request" | CSRF token expired (cookie cleared, session timed out) | Reload the form |
| "Too many attempts" after typos | Rate limit hit | Wait 5 min, or `rm /tmp/ireclips_rate/*` |
| Installer URL returns 404 immediately | Wrong/missing `?t=...` | Token must match exactly; otherwise installer self-destructs and you need a new kit |
| `curl https://blog/relay` returns the JSON 404 even with Bearer | Header not being passed through | Check `mod_setenvif` isn't stripping `Authorization`. Try: `RequestHeader set X-Auth %{HTTP:Authorization}` and read from `HTTP_X_AUTH` instead, or use `php_value` to disable header filtering |
| Client connects but no traffic flows | Path mismatch between client and Xray inbound | Client path = WP-host URL path. Server path (`/video`) is set inside the relay constants and must match the inbound's `wsSettings.path` |
| Client gets 502 from the front | Backend unreachable | Visit `/admin/probe.php?host=10.66.66.1&port=10000&csrf=...` — if `{"ok":false}`, the WP host can't reach the VPS. Check WG/firewall |
| Relay works for a minute then drops | 180 s idle timeout, normal | Keep the connection active or extend `lastActivity` window in the relay |

### Quick health check

From the admin host, with a valid session:

```bash
# 1. Front responds normally
curl -sI https://yourblog.com/

# 2. Relay returns WP-style 404 unauthenticated
curl -s https://yourblog.com/wp-includes/wp-blog-header.php

# 3. Relay accepts auth
curl -s -H "Authorization: Bearer $SECRET" \
     https://yourblog.com/wp-includes/wp-blog-header.php

# 4. Backend reachable from WP host
ssh wp-host 'curl -sI http://10.66.66.1:10000/'
```

Steps 1, 2, and 3 must all succeed. If 4 fails, it's a WG/firewall problem, not the relay.

---

## Appendix — File checksums

Generate locally after extraction to verify no in-transit tampering:
```bash
sha256sum bootstrap.php config.example.php index.php panel.php probe.php
```
