# Tunnel Kit — User Guide

> A simple, step-by-step guide to deploying and using the Parse tunnel kit.  
> No advanced server knowledge required.

---

## What you need before starting

| Item | Example |
|---|---|
| A VPS with 3x-ui installed | Contabo, Hetzner, Vultr, etc. |
| A WordPress host (cPanel / shared) | Your personal blog |
| A domain pointing to the WP host | `yourblog.com` |
| An FTP/cPanel File Manager or SFTP access | Provided by your WP host |

---

## Step 1 — Set up 3x-ui on your VPS

If you haven't installed 3x-ui yet, run this on your VPS:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh)
```

During setup, choose:
- **Panel port** — any number other than 2053 (e.g. `54321`)
- **Username / Password** — something strong, not `admin`/`admin`
- **Web path** — a random string (e.g. `/xp92k`)

After install, log into the panel **only through an SSH tunnel**:

```bash
# Run this on your local PC:
ssh -L 9000:127.0.0.1:54321 root@YOUR_VPS_IP
# Then open in browser: http://127.0.0.1:9000/xp92k
```

---

## Step 2 — Create a VLESS inbound in 3x-ui

1. In the panel click **Inbounds → Add Inbound**
2. Fill in:

| Setting | Value |
|---|---|
| Remark | anything (e.g. `relay-ws`) |
| Protocol | `vless` |
| Port | `8080` |
| Transmission | `ws` |
| Path | `/video` |
| TLS | off |

3. Under **Clients**, add a client and copy the **UUID** — you'll need it later.
4. Click **Add**.

> **Security tip:** In the panel go to **Settings → Panel Settings** and set  
> **Xray Listen IP** to `127.0.0.1` if you're using WireGuard, or leave it  
> at `0.0.0.0` but add a firewall rule (UFW) allowing port `8080` **only from your WP host's IP**.

---

## Step 3 — Upload the generator to your admin host

The generator panel (`index.php`, `panel.php`, `bootstrap.php`, `probe.php`) can live on any PHP host — even the same WordPress site.

### 3a — Create the config file

Using cPanel File Manager or FTP, create a file **outside your public folder** (e.g. `/home/USER/private/parse_config.php`):

1. Copy `config.example.php` to that path and rename it `parse_config.php`.
2. Open a terminal (or use cPanel's Terminal) to generate your password hash:
   ```bash
   php -r "echo password_hash('YOUR_CHOSEN_PASSWORD', PASSWORD_BCRYPT, ['cost'=>12]), PHP_EOL;"
   ```
3. Copy the `$2y$12$...` output into `parse_config.php` as the `admin_hash` value.

> ⚠️ **Never type your plaintext password into any PHP file.** Only the hash goes in the config.

### 3b — Upload the admin files

Upload these four files to a subdirectory on your WP host, e.g. `public_html/admin/`:

```
bootstrap.php
index.php
panel.php
probe.php
```

### 3c — Protect the directory (optional but recommended)

Create `public_html/admin/.htaccess` with:

```apache
# Only allow your own IP to reach the admin panel
Require ip YOUR.HOME.IP.ADDRESS
```

---

## Step 4 — Generate a tunnel kit

1. Visit `https://yourblog.com/admin/` in your browser.
2. Log in with the username `admin` and the password you set.
3. Fill the form:

| Field | What to enter |
|---|---|
| **VPS host** | Your VPS IP address (e.g. `104.194.158.108`) |
| **VPS port** | `8080` (or whatever port you used in Step 2) |
| **WS path** | `/video` (must match the inbound path in 3x-ui) |
| **Relay filename** | Something that looks like a normal WP file, e.g. `wp-blog-header.php` |

4. Click **Generate kit**.
5. A panel appears with three values — **save these immediately**:

| Item | What it is |
|---|---|
| **Bearer secret** | The password for the tunnel (64-character hex string) |
| **Install token** | One-time code to run the installer |
| Download button | Click to download `tunnel_kit.zip` |

> ⚠️ The Bearer secret is shown **only once**. If you close the page without copying it, generate a new kit.

---

## Step 5 — Deploy the tunnel on your WordPress host

1. Extract `tunnel_kit.zip` on your PC.
2. Upload **only `installer.php`** to a directory on your WP host, e.g. `public_html/wp-includes/`.
3. Open that URL in your browser **exactly once**:
   ```
   https://yourblog.com/wp-includes/installer.php?t=YOUR_INSTALL_TOKEN
   ```
4. You should see `OK`. The installer deletes itself and creates `wp-blog-header.php` and `.htaccess` in the same folder.

### Verify it works

```bash
# Should return the WP 404 JSON (not authenticated — good)
curl -s https://yourblog.com/wp-includes/wp-blog-header.php

# Should return {"ok":true} (authenticated)
curl -s -H "Authorization: Bearer YOUR_SECRET" \
     https://yourblog.com/wp-includes/wp-blog-header.php
```

Your WordPress site still works normally — none of this affects your blog content.

---

## Step 6 — Configure your client app

### v2rayN (Windows)

1. Click **Add server → Add VLESS server**
2. Fill in:

| Field | Value |
|---|---|
| Address | `yourblog.com` |
| Port | `443` |
| UUID | (from Step 2, the client UUID you copied) |
| Flow | *(leave empty)* |
| TLS | `tls` |
| SNI | `yourblog.com` |
| Transport | `ws` |
| Path | `/wp-includes/wp-blog-header.php` |
| Host | `yourblog.com` |

3. Under **WS Headers**, add:
   ```
   Authorization: Bearer YOUR_64_CHAR_SECRET
   ```
4. Save and click **Set as active**.

---

### Hiddify (Android / iOS / Windows / Mac)

1. Open Hiddify → **Add config → Manual**
2. Choose **VLESS**
3. Fill in the same values as v2rayN above.
4. In the **Custom headers** field add:
   ```
   Authorization: Bearer YOUR_64_CHAR_SECRET
   ```

---

### NekoBox (Android)

1. Tap **+** → **VLESS**
2. Fill in the fields as above.
3. In **WS Settings → Headers**, tap **Add header**:
   - Key: `Authorization`
   - Value: `Bearer YOUR_64_CHAR_SECRET`

---

## Maintenance

### How to update the Bearer secret (rotation)

Do this every 90 days or immediately if you think the secret leaked:

1. Log into the generator panel → generate a new kit (same VPS/port/path).
2. Delete the old `wp-blog-header.php` and `.htaccess` on the WP host.
3. Deploy the new installer.
4. Update the `Authorization` header in all your client apps.

### How to remove the tunnel completely

1. Delete `wp-blog-header.php` and `.htaccess` from the WP host's `wp-includes/` directory.
2. Your WordPress site is unaffected.

### Something isn't working?

| Symptom | Fix |
|---|---|
| Login page says "Too many attempts" | Wait 5 minutes and try again |
| Installer URL gives 404 immediately | The token was wrong — generate a new kit |
| Installer says "Already installed" | Delete the existing `wp-blog-header.php` + `.htaccess` first |
| Client connects but gets 404 | Check the WS path matches where you uploaded the relay file |
| Client connects but no data flows | Check the VPS port (8080) in 3x-ui is correct and the inbound is enabled |
| App connects but drops every few minutes | Normal — Xray idle timeout. Enable keepalive in the client or ignore and reconnect |

---

## File reference

| File | Role |
|---|---|
| `bootstrap.php` | Shared security helpers (don't remove) |
| `config.example.php` | Template for your config — rename and move outside docroot |
| `index.php` | Admin login page |
| `panel.php` | Kit generator |
| `probe.php` | Admin-only connectivity test |
| `wp-blog-header.php` *(generated)* | The tunnel relay — lives on the WP host |
| `.htaccess` *(generated)* | Apache routing rules |
| `installer.php` *(generated)* | One-shot deployer — self-deletes after use |

---

## Disclaimer

**Read this before deploying.**

1. **Personal use only.** This kit is designed for individuals who own or have authorized access to both the VPS and the WordPress hosting account. Do not deploy relay files on servers you do not control or on accounts without the explicit permission of the account owner.

2. **Hosting Terms of Service.** Most managed and shared WordPress hosting providers prohibit using their services as a proxy or tunnel. Using this tool on such accounts may result in account suspension. Review your hosting provider's Acceptable Use Policy before deploying. You are solely responsible for compliance with your hosting agreement.

3. **Legal responsibility.** Laws governing VPNs, proxies, and encrypted tunnels vary by country. In some jurisdictions, operating or using such tools may be restricted or require specific authorizations. You are solely responsible for ensuring your use complies with all applicable local, national, and international laws. The authors of this kit assume no legal liability for how it is used.

4. **No warranty.** This software is provided "as is" without any warranty of any kind. It is your responsibility to review the code, assess its suitability for your needs, and operate it securely. You accept all risks associated with its use.

5. **Security is your responsibility.** Keep your VPS, Bearer secret, and admin panel credentials private. Rotate credentials regularly. The authors are not responsible for unauthorized access resulting from credential leakage or misconfiguration on your part.

6. **Ethical use.** This tool is intended to help individuals access open information, protect their privacy, and communicate freely. It must not be used for illegal activities, unauthorized access to third-party systems, distribution of malicious content, or any activity that harms others.

---

