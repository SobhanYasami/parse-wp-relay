<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require_auth();

if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: index.php');
    exit;
}

$error = null;
$result = false;

// ---------- Validators ------------------------------------------------------

function validate_host(string $h): bool {
    if ($h === '' || strlen($h) > 253) return false;
    if (filter_var($h, FILTER_VALIDATE_IP)) return true;
    return (bool)preg_match(
        '/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/',
        $h
    );
}

function validate_path(string $p): bool {
    return (bool)preg_match('#^/[A-Za-z0-9_\-./]{1,128}$#', $p);
}

function validate_filename(string $f): bool {
    return (bool)preg_match('/^[a-z0-9][a-z0-9_\-]{0,30}\.php$/i', $f);
}

// ---------- Generators ------------------------------------------------------

/**
 * Generates the relay PHP file. All variable values are bound via var_export
 * so an attacker who controls the form fields cannot inject PHP into the
 * output (the bug the original panel.php had).
 */
function generate_relay(string $host, int $port, string $path, string $secret): string {
    $H = var_export($host,   true);
    $P = var_export($port,   true);
    $A = var_export($path,   true);
    $S = var_export($secret, true);

    return <<<PHP
<?php
declare(strict_types=1);

const RELAY_HOST   = $H;
const RELAY_PORT   = $P;
const RELAY_PATH   = $A;
const RELAY_SECRET = $S;

@set_time_limit(0);
@ini_set('max_execution_time', '0');
ignore_user_abort(true);
error_reporting(0);

// === 1. Auth gate ===========================================================
\$provided = '';
if (!empty(\$_SERVER['HTTP_AUTHORIZATION'])) {
    \$h = trim(\$_SERVER['HTTP_AUTHORIZATION']);
    if (stripos(\$h, 'Bearer ') === 0) \$provided = substr(\$h, 7);
}
\$valid = hash_equals(RELAY_SECRET, \$provided);

\$start = microtime(true);

if (!\$valid) {
    // Byte-exact WordPress REST 404. Match real WP timing (~5 ms warm).
    http_response_code(404);
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Robots-Tag: noindex');
    \$delta = microtime(true) - \$start;
    \$pad   = 0.005 - \$delta;
    if (\$pad > 0) usleep((int)(\$pad * 1e6));
    echo '{"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}}';
    exit;
}

// === 2. Dispatch ============================================================
\$isUpgrade = isset(\$_SERVER['HTTP_UPGRADE'])
    && strcasecmp(\$_SERVER['HTTP_UPGRADE'], 'websocket') === 0;
\$method = \$_SERVER['REQUEST_METHOD'] ?? 'GET';

// Authenticated GET probe — minimal info, no port leakage
if (!\$isUpgrade && \$method === 'GET') {
    header('Content-Type: application/json');
    \$fp = @fsockopen(RELAY_HOST, RELAY_PORT, \$errno, \$errstr, 5);
    if (\$fp) { fclose(\$fp); echo '{"ok":true}'; }
    else     { http_response_code(502); echo '{"ok":false}'; }
    exit;
}

// === 3. WebSocket relay =====================================================
\$remote = @fsockopen('tcp://' . RELAY_HOST, RELAY_PORT, \$errno, \$errstr, 10);
if (!\$remote) { http_response_code(502); exit; }
stream_set_timeout(\$remote, 600);

\$key = \$_SERVER['HTTP_SEC_WEBSOCKET_KEY'] ?? base64_encode(random_bytes(16));

\$req  = "GET " . RELAY_PATH . " HTTP/1.1\\r\\n";
\$req .= "Host: " . RELAY_HOST . ":" . RELAY_PORT . "\\r\\n";
\$req .= "Upgrade: websocket\\r\\n";
\$req .= "Connection: Upgrade\\r\\n";
\$req .= "Sec-WebSocket-Key: " . \$key . "\\r\\n";
\$req .= "Sec-WebSocket-Version: 13\\r\\n\\r\\n";
fwrite(\$remote, \$req);

\$resp = '';
\$dl   = time() + 10;
while (!feof(\$remote) && time() < \$dl) {
    \$line = fgets(\$remote, 1024);
    if (\$line === false) break;
    \$resp .= \$line;
    if (\$line === "\\r\\n") break;
}
if (strpos(\$resp, '101') === false) {
    http_response_code(502);
    fclose(\$remote);
    exit;
}

http_response_code(101);
header('Upgrade: websocket');
header('Connection: Upgrade');
\$accept = base64_encode(sha1(\$key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
header('Sec-WebSocket-Accept: ' . \$accept);
while (ob_get_level()) ob_end_flush();
flush();

stream_set_blocking(\$remote, false);
\$input = fopen('php://input', 'rb');
stream_set_blocking(\$input, false);

\$deadline     = time() + 3600; // hard cap: 1 h per session
\$lastActivity = time();

while (time() < \$deadline) {
    if (feof(\$remote) || time() - \$lastActivity > 180 || connection_aborted()) break;
    \$r = [\$remote, \$input];
    \$w = \$e = null;
    \$ready = @stream_select(\$r, \$w, \$e, 0, 200000);
    if (\$ready === false) break;
    if (\$ready === 0) continue;
    foreach (\$r as \$s) {
        \$data = @fread(\$s, 65536);
        if (\$data === false || \$data === '') continue;
        \$lastActivity = time();
        if (\$s === \$remote) { echo \$data; flush(); }
        else { if (@fwrite(\$remote, \$data) === false) break 2; }
    }
}
@fclose(\$remote);
@fclose(\$input);
PHP;
}

/**
 * Apache config. The fast path requires:
 *   - WS upgrade header
 *   - AND a Bearer auth header (so probes without the secret get the PHP 404)
 */
function generate_htaccess(string $host, int $port, string $path, string $relay_filename): string {
    $url = "ws://{$host}:{$port}{$path}";
    $fn  = preg_quote($relay_filename, '/');
    return <<<HT
# Auto-generated. Backend coordinates are bound here.
RewriteEngine On

# Fast path: Apache mod_proxy_wstunnel (only with WS upgrade + Bearer header)
RewriteCond %{HTTP:Upgrade} websocket [NC]
RewriteCond %{HTTP:Connection} upgrade [NC]
RewriteCond %{HTTP:Authorization} ^Bearer\\ . [NC]
RewriteRule ^{$fn}\$ "{$url}" [P,L]

# Anything else hitting the relay path → fall through to PHP, which
# returns a WP-style 404 unless the Bearer secret matches.
RewriteCond %{HTTP:Upgrade} !websocket [NC]
RewriteRule ^{$fn}\$ - [L]

# Don't ever serve the config or installer remnants
<FilesMatch "^(installer\\.php|iraneclips_config\\.php)\$">
    Require all denied
</FilesMatch>
HT;
}

/**
 * One-shot installer. Self-deletes on bad token AND on completion.
 * No "encryption" theatre — just base64 packing for transport.
 */
function generate_installer(string $relay_code, string $htaccess_code, string $relay_filename, string $token): string {
    $relay_b64 = base64_encode($relay_code);
    $ht_b64    = base64_encode($htaccess_code);
    $FN  = var_export($relay_filename, true);
    $TOK = var_export($token, true);

    return <<<PHP
<?php
declare(strict_types=1);
/* One-shot installer. Self-deletes after first run. */

\$expected_token = $TOK;
\$relay_filename = $FN;

if (!hash_equals(\$expected_token, \$_GET['t'] ?? '')) {
    http_response_code(404);
    @unlink(__FILE__);
    exit;
}

if (file_exists(\$relay_filename) || file_exists('.htaccess')) {
    http_response_code(409);
    echo "Already installed. Remove existing files first.\\n";
    exit;
}

\$ok1 = file_put_contents(\$relay_filename, base64_decode('$relay_b64')) !== false;
\$ok2 = file_put_contents('.htaccess',     base64_decode('$ht_b64'))    !== false;

if (\$ok1 && \$ok2) {
    @chmod(\$relay_filename, 0644);
    @chmod('.htaccess',     0644);
    echo "OK\\n";
} else {
    @unlink(\$relay_filename);
    @unlink('.htaccess');
    http_response_code(500);
    echo "FAIL\\n";
}

@unlink(__FILE__);
PHP;
}

// ---------- Form handler ----------------------------------------------------

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate'])) {
    if (!csrf_check($_POST['csrf'] ?? null)) {
        $error = 'Invalid request.';
    } else {
        $host = trim((string)($_POST['host'] ?? ''));
        $port = (int)($_POST['port'] ?? 0);
        $path = trim((string)($_POST['path'] ?? ''));
        $fn   = trim((string)($_POST['filename'] ?? 'wp-blog-header.php'));

        if (!validate_host($host))         $error = 'Invalid host.';
        elseif ($port < 1 || $port > 65535) $error = 'Invalid port.';
        elseif (!validate_path($path))     $error = 'Invalid path. Format: /[A-Za-z0-9_\-./]+';
        elseif (!validate_filename($fn))   $error = 'Invalid filename. Format: [a-z0-9_-]+.php';
        else {
            $secret = bin2hex(random_bytes(32));        // 64-char Bearer secret
            $token  = bin2hex(random_bytes(16));        // 32-char one-shot install token

            $relay_code = generate_relay($host, $port, $path, $secret);
            $ht_code    = generate_htaccess($host, $port, $path, $fn);
            $inst_code  = generate_installer($relay_code, $ht_code, $fn, $token);

            $zip_path = sys_get_temp_dir() . '/ireclips_' . bin2hex(random_bytes(8)) . '.zip';
            if (class_exists('ZipArchive')) {
                $zip = new ZipArchive();
                if ($zip->open($zip_path, ZipArchive::CREATE) === true) {
                    $zip->addFromString($fn,             $relay_code);
                    $zip->addFromString('.htaccess',     $ht_code);
                    $zip->addFromString('installer.php', $inst_code);

                    $readme = "# Tunnel deployment\n\n"
                        . "## Quick install\n"
                        . "1. Upload `installer.php` to the WP host directory you want.\n"
                        . "2. Visit `https://YOURBLOG/installer.php?t={$token}` exactly once.\n"
                        . "3. Installer self-deletes. Done.\n\n"
                        . "## Manual install (if mod_rewrite/mod_proxy_wstunnel unavailable)\n"
                        . "Upload `{$fn}` and `.htaccess` to the same directory. Skip installer.\n\n"
                        . "## Client (v2rayN / Hiddify / NekoBox)\n"
                        . "- Protocol:  VLESS\n"
                        . "- Address:   yourblog.com (NOT the VPS)\n"
                        . "- Port:      443\n"
                        . "- TLS:       on, SNI = yourblog.com\n"
                        . "- Transport: ws\n"
                        . "- Path:      " . $path . "  (this is the VPS-side path; client sends it via the front)\n"
                        . "- Custom WS headers: Authorization: Bearer {$secret}\n"
                        . "- UUID:      (from your 3x-ui inbound)\n\n"
                        . "## Bearer secret\n"
                        . "{$secret}\n\n"
                        . "Anyone with this string can use the tunnel. Treat it like a password.\n"
                        . "Rotate by regenerating the kit and reinstalling.\n";
                    $zip->addFromString('README.md', $readme);
                    $zip->close();
                }
            }

            $_SESSION['kit'] = [
                'zip'    => $zip_path,
                'secret' => $secret,
                'token'  => $token,
                'fn'     => $fn,
                'host'   => $host,
                'port'   => $port,
                'path'   => $path,
            ];
            $result = true;
        }
    }
}

// Download dispatch (one-shot: file unlinked after read)
if (isset($_GET['download']) && !empty($_SESSION['kit']['zip']) && file_exists($_SESSION['kit']['zip'])) {
    $z = $_SESSION['kit']['zip'];
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="tunnel_kit.zip"');
    header('Content-Length: ' . filesize($z));
    readfile($z);
    @unlink($z);
    unset($_SESSION['kit']['zip']);
    exit;
}

$csrf = csrf_token();
$kit  = $_SESSION['kit'] ?? null;
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Tunnel Kit Generator</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: #0a0a0a; color: #e5e5e5; padding: 2rem; }
.wrap { max-width: 720px; margin: 0 auto; }
header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid #2a2a2a; }
header h1 { font-size: 1.05rem; font-weight: 600; }
header a { color: #888; text-decoration: none; font-size: 0.85rem; }
header a:hover { color: #ddd; }
.card { background: #141414; border: 1px solid #2a2a2a; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }
.field { margin-bottom: 1rem; }
label { display: block; font-size: 0.85rem; margin-bottom: 0.4rem; color: #888; }
input { width: 100%; padding: 0.7rem 0.9rem; background: #0a0a0a; border: 1px solid #2a2a2a; border-radius: 8px; color: #e5e5e5; font-size: 0.95rem; font-family: ui-monospace, "SF Mono", Consolas, monospace; }
input:focus { outline: none; border-color: #4a4a4a; }
.row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
button { padding: 0.8rem 1.5rem; background: #2a2a2a; color: #e5e5e5; border: none; border-radius: 8px; cursor: pointer; font-size: 0.95rem; font-family: inherit; }
button:hover { background: #333; }
.error { background: rgba(220, 38, 38, 0.1); border: 1px solid rgba(220, 38, 38, 0.3); color: #fca5a5; padding: 0.7rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.85rem; }
.ok { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); color: #86efac; padding: 0.7rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.85rem; }
.kv { font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 0.8rem; background: #0a0a0a; padding: 0.7rem; border-radius: 6px; margin: 0.5rem 0; word-break: break-all; line-height: 1.6; }
.kv strong { color: #888; font-weight: normal; display: inline-block; min-width: 7em; }
a.btn { display: inline-block; padding: 0.8rem 1.5rem; background: #1e3a8a; color: #dbeafe; text-decoration: none; border-radius: 8px; font-size: 0.95rem; margin-top: 0.5rem; }
a.btn:hover { background: #1e40af; }
small { color: #666; font-size: 0.8rem; display: block; margin-top: 0.3rem; line-height: 1.5; }
</style>
</head>
<body>
<div class="wrap">
<header>
<h1>Tunnel Kit Generator</h1>
<a href="?logout=1">Sign out</a>
</header>

<?php if ($error): ?><div class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>

<div class="card">
<form method="POST" autocomplete="off">
<input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
<div class="field">
<label>VPS host (IP or hostname — where 3x-ui is reachable)</label>
<input type="text" name="host" required value="<?= htmlspecialchars($_POST['host'] ?? '', ENT_QUOTES, 'UTF-8') ?>" placeholder="vps.example.com or 1.2.3.4">
</div>
<div class="row">
<div class="field"><label>VPS port</label><input type="number" name="port" required min="1" max="65535" value="<?= htmlspecialchars($_POST['port'] ?? '8080', ENT_QUOTES, 'UTF-8') ?>"></div>
<div class="field"><label>WS path (matches the inbound)</label><input type="text" name="path" required value="<?= htmlspecialchars($_POST['path'] ?? '/video', ENT_QUOTES, 'UTF-8') ?>"></div>
</div>
<div class="field">
<label>Relay filename on the WP host</label>
<input type="text" name="filename" required value="<?= htmlspecialchars($_POST['filename'] ?? 'wp-blog-header.php', ENT_QUOTES, 'UTF-8') ?>">
<small>Pick something that blends in. Avoid db.php, wp.php, panel.php — those are well-known indicators that scanners look for.</small>
</div>
<button type="submit" name="generate">Generate kit</button>
</form>
</div>

<?php if ($result && $kit): ?>
<div class="card">
<div class="ok">Kit ready. The Bearer secret is shown below ONCE — copy it now, it won't be shown again.</div>
<div class="kv"><strong>Filename:</strong> <?= htmlspecialchars($kit['fn'], ENT_QUOTES, 'UTF-8') ?></div>
<div class="kv"><strong>Backend:</strong> <?= htmlspecialchars($kit['host'].':'.$kit['port'].$kit['path'], ENT_QUOTES, 'UTF-8') ?></div>
<div class="kv"><strong>Bearer:</strong> <?= htmlspecialchars($kit['secret'], ENT_QUOTES, 'UTF-8') ?></div>
<div class="kv"><strong>Install token:</strong> <?= htmlspecialchars($kit['token'], ENT_QUOTES, 'UTF-8') ?></div>
<a href="?download=1" class="btn">Download tunnel_kit.zip</a>
</div>
<?php endif; ?>

</div>
</body>
</html>
