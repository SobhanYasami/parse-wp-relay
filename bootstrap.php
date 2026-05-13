<?php
declare(strict_types=1);

/*
 * Shared bootstrap for index.php / panel.php / probe.php.
 * Loads config from a path OUTSIDE the web docroot and sets hardened
 * session cookie flags before session_start().
 */

// Resolve config path. Prefer environment override; fall back to a sibling
// directory of the docroot named "private". Never put config inside docroot.
$cfg_path = getenv('IRECLIPS_CONFIG')
    ?: dirname(__DIR__) . '/private/iraneclips_config.php';

if (!is_readable($cfg_path)) {
    http_response_code(500);
    exit('config missing');
}
$CONFIG = require $cfg_path;

if (!is_array($CONFIG) || empty($CONFIG['admin_hash']) || empty($CONFIG['admin_user'])) {
    http_response_code(500);
    exit('config invalid');
}

session_name($CONFIG['session_name'] ?? 'IRECLIPS');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => true,            // HTTPS only — refuse to leak the cookie over HTTP
    'httponly' => true,            // not reachable from JS
    'samesite' => 'Strict',        // mitigate CSRF & cross-origin login leaks
]);
session_start();

// --- Security headers on every response (login + panel) ----------------------
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'");

// --- CSRF --------------------------------------------------------------------
function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_check(?string $token): bool {
    return is_string($token)
        && !empty($_SESSION['csrf'])
        && hash_equals($_SESSION['csrf'], $token);
}

// --- Auth gate ---------------------------------------------------------------
function require_auth(): void {
    if (empty($_SESSION['auth']) || $_SESSION['auth'] !== true) {
        header('Location: index.php');
        exit;
    }
    // 30-minute idle timeout
    if (!empty($_SESSION['last_activity']) && time() - $_SESSION['last_activity'] > 1800) {
        $_SESSION = [];
        session_destroy();
        header('Location: index.php?timeout=1');
        exit;
    }
    $_SESSION['last_activity'] = time();
}

// --- Sliding-window rate limit (file-backed) --------------------------------
function rate_limit(string $key, int $max, int $window_seconds): bool {
    global $CONFIG;
    $dir = $CONFIG['rate_limit_dir'] ?? sys_get_temp_dir() . '/ireclips_rate';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $file = $dir . '/' . hash('sha256', $key);

    $now = time();
    $entries = [];
    if (file_exists($file)) {
        $entries = json_decode((string)@file_get_contents($file), true) ?: [];
    }
    $entries = array_values(array_filter(
        $entries,
        static fn($t) => is_int($t) && $t > $now - $window_seconds
    ));
    if (count($entries) >= $max) return false;
    $entries[] = $now;
    @file_put_contents($file, json_encode($entries), LOCK_EX);
    return true;
}
