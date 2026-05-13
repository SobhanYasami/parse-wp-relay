<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require_auth();

// Admin-only connectivity probe. Replaces test.php.
// Never accessible unauthenticated; never leaks errno/errstr.

if (!csrf_check($_GET['csrf'] ?? null)) {
    http_response_code(403);
    exit;
}

$host = (string)($_GET['host'] ?? '');
$port = (int)($_GET['port'] ?? 0);

if (!filter_var($host, FILTER_VALIDATE_IP)
    && !preg_match('/^[a-zA-Z0-9.\-]{1,253}$/', $host)) {
    http_response_code(400);
    exit('bad host');
}
if ($port < 1 || $port > 65535) {
    http_response_code(400);
    exit('bad port');
}

header('Content-Type: application/json');
$fp = @fsockopen($host, $port, $errno, $errstr, 5);
if ($fp) {
    fclose($fp);
    echo json_encode(['ok' => true]);
} else {
    http_response_code(502);
    echo json_encode(['ok' => false]);
}
