<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

// Already logged in? Skip the form.
if (!empty($_SESSION['auth'])) {
    header('Location: panel.php');
    exit;
}

$error = null;
if (isset($_GET['timeout'])) $error = 'Session expired. Sign in again.';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (!rate_limit("login:$ip", 5, 300)) {
        $error = 'Too many attempts. Wait 5 minutes.';
    } elseif (!csrf_check($_POST['csrf'] ?? null)) {
        $error = 'Invalid request.';
    } else {
        $user = (string)($_POST['user'] ?? '');
        $pass = (string)($_POST['pass'] ?? '');

        // Always run password_verify even when user is wrong — same timing for both.
        $valid_user = hash_equals($CONFIG['admin_user'], $user);
        $valid_pass = password_verify($pass, $CONFIG['admin_hash']);

        if ($valid_user && $valid_pass) {
            session_regenerate_id(true);          // mitigate session fixation
            $_SESSION['auth'] = true;
            $_SESSION['last_activity'] = time();
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            header('Location: panel.php');
            exit;
        }

        // Constant-ish jitter so wrong-user vs wrong-pass don't expose an oracle
        usleep(random_int(80000, 120000));
        $error = 'Invalid credentials.';
    }
}

$csrf = csrf_token();
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Admin</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: #0a0a0a; color: #e5e5e5; min-height: 100vh; display: grid; place-items: center; padding: 2rem; }
.card { background: #141414; border: 1px solid #2a2a2a; border-radius: 12px; padding: 2rem; width: 100%; max-width: 380px; }
h1 { font-size: 1.1rem; margin-bottom: 1.5rem; text-align: center; color: #d4d4d4; font-weight: 600; }
.field { margin-bottom: 1rem; }
label { display: block; font-size: 0.85rem; margin-bottom: 0.4rem; color: #888; }
input { width: 100%; padding: 0.7rem 0.9rem; background: #0a0a0a; border: 1px solid #2a2a2a; border-radius: 8px; color: #e5e5e5; font-size: 0.95rem; font-family: inherit; }
input:focus { outline: none; border-color: #4a4a4a; }
button { width: 100%; padding: 0.8rem; background: #2a2a2a; color: #e5e5e5; border: none; border-radius: 8px; cursor: pointer; font-size: 0.95rem; margin-top: 0.5rem; font-family: inherit; }
button:hover { background: #333; }
.error { background: rgba(220, 38, 38, 0.1); border: 1px solid rgba(220, 38, 38, 0.3); color: #fca5a5; padding: 0.7rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.85rem; text-align: center; }
</style>
</head>
<body>
<form class="card" method="POST" autocomplete="off">
<h1>Sign in</h1>
<?php if ($error): ?><div class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
<input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
<div class="field"><label>Username</label><input type="text" name="user" required autocomplete="username"></div>
<div class="field"><label>Password</label><input type="password" name="pass" required autocomplete="current-password"></div>
<button type="submit">Continue</button>
</form>
</body>
</html>
