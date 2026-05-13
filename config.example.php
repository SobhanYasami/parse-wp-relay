<?php
/*
 * iraneclips_config.php
 *
 * Place OUTSIDE the web docroot, e.g.:
 *   /home/USER/private/iraneclips_config.php
 *
 * Or, if your host doesn't allow that, put it under docroot AND add an
 * .htaccess rule next to it:
 *
 *   <Files "iraneclips_config.php">
 *     Require all denied
 *   </Files>
 *
 * Generate admin_hash offline:
 *
 *   php -r "echo password_hash('YOUR_REAL_PASSWORD', PASSWORD_BCRYPT, ['cost'=>12]), PHP_EOL;"
 *
 * Generate csrf_secret:
 *
 *   openssl rand -hex 32
 */
return [
    'admin_user'      => 'admin',
    'admin_hash'      => '$2y$12$REPLACE_THIS_WITH_REAL_BCRYPT_HASH_FROM_CLI_GENERATOR',
    'session_name'    => 'IRECLIPS',
    'rate_limit_dir'  => '/tmp/ireclips_rate',
];
