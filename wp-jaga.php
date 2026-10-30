<?php
/**
 * Plugin Name:       WP Jaga
 * Plugin URI:        https://github.com/Ptraaah/wp-jaga
 * Description:       One-click WordPress hardening: security headers, XML-RPC off, REST and author enumeration blocked, generic login errors, a simple login limiter, and editor lockdown. Small, fast, no bloat.
 * Version:           1.0.0
 * Author:            ptraaa
 * Author URI:        https://github.com/Ptraaah
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-jaga
 *
 * WP Jaga - "jaga" is Indonesian for "to guard". Guard your site.
 */

if (!defined('ABSPATH')) {
    exit;
}

final class WP_Jaga {

    const OPTION = 'wp_jaga_options';

    public static function defaults(): array {
        return [
            'headers'        => 1, // security response headers
            'hide_version'   => 1, // generator meta + asset version scrub
            'disable_xmlrpc' => 1, // XML-RPC and pingbacks off
            'rest_users'     => 1, // /wp/v2/users needs authentication
            'author_enum'    => 1, // ?author=1 redirects home
            'login_errors'   => 1, // generic login failure message
            'login_limit'    => 1, // simple login attempt limiter
            'file_editor'    => 1, // disable theme/plugin editor
            'tidy_head'      => 1, // remove RSD / WLW / shortlink clutter
        ];
    }

    public static function opts(): array {
        $saved = get_option(self::OPTION, []);
        return array_merge(self::defaults(), is_array($saved) ? $saved : []);
    }

    public static function boot(): void {
        $o = self::opts();

        if ($o['headers']) {
            add_action('send_headers', [self::class, 'headers']);
        }
        if ($o['hide_version']) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
            add_filter('style_loader_src', [self::class, 'scrub_version'], 9999);
            add_filter('script_loader_src', [self::class, 'scrub_version'], 9999);
        }
        if ($o['disable_xmlrpc']) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', static function (array $h): array {
                unset($h['X-Pingback']);
                return $h;
            });
            add_filter('pings_open', '__return_false');
        }
        if ($o['rest_users']) {
            add_filter('rest_pre_dispatch', [self::class, 'guard_rest_users'], 10, 3);
        }
        if ($o['author_enum']) {
            add_action('init', [self::class, 'block_author_enum']);
        }
        if ($o['login_errors']) {
            add_filter('login_errors', static fn(): string =>
                '<strong>Error:</strong> Invalid username or password.');
        }
        if ($o['login_limit']) {
            add_filter('authenticate', [self::class, 'limit_check'], 30, 3);
            add_action('wp_login_failed', [self::class, 'limit_record']);
            add_action('wp_login', [self::class, 'limit_clear']);
        }
        if ($o['file_editor'] && !defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }
        if ($o['tidy_head']) {
            remove_action('wp_head', 'rsd_link');
            remove_action('wp_head', 'wlwmanifest_link');
            remove_action('wp_head', 'wp_shortlink_wp_head');
            remove_action('template_redirect', 'wp_shortlink_header', 11);
        }

        if (is_admin()) {
            add_action('admin_menu', [self::class, 'menu']);
            add_action('admin_init', [self::class, 'register_settings']);
        }
    }

    /* ---------------- protections ---------------- */

    public static function headers(): void {
        if (!headers_sent()) {
            header('X-Frame-Options: SAMEORIGIN');
            header('X-Content-Type-Options: nosniff');
            header('Referrer-Policy: strict-origin-when-cross-origin');
            header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        }
    }

    public static function scrub_version(string $src): string {
        if (str_contains($src, 'ver=')) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }

    /** @param mixed $result */
    public static function guard_rest_users($result, $server, $request) {
        $route = $request->get_route();
        if (preg_match('#^/wp/v2/users(/|$)#', $route) && !is_user_logged_in()) {
            return new WP_Error(
                'wp_jaga_rest_users',
                'Listing users requires authentication.',
                ['status' => 401]
            );
        }
        return $result;
    }

    public static function block_author_enum(): void {
        if (!is_admin() && isset($_GET['author']) && is_numeric($_GET['author'])) {
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }

    /* ---------------- login limiter ---------------- */

    private static function limit_key(): string {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        return 'wp_jaga_fail_' . md5($ip);
    }

    /** @param mixed $user */
    public static function limit_check($user, $username, $password) {
        if ($username === '' || $username === null) {
            return $user;
        }
        $fails = (int) get_transient(self::limit_key());
        if ($fails >= 5) {
            return new WP_Error(
                'wp_jaga_limited',
                '<strong>Error:</strong> Too many failed login attempts. Try again in a few minutes.'
            );
        }
        return $user;
    }

    public static function limit_record(string $username): void {
        $key = self::limit_key();
        $fails = (int) get_transient($key);
        set_transient($key, $fails + 1, 15 * MINUTE_IN_SECONDS);
    }

    public static function limit_clear(): void {
        delete_transient(self::limit_key());
    }

    /* ---------------- settings page ---------------- */

    public static function menu(): void {
        add_options_page('WP Jaga', 'WP Jaga', 'manage_options', 'wp-jaga', [self::class, 'page']);
    }

    public static function register_settings(): void {
        register_setting('wp_jaga_group', self::OPTION, [
            'type' => 'array',
            'sanitize_callback' => [self::class, 'sanitize'],
        ]);
    }

    public static function sanitize($input): array {
        $clean = [];
        foreach (self::defaults() as $key => $_) {
            $clean[$key] = (!empty($input[$key])) ? 1 : 0;
        }
        return $clean;
    }

    public static function page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }
        $o = self::opts();
        $labels = [
            'headers'        => 'Security headers (frame, MIME sniffing, referrer, permissions)',
            'hide_version'   => 'Hide the WordPress version (generator meta and asset ?ver=)',
            'disable_xmlrpc' => 'Disable XML-RPC and pingbacks',
            'rest_users'     => 'Require login to list users through the REST API',
            'author_enum'    => 'Block author enumeration (?author=1 redirects home)',
            'login_errors'   => 'Generic login error (never reveal if the username exists)',
            'login_limit'    => 'Login limiter (5 failures lock the IP for 15 minutes)',
            'file_editor'    => 'Disable the theme and plugin file editor',
            'tidy_head'      => 'Remove RSD, WLW manifest and shortlink clutter from the head',
        ];
        echo '<div class="wrap"><h1>WP Jaga</h1>';
        echo '<p>One-click hardening. Changes apply immediately. Turn anything off if it conflicts with another plugin.</p>';
        echo '<form method="post" action="options.php">';
        settings_fields('wp_jaga_group');
        echo '<table class="form-table"><tbody>';
        foreach ($labels as $key => $label) {
            printf(
                '<tr><th scope="row">%s</th><td><label><input type="checkbox" name="%s[%s]" value="1" %s> Enabled</label></td></tr>',
                esc_html($label),
                esc_attr(self::OPTION),
                esc_attr($key),
                checked(1, $o[$key], false)
            );
        }
        echo '</tbody></table>';
        submit_button();
        echo '</form>';
        // a small signature, only on this page. hello, fellow source reader.
        echo '<p style="color:#888">WP Jaga by <a href="https://github.com/Ptraaah" target="_blank" rel="noopener">ptraaa</a> - free and open source (GPL-2.0).</p>';
        echo '</div>';
    }
}

add_action('plugins_loaded', ['WP_Jaga', 'boot']);
