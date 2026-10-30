=== WP Jaga ===
Contributors: ptraaa
Tags: security, hardening, xmlrpc, headers, login
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

One-click WordPress hardening: security headers, XML-RPC off, enumeration blocked, login protected. Small and readable.

== Description ==

WP Jaga applies the ten hardening fixes every WordPress site needs, each toggleable from a single settings page:

* Security headers (frame options, MIME sniffing, referrer, permissions policy)
* WordPress version hidden (generator meta and asset version strings)
* XML-RPC and pingbacks disabled
* REST API user listing requires authentication
* Author enumeration blocked (?author=1 redirects home)
* Generic login error messages
* Login attempt limiter (5 failures lock the IP for 15 minutes)
* Theme and plugin file editor disabled
* RSD, WLW manifest and shortlink clutter removed

One file, no external calls, no telemetry, no upsells.

== Installation ==

1. Upload the wp-jaga folder to /wp-content/plugins/ (or install the zip via Plugins -> Add New -> Upload).
2. Activate WP Jaga.
3. Optionally review the checkboxes under Settings -> WP Jaga. Everything is on by default.

== Changelog ==

= 1.0.0 =
* Initial release.
