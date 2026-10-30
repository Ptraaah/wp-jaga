# WP Jaga

One-click WordPress hardening in a single small plugin. No bloat, no upsells, no telemetry. "Jaga" is Indonesian for "to guard".

## What it does

Every protection is a checkbox on one settings page (Settings -> WP Jaga), and everything is on by default:

- Security headers: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Hides the WordPress version (generator meta removed, ?ver= scrubbed from assets)
- Disables XML-RPC and pingbacks (authenticated XML-RPC methods answer "disabled on this site")
- REST API user listing requires login (GET /wp/v2/users returns 401 to visitors)
- Blocks author enumeration (?author=1 redirects to the homepage)
- Generic login errors (never reveals whether the username exists)
- Simple login limiter: 5 failed attempts lock the source IP for 15 minutes
- Disables the theme and plugin file editor
- Removes RSD, WLW manifest, and shortlink clutter from the page head

## Install

Download the latest wp-jaga.zip from the Releases page, then in WordPress: Plugins -> Add New -> Upload Plugin. Or drop the wp-jaga folder into wp-content/plugins and activate it.

## Why another security plugin?

The big suites are powerful but heavy, and most small sites only need the ten fixes above. WP Jaga is one file you can actually read end to end before trusting it: about 200 lines, zero external calls, zero settings beyond the checkboxes.

Verified end to end on a live WordPress install: headers present, generator gone, REST user list 401, author scan redirected, XML-RPC write methods disabled.

## Indonesian summary

Plugin pengaman WordPress sekali klik: header keamanan, sembunyikan versi, matikan XML-RPC, blokir enumerasi user dan author, pesan error login generik, pembatas percobaan login, dan matikan editor file. Satu file, tanpa bloat, semua bisa dimatikan per item dari satu halaman pengaturan.

## License

GPL-2.0-or-later. By ptraaa.

## Support

If this project helped you, you can support its development on Trakteer: https://trakteer.id/adel_putra2

Kalau proyek ini membantu Anda, Anda bisa mendukung pengembangannya lewat Trakteer: https://trakteer.id/adel_putra2
