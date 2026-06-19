# Configuration reference

This document describes the runtime settings and related operational behavior. Most options are configured in the UI and stored in the database; environment variables override behavior where applicable.

## Network and listener settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `BIND_ADDRESS` | `0.0.0.0` | Listen address. Use `127.0.0.1` when a local reverse proxy fronts the UI. |

Example:

```bash
-e PORT=3080 -e BIND_ADDRESS=127.0.0.1
```

For production reverse proxy patterns, see [reverse-proxy.md](reverse-proxy.md).

## HTTP base path (subpath deployment)

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_PATH` | unset (`/`) | Optional URL path prefix under which the application is served. Environment-only; not configurable in the UI. |

With `BASE_PATH=/myf2b`, the UI, static files, API, WebSocket, and OIDC routes are reachable under `https://host/myf2b/...`.

Rules:

* Use a single leading slash and no trailing slash: `/myf2b`, not `myf2b/`.
* When set, the application is served only under that prefix. Visiting `/` redirects to `{BASE_PATH}/`; non-prefixed paths are not served.
* The reverse proxy must forward requests *with* the path prefix to Fail2Ban UI. See [reverse-proxy.md](reverse-proxy.md).

When `BASE_PATH` is set, align the related URLs:

* `CALLBACK_URL` must include the prefix, for example `https://fail2ban.example.com/myf2b` (no trailing slash).
* `OIDC_REDIRECT_URL` must include the prefix, for example `https://fail2ban.example.com/myf2b/auth/callback`.

## Callback URL and secret (Fail2Ban to Fail2ban-UI)

Fail2Ban UI receives ban and unban callbacks at:

* `POST {BASE_PATH}/api/ban` (`POST /api/ban` by default)
* `POST {BASE_PATH}/api/unban` (`POST /api/unban` by default)

| Variable | Description |
|----------|-------------|
| `CALLBACK_URL` | URL reachable from every managed Fail2Ban host: scheme, host, optional port, and `BASE_PATH` if used. No trailing slash. |
| `CALLBACK_SECRET` | Shared secret validated through the `X-Callback-Secret` header. If unset, Fail2Ban UI generates one on first start. |

Example:

```bash
-e CALLBACK_URL=http://10.88.0.1:3080 \
-e CALLBACK_SECRET='replace-with-a-random-secret'
```

With a subpath:

```bash
-e BASE_PATH=/myf2b \
-e CALLBACK_URL=https://fail2ban.example.com/myf2b \
-e CALLBACK_SECRET='replace-with-a-random-secret'
```

## Privacy and telemetry controls

| Variable | Description |
|----------|-------------|
| `DISABLE_EXTERNAL_IP_LOOKUP=true` | Disables the external public-IP lookup used for display in the UI |
| `UPDATE_CHECK=false` | Disables the GitHub release update check |

## UI behavior flags

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTODARK` | `false` | When `true`, enables automatic dark mode based on the browser or OS preference. The default remains light mode. |

## Fail2Ban configuration migration

| Variable | Description |
|----------|-------------|
| `JAIL_AUTOMIGRATION=true` | Experimental migration from a monolithic `jail.local` to `jail.d/*.local`. On production systems, migrate manually instead. |

## Alert settings (UI-managed)

Configure under **Settings → Alert Settings**:

* Provider: `email`, `webhook`, or `elasticsearch`
* Enable alerts for bans and/or unbans
* Alert country filters
* GeoIP provider and log-line limits

For provider behavior and payloads, see [alert-providers.md](alert-providers.md) and [webhooks.md](webhooks.md).

## Threat intelligence settings (UI-managed)

Configure under **Settings → Alert Settings**:

* `threatIntel.provider`: `none`, `alienvault`, or `abuseipdb`
* `threatIntel.alienVaultApiKey` (for `alienvault`)
* `threatIntel.abuseIpDbApiKey` (for `abuseipdb`)

Runtime behavior:

* Queries run server-side through `GET /api/threat-intel/:ip`.
* Successful responses are cached for 30 minutes per provider and IP.
* An upstream `429` triggers a retry window with backoff and stale-cache fallback.

See [threat-intel.md](threat-intel.md) for details.

## OIDC authentication

Required when OIDC is enabled:

| Variable | Description |
|----------|-------------|
| `OIDC_ENABLED=true` | Enables OIDC authentication |
| `OIDC_PROVIDER` | `keycloak`, `authentik`, or `pocketid` |
| `OIDC_ISSUER_URL` | Issuer URL; must match the provider's discovery document |
| `OIDC_CLIENT_ID` | Client ID configured at the provider |
| `OIDC_CLIENT_SECRET` | Client secret |
| `OIDC_REDIRECT_URL` | `https://<ui-host>{BASE_PATH}/auth/callback`, for example `https://<ui-host>/myf2b/auth/callback` with `BASE_PATH=/myf2b` |

Common optional variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_SCOPES` | `openid,profile,email` | Requested scopes, comma-separated |
| `OIDC_SESSION_SECRET` | auto-generated | Session signing secret; 32 or more bytes recommended |
| `OIDC_SESSION_MAX_AGE` | `3600` | Session lifetime in seconds |
| `OIDC_USERNAME_CLAIM` | `preferred_username` | Claim used as the display username |
| `OIDC_SKIP_VERIFY` | `false` | Skips TLS verification toward the provider. Development only. |
| `OIDC_SKIP_LOGINPAGE` | `false` | Skips the UI login page and redirects to the provider directly |

Provider notes:

* **Keycloak**: allow the redirect URI `{BASE_PATH}/auth/callback` (or `/auth/callback` at root) and the post-logout redirect `{BASE_PATH}/auth/login`.
* **Authentik / Pocket-ID**: the redirect URI must match exactly, including any `BASE_PATH` prefix.

A ready-to-run OIDC test environment is available under [development/oidc/README.md](../development/oidc/README.md).

## Email template style

| Variable | Description |
|----------|-------------|
| `emailStyle=classic` | Uses the classic email template instead of the default modern template (Email provider only) |
