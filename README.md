# localoidc

**Development only. Synthetic identity, no authentication. Never trust this issuer in production.**

A small standalone OpenID Connect tool for local applications. It serves discovery,
JWKS, authorization-code exchange, RS256-signed ID tokens, and UserInfo. Any nonempty
client ID and arbitrary client secrets are accepted. Login is one confirmation
button, not a password. One configured identity and fresh signing keys per process.

## Run

Requires Go 1.26 or newer. No external runtime services or frontend build.

```sh
go build -o localoidc .
./localoidc
# Or use the sample identity and additional scopes:
./localoidc --config localoidc.example.json --port 8080
./localoidc --version
```

Plain `go build` reports `dev` with unknown commit/build time. Release builds embed
the version, full commit and UTC build time; `--version` exits without reading
runtime configuration or opening a listener.

Configure your local OIDC client with issuer **`http://127.0.0.1:8080`**, any
nonempty client ID, and a local callback. The client must explicitly allow a
development HTTP issuer. Use that exact issuer, not `localhost` or a trailing slash.

Supported token client modes:

- `client_secret_basic`: any nonempty secret, OAuth form-encoded Basic credentials.
- `client_secret_post`: any nonempty secret in an URL-encoded POST body.
- `none`: no secret or an empty secret; **S256 PKCE is required**.

S256 PKCE is also supported for clients supplying secrets. Plain PKCE is rejected.
Client-ID, exact callback, nonce, audience, issuer, expiration, and code-verifier
validation are not bypassed. Codes are one-time, including concurrent redemption;
an exchange attempt that reaches code lookup consumes the code even if subsequent
client/redirect/PKCE validation fails. Start a new authorization request after failure.

Default confirmation shows **Sign in locally**, the configured name and email (with
the subject as a fallback when no name is configured), client, scopes and callback.
One **Login** button confirms the identity; there are no editable fields or account
selectors. Closing the tab abandons the request. The dark interface uses system
fonts and an embedded, locally served stylesheet: no external assets, JavaScript,
or frontend build step. Its appearance is fixed; configure identity claims through
`identity`, not through UI-specific settings.

```sh
LOCALOIDC_SKIP_CONFIRMATION=true ./localoidc
./localoidc --skip-confirmation
# Explicit false overrides a true environment setting:
./localoidc --skip-confirmation=false
```

`prompt=none` never displays UI: it returns `interaction_required` unless automatic
approval is enabled. Explicit `prompt=login`, `consent`, or `select_account` still
requires confirmation. `none` combined with another prompt is invalid.

## Configuration

Precedence: built-in defaults → selected JSON file → environment → explicit flags.
Restart to reload. Unknown file keys/`LOCALOIDC_*` variables, invalid types, and
out-of-range values fail startup. Composite settings replace, rather than merge,
the defaults. `--help` lists CLI options. Runtime flags are `--port`, `--config`, and
`--skip-confirmation`; other settings are file/environment values. `--version`
prints build metadata and exits.

| JSON key | Environment | Default |
| --- | --- | --- |
| `port` | `HTTP_PORT` | `8080`, range 1–65535 |
| selected file (CLI `--config`) | `LOCALOIDC_CONFIG` | no file |
| `skip_confirmation` | `LOCALOIDC_SKIP_CONFIRMATION` | `false` |
| `identity` | `LOCALOIDC_IDENTITY` | local-user / Local Developer / developer@localhost |
| `scopes` | `LOCALOIDC_SCOPES` | openid, profile, email mappings |
| `redirect_uris` | `LOCALOIDC_REDIRECT_URIS` | `[]`: any valid local callback |
| `request_lifetime` | `LOCALOIDC_REQUEST_LIFETIME` | `5m` |
| `code_lifetime` | `LOCALOIDC_CODE_LIFETIME` | `1m` |
| `token_lifetime` | `LOCALOIDC_TOKEN_LIFETIME` | `1h` |
| `max_transactions` | `LOCALOIDC_MAX_TRANSACTIONS` | `1024`, range 1–10000 |

See [`localoidc.example.json`](localoidc.example.json) for the complete schema.
Composite environment values are JSON, for example
`LOCALOIDC_SCOPES='{"openid":[],"email":["email","email_verified"]}'`.
Durations use Go duration syntax and must be between `1s` and `24h`.
The live request and token maps each have the configured hard capacity. Expired
entries are reclaimed on activity; valid entries are never silently evicted.

`identity` contains a nonempty stable `sub` (no colon, due to the library's opaque
bearer format) and a `claims` object. Standard claims retain their proper types;
custom claims preserve JSON booleans, arrays, numbers (including large integers),
and objects. Scope mappings select which claims appear in **both ID tokens and
UserInfo**; `sub` is always present. `openid` must be defined and requested. Unknown
scopes and `offline_access` are rejected. Generated protocol claims (`iss`, `aud`,
timestamps, nonce, hashes, etc.) cannot be overridden through claim configuration.

## Boundaries and limitations

- Listens only on **127.0.0.1**, never all interfaces. There is no host flag.
  `HTTP_ADDRESS` is rejected. Incoming Host must be the exact canonical authority;
  forwarded/proxy headers do not alter the issuer. A port conflict fails startup.
- Callback hosts must be exactly `localhost`, `127.0.0.1`, or `[::1]`, using HTTP(S).
  Any valid local port is accepted. No userinfo, fragments, custom schemes, hostname
  lookalikes, remote destinations, or DNS resolution. Nonempty `redirect_uris`
  further narrows callbacks to exact URI matches, including port/path/query.
- No refresh/device/client-credentials/JWT grants, implicit/hybrid flow, logout,
  introspection, revocation, dynamic registration, or remote metadata fetching.
  Discovery does not advertise those features; their routes are not mounted.
  Only query-mode authorization responses are supported. No SPA CORS support.
- Confirmation uses an escaped form, transaction-bound one-time CSRF state and an
  HttpOnly SameSite cookie. Framing is disabled and responses have a restrictive
  CSP (only same-origin styles and form submissions) and no-store policy.
  `Referrer-Policy: same-origin` preserves normal Chromium
  form Origin behavior while suppressing referrers on cross-origin requests,
  including callbacks on different loopback ports. Requests, codes, secrets and
  tokens are not logged. This does **not** isolate the tool from other local
  users/processes.
- Restart discards pending codes, access tokens and keys. Previously issued ID
  tokens may still validate until expiry at clients caching the old public key;
  restart is not universal immediate JWT revocation.
- HTTP issuer and intentionally permissive clients are development deviations,
  not production OIDC authentication or a conformance/certification claim.
- Tunnels, reverse proxies, shared-host deployment and remote port forwarding are
  unsupported and can defeat loopback isolation. Containers require **native Linux
  host networking**, as described below. Docker bridge `-p` publishing cannot reach
  a container-loopback listener. Docker Desktop, WSL and VM networking arrangements
  are unsupported/unvalidated; use the native binary instead.

## Distribution and containers

GoReleaser OSS **v2.17.0** produces Linux, macOS (`darwin`) and Windows binaries
for both amd64 and arm64. Linux/macOS archives are `.tar.gz`; Windows archives are
`.zip`. Names are `localoidc_<version>_<os>_<arch>.<format>`. Each archive includes
the binary, LICENSE, this README and the sample configuration. `checksums.txt`
contains SHA-256 checksums. These are unsigned archives; there is no macOS signing or
notarization. Cross-compilation does not establish runtime compatibility: only
Linux amd64 is runtime-validated here.

### Build locally without publishing

Install Go 1.26+, GoReleaser OSS v2.17.0, Docker and buildx separately. From the
repository root:

```sh
goreleaser check
goreleaser release --snapshot --clean --skip=publish --parallelism 2 --timeout 15m
```

This replaces `dist/` with six native binaries, archives, checksums and metadata.
With **v2.17.0**, this snapshot command also builds and loads separately tagged
local Linux amd64/arm64 images; it does not push images or create a GitHub release.
The log gives their exact names (`ghcr.io/renevo/localoidc:<snapshot-tag>-amd64`
and `...-arm64`). They are local images despite the registry-qualified names.
Snapshot image tags are not a multi-platform registry index. The `dockers_v2`
configuration uses prebuilt, `CGO_ENABLED=0` binaries, so no QEMU or privileged
binfmt installation is needed: the Dockerfile never executes target binaries.
In a checkout without a Git remote, GoReleaser snapshots may report commit `none`;
tagged releases from GitHub embed the real full commit.

`docker build .` is **not** a source build: this Dockerfile expects GoReleaser's
temporary build context containing `linux/amd64/localoidc` and
`linux/arm64/localoidc`. Use the snapshot command rather than duplicating that
build process. The scratch image contains only the executable and runs as
`65532:65532`. There is no shell, CA bundle, package manager or writable runtime
state; the application needs neither outbound connections nor filesystem writes.

### Run a container on native Linux

Use the local snapshot's amd64 or arm64 tag, or a published version tag after a
release exists. For a future published release, substitute the actual tag:

```sh
IMAGE=ghcr.io/renevo/localoidc:vX.Y.Z
docker run --rm --name localoidc --network host \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e HTTP_PORT=8080 "$IMAGE"
```

The issuer remains exactly **`http://127.0.0.1:8080`** on the Linux host. Do not
add `-p`, use bridge networking, or change the listener to a wildcard address.
Host networking shares the host's network namespace; it is not isolation from
other host processes. Use an unused port, and never expose the issuer remotely.
For reproducible runs, replace the version tag with the published index digest,
`ghcr.io/renevo/localoidc@sha256:...`.

To mount configuration, add these options before `"$IMAGE"`, then append
`--config /config.json` after it:

```sh
--mount "type=bind,src=$(pwd)/localoidc.example.json,dst=/config.json,readonly"
```

The mounted file must be readable by UID 65532. The supplied synthetic sample may
have mode `0600`; `chmod 0644 localoidc.example.json` makes that sample readable.
Do not make sensitive files world-readable just to mount them. Environment
configuration and application flags work as with the native binary.

### Future tag publication

Nothing is published by a local snapshot or pull-request CI. After this repository
is hosted at `github.com/renevo/localoidc`, review/merge the changes and explicitly
push a new semantic version tag such as `v0.1.0`. The tag-only release workflow:

1. Checks formatting, runs core tests with the race detector, runs `go vet`, and
   validates the GoReleaser configuration. Ordinary branch/PR CI runs those same
   checks without registry login or image publication.
2. Uses `GITHUB_TOKEN` with `contents: write` and `packages: write` to create the
   GitHub release with archives/checksums and push
   **`ghcr.io/renevo/localoidc:<tag>`**, containing linux/amd64 and linux/arm64.
   There is no `latest` alias. The source label associates the package with this
   repository; an existing package may require granting this repository Actions
   access before publication can succeed.

Initial GHCR packages may be **private**;
anonymous pulls require a separate, explicit package-visibility change in GitHub.
No remote publication, permissions or visibility change is part of local setup.

## Implementation and checks

Uses ZITADEL OIDC **v3.51.16** for protocol handling and signing; configuration uses
`renevo/config` **v0.6.0**, Bootstrap's actual configuration library. Bootstrap
v0.9.0 was source-inspected: its mandatory combined request logging and proxy-header
middleware conflict with the application's boundaries. The approved fallback is
minimal `net/http`, signal-based graceful shutdown and structured `slog`, not a
replacement framework. Dependency logs retain fixed messages/severity only to
avoid leaking submitted parameters. No NATS/exporters or other runtime services.

```sh
go test -race -count=1 -timeout=60s ./...
go vet ./...
```

Tests cover application-owned configuration precedence/types, loopback and callback
policies, claim release, prompt decisions, client-mode selection and bounded,
one-time, expiring state. Assertions use only `github.com/matryer/is`. There is no
committed integration test suite or browser automation.

Core validation used one-off Python standard-library HTTP requests (not a
third-party relying-party application) against the running binary. Basic, POST,
and public S256 exchanges, confirmation/code replay rejection, UserInfo typed
claims, prompt behavior, Host rejection and unsupported routes were exercised.
ID-token RS256 signatures were verified against the served JWKS with Python
`cryptography`, together with issuer/audience/nonce/expiry checks. One-off Playwright
checks using Chrome 147 also exercised Login → continuation → local callback →
token exchange, RS256/JWKS verification, issuer/audience/nonce/expiry checks, and
typed UserInfo claims with both normal and long-value configurations. Basic, POST,
and public client modes, automatic approval, and `prompt=none`, `login`, `consent`,
and `select_account` were exercised in core validation.

Screenshots of the styled pages were captured and personally inspected at desktop
(1440×1000), narrow (390px and 320px wide), and short (390×500) sizes, including
long name/email/client/scope/callback values, hover/focus/pressed states, expired
requests, and the continuation fallback at desktop and narrow widths. Geometry
checks found no horizontal overflow, confirmed that headings remained reachable
at the top of the page, and checked a minimum 44px button height. These were
one-off checks, not a committed Playwright suite or automated visual regression
coverage. Third-party relying-party compatibility remains untested.

Manual smoke checklist:

1. Start with the sample config. Check the warning and exact loopback issuer;
   inspect discovery at `/.well-known/openid-configuration` and JWKS at `/keys`.
2. With a local callback listener or relying-party app, request
   `openid profile email groups` with a nonce and S256 PKCE. Confirm Login, exchange
   the callback code, validate the ID-token RS256 signature against `/keys` and its
   issuer/audience/nonce/expiry, then call `/userinfo` and verify claim types.
   Repeat with long identity, client, scope, and callback values. Record the browser
   and client or one-off script used.
3. Repeat with Basic, POST, and public S256 clients, automatic approval, and
   `prompt=none`, `login`, `consent`, and `select_account`. Reusing an authorization
   code must fail.
4. Stop with Ctrl-C; restart and confirm that the old access token no longer works.
5. Capture and personally inspect 1440×1000, 390px/320px-wide, and 390×500 layouts
   with default and long values; check hover, keyboard focus, and pressed states.
   Check for horizontal overflow, reachable headings, and buttons at least 44px
   high. Inspect expired/invalid confirmation pages and the continuation fallback
   at desktop and narrow widths (disable automatic refresh to inspect the fallback).

## License

Licensed under the [MIT License](LICENSE).
