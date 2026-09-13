# Validation record — 0.1.0-dev

Date: 2026-09-13. Initial host runtime: macOS, darwin/arm64; subsequent checks: Arch Linux, linux/amd64. This is evidence for a development delivery, not a claim that every acceptance criterion in SPEC.md is complete.

## Repeatable commands

```sh
make test
make check
make release
./bin/utlsproxy test --json
./bin/utlsproxy test --profile firefox-120 --json
env GOTOOLCHAIN=go1.27.1 go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

The regular tests use local fixtures, not external fingerprint sites. They do not edit system hosts, install trust, register a service or need sudo.

## Local automated evidence

| Area | Exercised behavior |
| --- | --- |
| Configuration | Strict JSON, duplicate/unknown/null rejection, domain normalization, IPv4 restrictions, defaults, paths and reload boundaries. |
| CA | Key permissions, matching certificate/key, refusal to overwrite complete or partial existing material, single-name leaf trust and hostname rejection. |
| ClientHello | Actual wire bytes from Chrome/Firefox presets; strict ALPN, compatible ALPN, no-ALPN, removal of ALPN-dependent ALPS when h2 is not offered. |
| TLS relay | Verified local upstream and downstream handshakes; HTTP/1.1 and HTTP/2 streamed request/response equality; bad upstream certificate and denied SNI rejection; half-close preserving the reverse stream. |
| Concurrency | 24 independent concurrent TLS tunnels per HTTP version, each transferring a 208,000-byte payload in both directions. Connection-limit rejection and handshake-timeout resource cleanup. |
| DNS | Direct queries to fixture DNS, A/CNAME ownership checks, zero TTL, truncated UDP/TCP retry, NXDOMAIN, no unrelated-resolver fallback, query coalescing, cache/discovery generation and refresh/configuration races. |
| Discovery | macOS resolver parsing, default/supplemental selection, invalid interface handling; Linux Manager property fixtures preserve global routing domains, skip per-link entries and retain custom DNS ports. |
| Control/reload | Private Unix socket, ownership/stale socket safety; valid reload generation change and new-profile connections; invalid listener reload retains active config. |
| Hosts | Temporary-file apply/remove, unrelated comments/aliases and later edits preserved, permission metadata, unmanaged conflicts, malformed markers and concurrent-edit rejection. |
| Service definitions | launchd XML structure and escaping; systemd argument escaping; newline injection rejection. No native registration during tests. |
| CLI/logging | Help/invalid-command exit codes, local config/CA workflow, nonoverwrite behavior, unavailable socket exit code, bounded log rotation and symlink refusal. |
| CA trust | Receipt-owned install/repeat/status/untrust, no-write dry runs, root requirement, public certificate without private key, unmanaged refusal, wrong fingerprint/replaced anchor/symlink rejection, rollback/retry and recovery snapshot use. macOS command arguments and Debian, Fedora and Arch Linux updater/file layouts are exercised with fake native runners. |

`go test -race ./...` and `go vet ./...` passed on the native host. Release builds target macOS/Linux arm64/amd64. Cross-build success does not establish Linux runtime, resolver D-Bus permissions or reboot behavior.

The vulnerability check reports no reachable or imported-package vulnerabilities. A module-level advisory for unused `golang.org/x/crypto/openpgp` remains; utlsproxy does not import it. The unused compress/s2 advisory found in the initial dependency tree was addressed by pinning `github.com/klauspost/compress` to `v1.18.7`.

## Public fingerprint evidence

Target: [tls.peet.ws API](https://tls.peet.ws/api/all). The daemon selected a real LAN upstream DNS server from macOS `scutil --dns` and queried it directly. Both requests used normal certificate verification. Neither hosts nor system trust was changed.

Results from the self-contained `utlsproxy test` command (Go HTTP/2 client):

| TLS connection | Observed JA4 | HTTP/2 Akamai fingerprint hash |
| --- | --- | --- |
| Direct Go TLS | `t13d1312h2_f57a46bbacb6_f50d94e863eb` | `b4e6bd27e907d4aa4316619ce615fda4` |
| Proxied `chrome-133`, strict | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `b4e6bd27e907d4aa4316619ce615fda4` |
| Proxied `firefox-120`, strict | `t13d1715h2_5b57614c22b0_5c2c66f702b0` | `b4e6bd27e907d4aa4316619ce615fda4` |

The TLS fingerprint changed and the HTTP/2 fingerprint stayed the same, as expected for a TLS-only relay. JA3 is also returned but Chrome's shuffled extension ordering makes a fixed JA3 unsuitable as a stable acceptance value. These observations are not universal constants for future toolchains, dependency versions or server changes.

Separate native curl 8.7.1 checks passed through temporary foreground listeners using `--connect-to` and `--cacert`: Chrome strict HTTP/2, Firefox compatible HTTP/2, and Firefox compatible HTTP/1.1. The direct/proxied curl HTTP/2 hash remained `64a832f547be33249bf4d33e8a46c5dc`. These were curl connections, not Chrome browser tests.

## Arch Linux follow-up

On 2026-09-13, native checks on Arch Linux amd64 established:

- Automatic DNS discovery succeeds using kernel interface enumeration and resolved's `GetLink` method. The previous `ListLinks` call was not part of the resolve1 API. The discovered LAN resolver successfully resolved `tls.peet.ws`, and `doctor --domain tls.peet.ws` completed a verified upstream TLS handshake with HTTP/2.
- `ca trust-status` reports the exact installed CA as trusted in Arch's system bundle. An OpenSSL connection to the foreground proxy verified both the certificate chain and the `tls.peet.ws` hostname.
- Chromium 153's user NSS database needed a separate import of that same CA with website trust. Its fingerprint and trust flags were verified, and the user confirmed browser success after restarting Chromium.
- The user confirmed Codex connections to `chatgpt.com` worked after selecting compatible ALPN. The failing connections offered no ALPN while strict mode's upstream selected `h2`. This motivates making compatible mode the generated-config default; it is not an assertion that every client has the same transport or fingerprint.

On this Arch host, the full race-detector suite, the full suite with `CGO_ENABLED=0`, cgo-free `go vet`, and workflow `actionlint` checks passed. All four release archives built successfully; checksums, executable permissions, Go license inclusion and `CGO_ENABLED=0` build metadata were checked. Both Linux executables have no ELF interpreter or dynamic-library dependencies.

The GitHub workflow builds four archives with `CGO_ENABLED=0` and includes checksums. Its hosted execution still needs the commit to be pushed; local packaging checks do not establish a successful GitHub run.

## Explicit remaining validation

| Spec criteria | Status / remaining evidence |
| --- | --- |
| AC-01 | Four target builds/packages; native runtime checked on macOS arm64 and Arch Linux amd64. |
| AC-02, AC-05, AC-13 | Core evidence obtained as above. |
| AC-03, AC-10 | TLS trust/relay and hosts fixture tests pass separately; initial macOS checks did not apply system hosts redirection; the subsequent Arch foreground trial used user-applied hosts routing. |
| AC-04, AC-06, AC-09 | Core failure, protocol and DNS tests exist; exhaustive malformed traffic, ALPS-enabled origin fixtures and long-lived adverse-network testing remain. |
| AC-07, AC-08 | Native macOS auto DNS and deterministic routing/refresh tests pass; native Arch resolved discovery now passes; other Linux/direct-file scenarios and real Wi-Fi/VPN transitions remain. |
| AC-11 | Installer/lifecycle implementation and definition tests provided. Actual install, upgrade/rollback, crash restart, uninstall and reboot not executed on either OS. |
| AC-12 | Chrome with QUIC enabled, fallback latency and LAN client routing remain untested. No firewall or browser-setting changes were made. |
| AC-14 | Bounded concurrency/transfer/cleanup tests pass. Dedicated daemon RSS/CPU/throughput measurements and a prolonged soak test remain; no production capacity claim is made. |
| AC-15 | Trust lifecycle fixture tests pass; native macOS read-only trust inspection exercised. Arch installed-CA status and served-certificate verification passed after user-run system installation. Chromium NSS import was verified and the user confirmed success after restart. Native removal/recovery and other Linux distributions remain untested. |

## Known behavior and recovery

- In explicit `strict` mode, `chrome-133` keeps its wire profile, including ALPS. The default `compatible` mode adjusts ALPN and dependent ALPS to the client offer. If an origin returns nonempty application settings that cannot cross the downstream TLS boundary, the connection fails with `unsupported_alps`. Select `firefox-120`; do not disable upstream verification. This endpoint did not trigger that limitation.
- Real ECH, pinning, mTLS, IPv6, existing browser sessions and alternate-host routing are outside the supported interception path. QUIC fallback is expected client behavior, not something this daemon forces or has browser-verified.
- Discovery reads endpoint/routing configuration, not the OS's encrypted DNS or DNSSEC validation service. Mandatory discovered DNS-over-TLS is rejected; there is no DNSSEC validator in this release.
- The installer is deliberately conservative about root ownership and boot-stable paths. Backups preserve executable/definition files, but native failure/rollback combinations still require disposable-machine validation. Do not treat a successful dry run as deployment certification.
- The nonpersistent `test` command cleans its generated CA and listener on normal/error/signal exit. Only uncatchable termination can bypass cleanup. The earlier workspace-local test setups are under ignored `.local/`; their CAs were never added to a trust store. The manually started foreground daemons were stopped.

Before promoting a release, run the pending native service and browser tests on disposable macOS and systemd Linux machines, record OS/browser versions and reboot evidence, and update this report. Service/reboot, controlled QUIC and LAN tests were not performed on the user's working machine.

Trust management was added after the initial fingerprint tests. It is separate from `utlsproxy test`: the temporary fingerprint command deliberately does not verify an installed daemon's hosts routing or global CA trust. Use `ca trust-status` for system-store inspection and a browser/curl request through the configured daemon for end-to-end deployment validation. The trust test suite never modifies the development machine's actual trust settings.
