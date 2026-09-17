# utlsproxy

A Go daemon and CLI for replacing the upstream TLS ClientHello of selected IPv4 HTTPS connections, using [uTLS](https://github.com/refraction-networking/utls). It terminates client TLS using your local CA, opens verified upstream TLS using a versioned profile, and relays the application byte stream without parsing HTTP.

Development release: `0.1.0-dev`. Native macOS testing and public fingerprint checks are recorded in [docs/VALIDATION.md](docs/VALIDATION.md). Native Arch Linux DNS, CA trust and client checks are also recorded there; installed-service/reboot validation remains pending.

## Quickstart

### 1. Build and try a temporary proxy

Download the archive for your machine from [GitHub Releases](https://github.com/unixapple/utlsproxy/releases). Public release downloads do not require GitHub sign-in.

| Platform | CPU | Archive suffix |
| --- | --- | --- |
| macOS | Apple Silicon | `darwin-arm64.tar.gz` |
| macOS | Intel | `darwin-amd64.tar.gz` |
| Linux | ARM64 | `linux-arm64.tar.gz` |
| Linux | Intel/AMD 64-bit | `linux-amd64.tar.gz` |

Download `SHA256SUMS` alongside your archive. On Linux, verify the downloaded archive with `sha256sum --check --ignore-missing SHA256SUMS`. On macOS, run `shasum -a 256 utlsproxy-<version>-darwin-<arch>.tar.gz` and compare it with the matching line in `SHA256SUMS`. Extract with `tar -xzf utlsproxy-<version>-<os>-<arch>.tar.gz` in an empty directory. Each archive includes the executable, documentation and examples. No Go installation or C runtime installation is needed for Linux binaries; macOS binaries use the OS's system libraries.

Run `./utlsproxy test` from the extracted directory. In the commands below, replace `./bin/utlsproxy` with `./utlsproxy` when using an archive.

To build from source, install Go 1.26 or later, Git and make, then:

```sh
git clone https://github.com/unixapple/utlsproxy.git
cd utlsproxy
make build
./bin/utlsproxy test
```

This needs no sudo or installed CA. It creates a temporary proxy and CA, compares direct/proxied results at tls.peet.ws, and cleans up. Expect `TLS fingerprint changed: true` and `HTTP/2 fingerprint preserved: true`. On Linux, install your distribution's `ca-certificates` package for upstream HTTPS verification. If automatic DNS discovery is unavailable, use `./bin/utlsproxy test --dns YOUR_DNS_IPV4:53`.

### 2. Use it with your browser

These steps intentionally create persistent configuration and system CA trust. Skip `init` commands if you already created the configuration and CA; they refuse overwrite.

```sh
sudo ./bin/utlsproxy config init
sudo ./bin/utlsproxy ca init
```

Edit the generated configuration if needed. Defaults are `127.0.0.1:443`, the exact domain `tls.peet.ws`, profile `chrome-133`, compatible ALPN, and automatic DNS. Config path: `/etc/utlsproxy/config.json` on Linux, `/Library/Application Support/utlsproxy/config.json` on macOS. Add every exact hostname you want to proxy to `domains`; `google.com` and `www.google.com` are separate entries.

```sh
sudo ./bin/utlsproxy config validate
sudo ./bin/utlsproxy ca trust --dry-run
sudo ./bin/utlsproxy ca trust
sudo ./bin/utlsproxy ca trust-status
sudo ./bin/utlsproxy serve
```

Keep this foreground process running. In another terminal, in the same project directory:

```sh
sudo ./bin/utlsproxy status
sudo ./bin/utlsproxy hosts apply --dry-run
sudo ./bin/utlsproxy hosts apply
```

Fully quit and reopen your browser, then visit **https://tls.peet.ws/api/all**. Check `tls.ja4`; with `chrome-133`, strict ALPN and HTTP/2, the measured value is `t13d1516h2_8daaf6152771_d8a2da3f94cd`. JA3 can vary because Chrome shuffles extensions. The page's certificate should be issued by your `utlsproxy Local CA`. User-Agent and HTTP/2 behavior remain your browser's, not those of the selected TLS profile. See [recorded measurements and limitations](docs/VALIDATION.md).

Importing system trust does not guarantee that every application uses it: some browsers, Java applications and containers maintain separate stores. See [CA trust management](#ca-trust-management). If you already imported this CA manually, utlsproxy will preserve that installation rather than take ownership of it.

### 3. Start automatically after reboot, or clean up

For persistence, stop the foreground daemon with Ctrl-C, then:

```sh
sudo ./bin/utlsproxy install-service --dry-run
sudo ./bin/utlsproxy install-service
sudo /usr/local/bin/utlsproxy status
```

This installs a macOS LaunchDaemon or Linux systemd service. To undo a foreground trial, remove hosts redirection first, remove CLI-managed CA trust if no longer needed, then stop the foreground daemon:

```sh
sudo ./bin/utlsproxy hosts remove
sudo ./bin/utlsproxy ca untrust --dry-run
sudo ./bin/utlsproxy ca untrust
# Ctrl-C in the terminal running serve.
```

For an installed service, run `sudo /usr/local/bin/utlsproxy ca untrust` before `sudo /usr/local/bin/utlsproxy uninstall-service --remove-hosts`. Uninstall preserves original CA/config files and does not remove trust automatically. A manually imported CA must be removed through the same manual trust-store procedure.

## Nonpersistent fingerprint test details

To compare both supported profiles:

```sh
make build
./bin/utlsproxy test
./bin/utlsproxy test --profile firefox-120
```

The test contacts [tls.peet.ws](https://tls.peet.ws/api/all) twice: once directly using Go TLS, then through a temporary proxy using the selected uTLS profile. It compares the returned JA3/JA4 and HTTP/2 fingerprints. A passing run reports `TLS fingerprint changed: true` and `HTTP/2 fingerprint preserved: true`.

No sudo, hosts edits, trust-store installation, firewall changes, or service installation. An ephemeral loopback TCP port and a CA trusted only by the test's client are used. The listener stops and its temporary configuration, CA and socket are removed on normal exit, error, SIGINT or SIGTERM. As with any process, SIGKILL or power loss can leave its private `/tmp/utlsproxy-test-*` directory behind.

```sh
./bin/utlsproxy test --json
# If auto discovery is unavailable, supply YOUR real IPv4 DNS server:
./bin/utlsproxy test --dns 192.168.1.1:53
```

This is an explicit external network test, not part of the automated test suite. The public site receives ordinary connection metadata (including your public IP); the CLI prints only selected fingerprint fields. Changes or outages at the site can make the test fail. This does not test Chrome itself, hosts routing, or QUIC fallback.

## Build and verify

```sh
make build                 # bin/utlsproxy for this machine
make test                  # deterministic local tests, with race detector
make check                 # go vet
make release               # four platform archives plus dist/SHA256SUMS
```

The module pins its dependencies and suggests Go `1.27.1` through `go.mod`; source requires Go 1.26 or later. Make and the release script respect your Go toolchain configuration. With `GOTOOLCHAIN=auto`, Go can download the suggested toolchain if your installed version is older. To use only your installed compiler, run `make GOTOOLCHAIN=local build` (or `make GOTOOLCHAIN=local release`). To explicitly select the standard toolchain, use `make GOTOOLCHAIN=go1.27.1 build`.

Both `make build` and release packaging use `CGO_ENABLED=0`; shipped binaries require no C compiler, and Linux binaries have no dynamic libc dependency. Race-detector tests need cgo and a C compiler on the development/CI host.

The [build workflow](.github/workflows/build.yml) tests the code and builds four macOS/Linux `arm64` and `amd64` archives plus SHA-256 checksums. Branch pushes and manual branch runs upload development artifacts (retained for 30 days) under [Actions → Build binaries](https://github.com/unixapple/utlsproxy/actions/workflows/build.yml). CI installs the suggested Go version with `setup-go` and uses `GOTOOLCHAIN=local` for subsequent commands.

To publish a release, commit and push the changes, then push a version tag pointing to that commit:

```sh
git tag v0.1.0
git push origin v0.1.0
```

After tests and packaging pass, the workflow creates a GitHub Release with all four archives and `SHA256SUMS` as individual downloadable assets. Archive names and the embedded binary version use the tag without `v`, for example `utlsproxy-0.1.0-linux-amd64.tar.gz`. Tags such as `v0.1.0-rc.1` create prereleases. A release stays in draft until its assets have uploaded; rerunning the workflow retries asset uploads. Only the release job receives repository write permission, using GitHub's built-in token; no additional secret is needed.

Release archives include documentation, configuration examples and dependency license notices; they do not contain private keys. Arch's packaged Go license is detected automatically; for other custom toolchain layouts, set `GO_LICENSE=/path/to/LICENSE` when packaging. No code signing, notarization, package-manager integration, or automatic updates are provided.

## Foreground daemon and inspection

For a reusable local setup (files persist, but no system settings change):

```sh
./bin/utlsproxy config init --local --output .local/config.json
./bin/utlsproxy ca init --config .local/config.json
./bin/utlsproxy config validate --config .local/config.json
./bin/utlsproxy serve --config .local/config.json
```

Creation refuses existing files. If `.local` already contains a setup, reuse it or choose another directory. The default local listener is `127.0.0.1:8443`, the allowed domain is `tls.peet.ws`, and DNS mode is `auto`. `serve` remains in the foreground; Ctrl-C drains connections and stops it.

In another terminal:

```sh
./bin/utlsproxy status --config .local/config.json
./bin/utlsproxy connections --config .local/config.json --json
./bin/utlsproxy doctor --config .local/config.json --domain tls.peet.ws
curl -4 --noproxy '*' --http2 --cacert .local/ca/ca.crt \
  --connect-to tls.peet.ws:443:127.0.0.1:8443 https://tls.peet.ws/api/all
```

`--connect-to` changes only curl's TCP destination; SNI and the URL stay `tls.peet.ws`. There is no hosts override or global CA trust involved. curl needs HTTP/2 support for this example. For an HTTP/1-only client, omit `--http2`; the default compatible mode handles its protocol offer.

Edit the JSON, then use `reload --config .local/config.json`. Domains, profile, ALPN policy, DNS, access rules, limits and log level reload for new connections. Listener, upstream port, CA/runtime paths and log format require restart. Explicit `serve` flags remain in effect across reloads. Existing streams retain their original configuration.

## Configuration and TLS profiles

`config init` without `--local` emits the platform's service paths and a port-443 listener. JSON is strict: unknown/duplicate fields and invalid values are rejected. New configurations and omitted `upstream.alpn_mode` use `compatible`; existing explicit `strict` settings remain strict. Defaults fill omitted fields; relative JSON paths resolve against the config file. See [the full configuration contract](SPEC.md#6-configuration-contract).

| Example | Purpose |
| --- | --- |
| [examples/local.json](examples/local.json) | Loopback port 8443, automatic DNS, workspace-relative CA/state. |
| [examples/lan.json](examples/lan.json) | Explicit LAN listener and client subnet; replace example addresses. Uses platform CA/state defaults. |
| [examples/custom-loopback.json](examples/custom-loopback.json) | Linux custom address on `lo` for clients that reject `127.0.0.1`; includes the required source-IP allowlist. Uses platform CA/state defaults. |
| [examples/manual-dns.json](examples/manual-dns.json) | Explicit DNS; replace `192.0.2.53` (documentation-only, not a working resolver). |

```sh
./bin/utlsproxy profiles list
./bin/utlsproxy profiles show chrome-133
./bin/utlsproxy config show --effective --config .local/config.json
```

| Profile | uTLS mapping | Limitations |
| --- | --- | --- |
| `chrome-133` (default) | `HelloChrome_133` | Shuffled extensions/GREASE mean JA3 can vary. Nonempty upstream ALPS settings are rejected as `unsupported_alps`; use Firefox for such origins. |
| `firefox-120` | `HelloFirefox_120` | No Chrome ALPS requirement; this is a TLS profile, not a complete Firefox implementation. |

`compatible` (default) restricts ALPN to the client's protocols and adjusts dependent ALPS extensions, reporting changes in connection metadata. For clients that send no ALPN, including some HTTP/1.1 WebSocket transports, it omits upstream ALPN too. This can change the TLS fingerprint. Choose `strict` explicitly to preserve the profile's advertised ALPN; it rejects a selection the client cannot use, such as upstream `h2` when the client offered no ALPN. Both TLS legs must agree on the application protocol. No HTTP/1-to-HTTP/2 translation is performed. Upstream certificate and hostname verification cannot be disabled.

DNS `auto` reads macOS resolver groups via `scutil --dns`, or Linux systemd-resolved global/per-link configuration via D-Bus. Ordinary direct `/etc/resolv.conf` is supported on Linux as default-only DNS. Actual lookups use direct A queries, not the system hostname resolver or hosts file. Domain routing and interface scope are retained; auto mode rejects opaque local DNS stubs and unsupported mandatory DNS-over-TLS. Supply explicit servers if discovery cannot expose a usable IPv4 upstream. Discovery refreshes as network configuration changes, with no hidden public-DNS fallback. On Linux, interface-bound DNS can require root/capabilities even with a high TCP port.

### Custom loopback address for clients such as OpenClaw

If a client rejects an endpoint because its hostname resolves to `127.0.0.1`, Linux can host utlsproxy on another IPv4 address assigned to `lo`. This example documents the setup used when troubleshooting an OpenClaw endpoint rejection; client address restrictions may vary, so it does not guarantee acceptance by every client.

First assign the address before starting the daemon:

```sh
sudo ip address add 19.19.19.19/32 dev lo
```

Use [examples/custom-loopback.json](examples/custom-loopback.json) as a configuration template. For an existing installation, merge its `listen`, `hosts.address`, and `access.client_cidrs` fields into `/etc/utlsproxy/config.json`, keeping your existing CA, runtime paths and working DNS settings. Adjust `domains` to the exact endpoint hostnames you use. The example uses automatic DNS; retain manual DNS if your installation needs it.

The `/32` entry in `access.client_cidrs` is essential: local connections to `19.19.19.19` can also use `19.19.19.19` as their source address. Allowing only `127.0.0.0/8` causes the proxy to reject them with `client_denied`, even though the address is on `lo`.

For an existing systemd installation, validate the configuration, restart to change the listener, and update hosts redirection:

```sh
sudo utlsproxy config validate
sudo systemctl restart utlsproxy
sudo utlsproxy hosts apply --dry-run
sudo utlsproxy hosts apply
```

Keep the application's endpoint URL as its original HTTPS hostname (for example, `https://api.openai.com/v1`); hosts redirection sends it to the local proxy while preserving TLS SNI. The client still needs to trust your utlsproxy CA. For a fresh installation, follow the quickstart CA and service setup with this configuration.

If OpenClaw reports `UNABLE_TO_VERIFY_LEAF_SIGNATURE` even after system CA trust is installed, enable Node.js's system CA store. On the tested Debian installation with Node.js 24.15.0, default Node TLS verification failed while `--use-system-ca` successfully verified the proxied `auth.openai.com` certificate:

```sh
NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--use-system-ca" openclaw models auth login --provider openai
```

This setting applies to that command and its children. For subsequent OpenClaw commands in the same shell, use `export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--use-system-ca"`; a separately launched service needs the option in its own environment. See [Node.js system CA support](https://nodejs.org/api/cli.html#--use-system-ca). Certificate verification remains enabled.

`19.19.19.19` is the address used in the tested setup, not a reserved example address; assigning it locally shadows access to that actual IP. Choose an address appropriate for your network and client policy, and change all three config fields together. The `ip address add` command lasts only until reboot: configure the address in your network manager before relying on automatic service startup. To undo the setup, remove hosts redirection and stop or reconfigure the proxy before running `sudo ip address del 19.19.19.19/32 dev lo`.

## Persistent deployment — optional

These commands are provided for later use; the temporary test does not run them.

```sh
# Complete the quickstart configuration/CA steps and stop foreground serve first.
sudo ./bin/utlsproxy config validate
sudo ./bin/utlsproxy install-service --dry-run
sudo ./bin/utlsproxy install-service
sudo /usr/local/bin/utlsproxy status
```

The installer copies the executable to `/usr/local/bin/utlsproxy`, references the existing absolute config path, installs a macOS LaunchDaemon (`local.utlsproxy`) or Linux systemd unit (`utlsproxy.service`), enables boot startup and starts it. Configuration and CA must be root-owned, protected and available at boot. Unsafe ancestors (including user-owned `/usr/local/bin`) and unrelated installation files are refused, not taken over. A dry run renders the plan but is not proof that installation will succeed. The installer keeps ownership hashes, preserves replaced files for recovery, and attempts rollback if activation fails.

Default config: macOS `/Library/Application Support/utlsproxy/config.json`; Linux `/etc/utlsproxy/config.json`. Default CA: macOS `/Library/Application Support/utlsproxy/ca`; Linux `/var/lib/utlsproxy/ca`. The default control socket is `/var/run/utlsproxy/control.sock`, owned by the daemon user and mode `0600`. Only local socket inspection is supported.

Install **only `ca.crt`**, never `ca.key`, into each client's trust store using the explicit CA trust commands below or a manual import. Check the certificate's SHA-256 with `ca inspect` first. The daemon never installs trust automatically. Anyone obtaining this private CA key can impersonate sites to clients trusting it: keep it private and remove trust when the CA is no longer needed.

Once the daemon and client trust are ready, hosts changes are a separate explicit action:

```sh
sudo /usr/local/bin/utlsproxy hosts apply --dry-run
sudo /usr/local/bin/utlsproxy hosts apply
sudo /usr/local/bin/utlsproxy hosts status
```

Local apply checks daemon readiness, domain coverage, port 443 and upstream TLS. LAN apply can only check TCP reachability; verify remote configuration and client trust yourself. The manager preserves unrelated hosts entries, refuses conflicts, writes only its marked block and makes backups. Restart client connections after changes; no global DNS-cache flush is performed automatically.

```sh
sudo /usr/local/bin/utlsproxy service status
sudo /usr/local/bin/utlsproxy service restart
sudo /usr/local/bin/utlsproxy hosts remove   # restore ordinary resolution first
sudo /usr/local/bin/utlsproxy service stop
sudo /usr/local/bin/utlsproxy uninstall-service --remove-hosts
```

Stopping a daemon leaves hosts redirection in place unless explicitly removed. `hosts remove` works without a live daemon or valid config and edits the current file, rather than restoring an old backup over later user changes. Uninstall preserves CA, config, state and logs; remove client trust separately. On Linux logs go to the journal; macOS service logs rotate at 10 MiB with three backups.

## CA trust management

```sh
sudo ./bin/utlsproxy ca trust [--config PATH] [--dry-run] [--json]
sudo ./bin/utlsproxy ca trust-status [--config PATH] [--json]
sudo ./bin/utlsproxy ca untrust [--config PATH] [--dry-run] [--json]
```

The brackets above denote optional arguments. Trust management reads only the public certificate, never the private key. To trust a remote LAN daemon from a client machine, copy only its `ca.crt` to the client, then use `sudo utlsproxy ca trust --cert /path/to/ca.crt`. No daemon configuration or private key is required on that client. `--cert` also works with `trust-status` and `untrust`.

| Platform | What `ca trust` changes |
| --- | --- |
| macOS | Imports the exact CA into `/Library/Keychains/System.keychain` and adds **SSL-only** trust in the admin domain using `/usr/bin/security`. |
| Debian/Ubuntu family | Adds a fingerprint-named `.crt` under `/usr/local/share/ca-certificates`, then runs `/usr/sbin/update-ca-certificates`. This grants system CA trust, **not SSL-only trust**. |
| Fedora/RHEL family | Adds a fingerprint-named `.crt` under `/etc/pki/ca-trust/source/anchors`, then runs `/usr/bin/update-ca-trust extract`. This grants system CA trust, **not SSL-only trust**. |
| Arch Linux family | Adds a fingerprint-named `.crt` under `/etc/ca-certificates/trust-source/anchors`, then runs `/usr/bin/update-ca-trust extract`. Checks trust in `/etc/ca-certificates/extracted/tls-ca-bundle.pem`. This grants system CA trust, **not SSL-only trust**. |
| Other Linux distributions | Refuses automatic changes and requests manual import. |

Install the distribution's `ca-certificates` package first. Platform integration follows the [Debian update-ca-certificates contract](https://manpages.debian.org/bookworm/ca-certificates/update-ca-certificates.8.en.html), [RHEL shared trust-store guidance](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/securing_networks/using-shared-system-certificates_securing-networks), and [Arch update-ca-trust contract](https://man.archlinux.org/man/update-ca-trust.8).

`trust-status` checks the exact fingerprint: macOS uses local native SSL certificate evaluation; Linux checks the generated system TLS CA bundle. It returns exit code 5 when not trusted. A readable public certificate permits unprivileged status checks; receipt ownership may be reported unknown unless run with sudo. On macOS, user-specific trust overrides can make evaluation differ between users. This is a system-store check, not proof of trust in every application.

On Linux, Chrome/Chromium may still report `NET::ERR_CERT_AUTHORITY_INVALID` after system trust succeeds. Import the same public CA through `chrome://settings/certificates` and enable trust for identifying websites, then fully quit and reopen the browser. The installed certificate path is shown by `ca trust-status --json` under `store.target`. Chromium also supports importing through `certutil` into your user's NSS database with trust flags `C,,` (SSL server CA trust). Chromium 146 and later default to `~/.local/share/pki/nssdb`, but continue using `~/.pki/nssdb` if it already exists; run browser imports as your normal user. See [Chromium's Linux certificate management documentation](https://chromium.googlesource.com/chromium/src/+/master/docs/linux/cert_management.md). Browser imports are separate from CLI-managed system trust; remove them separately in the browser when removing this CA.

Trust commands are explicit opt-in administrative actions. `ca init`, `serve`, `test`, `install-service` and `uninstall-service` never automatically install or remove system trust. `--dry-run` performs inspection only. Repeating a successful installation does not rewrite trust. A certificate already installed manually is **not adopted**: if already trusted, installation is a no-op; if installed but untrusted, the command requests manual correction. `ca untrust` refuses to remove unmanaged certificates, even if their display name matches.

Ownership receipts and public recovery snapshots are stored by SHA-256 in `/etc/utlsproxy/trust` on Linux or `/Library/Application Support/utlsproxy/trust` on macOS. Removal validates the receipt and exact fingerprint; modified anchors or snapshots cause an error. Failed installation attempts rollback. A failed rollback/removal retains recovery information for a retry. If the original certificate/configuration was lost or rotated, use the printed recovery certificate path with `ca untrust --cert PATH`. Do not delete receipts before removing their managed trust. Original CA/key/config files are preserved.

For manual macOS import, open Keychain Access, select **System**, import `ca.crt`, then find it under **Certificates** and enable SSL trust in its **Trust** settings. [Apple's import instructions](https://support.apple.com/guide/keychain-access/add-certificates-to-a-keychain-kyca2431/mac), [trust settings](https://support.apple.com/en-gb/guide/keychain-access/kyca11871/mac).

Trust lifecycle tests use fake native commands and isolated fixture directories, covering install/repeat/status/remove, partial failure recovery, exact-fingerprint conflicts and private-key independence. Read-only native macOS inspection and native Arch Linux installed-CA checks have been exercised. On Arch, the served certificate verified against the system bundle; Chromium required a separate NSS import and restart. See [validation details](docs/VALIDATION.md).

## Scope and limits

- IPv4 TCP only. IPv6, existing browser connections, alternate-service hostnames and DNS behavior that bypasses hosts can escape interception. This daemon does not enforce machine-wide routing.
- UDP/443 is left unbound. QUIC fallback timing is client-dependent and has not been browser-tested in this delivery.
- Requires visible, allowed SNI and an ECDSA-capable TLS 1.2/1.3 client. Real ECH, certificate pinning and forwarding client-certificate authentication are not supported.
- No HTTP parsing/rewriting, HTTP/2 fingerprint spoofing, upstream pooling, session resumption or 0-RTT. Plaintext exists transiently in memory but is not logged.
- Exact domain names only; not an open proxy. LAN exposure requires an explicit client CIDR allowlist. One upstream is selected by the initial SNI; the daemon cannot enforce HTTP Host/:authority inside that stream.
- This is a development build. Native service installation/reboot, broader Linux distribution coverage, LAN browser routing and long-duration resource measurements remain to be validated before unattended production use.

See [SPEC.md](SPEC.md) for the formal requirements, [DELIVERY.md](DELIVERY.md) for command shapes, and [docs/VALIDATION.md](docs/VALIDATION.md) for the actual verification boundary. `COMMAND --help` lists flags; exit codes are 0 success, 1 operation failure, 2 invalid input, 3 unavailable control/service, 4 permission denied, and 5 running but degraded.

## License

[BSD 3-Clause](LICENSE). The Go module path is `github.com/unixapple/utlsproxy`; the executable remains `utlsproxy`. Release archives include the project license and third-party dependency notices.
