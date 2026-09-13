# utlsproxy delivery summary

Status: development implementation delivered (`0.1.0-dev`); native deployment/browser validation pending

Date: 2026-09-13

Detailed requirements: [Project specification](SPEC.md)

## Deliverables

| Deliverable | Contents |
| --- | --- |
| Go project | Module `github.com/unixapple/utlsproxy`, BSD 3-Clause license, pinned dependencies, source, meaningful automated tests, and build instructions. |
| One executable | `utlsproxy` contains the daemon, CLI, CA generator, hosts manager, and native service installer. No separate control daemon or web UI. |
| Platform artifacts | macOS/Linux builds for `arm64` and `amd64`, cgo-free archive packages and SHA-256 checksums, uploaded by GitHub Actions on each push. |
| Configuration | Versioned JSON, a starter-config command, loopback/LAN examples, automatic/manual DNS examples, and validation. |
| Native services | macOS LaunchDaemon and Linux systemd integration, installed by the CLI. Boot startup, process restart, lifecycle commands, and uninstall. |
| CA trust | Explicit trust/status/untrust commands for macOS and Debian/Ubuntu/Fedora/RHEL/Arch-family Linux, with exact ownership receipts and manual fallback. |
| Documentation | Quickstart, explicit/manual CA trust guidance, command reference, recovery instructions, supported profile matrix, and platform/browser validation results. |

The executable is called `utlsproxy`; the Go module uses the repository path `github.com/unixapple/utlsproxy`. The workspace directory does not need to be renamed.

## Execution model

`utlsproxy serve` is a foreground process. For persistent deployment, `sudo utlsproxy install-service` installs a stable executable and native service definition, enables startup at boot, and starts the service. launchd/systemd owns the process lifecycle; the application does not background itself. Version 1 normally runs as root.

The daemon accepts IPv4 TCP TLS, reads configured SNI, resolves the real upstream through direct IPv4 DNS queries, performs verified upstream TLS with uTLS, and copies application bytes. HTTP/1.1 and HTTP/2 are supported where protocol negotiation is compatible. It does not parse HTTP.

QUIC remains enabled in the browser. The daemon leaves UDP unbound and relies on normal browser TCP fallback; fresh-connection tests must verify that behavior. IPv6 is outside version 1. Full compatibility details are defined in [the operating model](SPEC.md#3-operating-model).

## Main command shapes

```text
utlsproxy config init [--output PATH]
utlsproxy config validate [--config PATH]
utlsproxy config show --effective [--config PATH] [--json]

utlsproxy ca init [--dir PATH] [--name "utlsproxy Local CA"]
utlsproxy ca inspect [--cert PATH] [--json]
utlsproxy ca trust [--config PATH] [--cert PATH] [--dry-run] [--json]
utlsproxy ca trust-status [--config PATH] [--cert PATH] [--json]
utlsproxy ca untrust [--config PATH] [--cert PATH] [--dry-run] [--json]

utlsproxy profiles list [--json]
utlsproxy profiles show NAME [--json]

utlsproxy serve [--config PATH]
               [--listen IPv4:PORT]
               [--profile NAME]
               [--alpn-mode strict|compatible]
               [--dns auto|IPv4:PORT,...]

utlsproxy status [--json]
utlsproxy connections [--json]
utlsproxy reload
utlsproxy doctor [--domain NAME] [--json]
utlsproxy test [--profile NAME] [--dns auto|IPv4:PORT,...] [--json]

utlsproxy hosts status [--json]
utlsproxy hosts apply [--address IPv4] [--dry-run]
utlsproxy hosts remove [--dry-run]

utlsproxy install-service [--config PATH] [--dry-run]
utlsproxy service start|stop|restart|status
utlsproxy uninstall-service [--remove-hosts|--keep-hosts] [--dry-run]

utlsproxy version [--json]
```

The commands above are implemented. `config init --local --output PATH` also creates a rootless port-8443 configuration. `test` creates and cleans a temporary CA, config and listener, compares direct/proxied fingerprints at tls.peet.ws, and changes no hosts/trust/service settings. See [README.md](README.md) for runnable commands and [SPEC.md section 7](SPEC.md#7-cli-contract) for the full contract.

## Decisions included in version 1

- CA generation writes a public `ca.crt` and a protected private `ca.key`, refuses overwrite, and prints identifying information. The user explicitly invokes `ca trust` on each client or imports manually. CA generation, daemon/service lifecycle and the temporary test do not change system trust. `ca untrust` removes only exact receipt-owned installations.
- DNS defaults to `auto`: discover the daemon machine's current usable IPv4 DNS servers from macOS resolver configuration or Linux resolver configuration, then query them directly. Refresh discovery as the network changes. An opaque local DNS stub requires explicit manual configuration if its real upstream cannot be discovered. No hidden public-DNS fallback.
- Named, versioned profiles are selected through CLI or JSON. The default is `chrome-133`; `firefox-120` is also implemented and publicly tested. Chrome origins returning nonempty ALPS settings are explicitly rejected; use Firefox for those origins. Arbitrary custom ClientHello JSON is deferred.
- ALPN defaults to `compatible`, which adapts advertised protocols for HTTP/1.1, HTTP/2 and no-ALPN clients and reports fingerprint-relevant changes. Explicit `strict` mode preserves the profile offer and rejects incompatible clients.
- Hosts management is optional and explicit. Only an application-owned block is edited. Service installation does not change hosts entries.
- A local Unix socket exposes status, active connections, and reload. Inspectable data is connection metadata, counters, DNS selection, and errors; no HTTP content or request logs.
- macOS service installation uses `local.utlsproxy`; Linux uses `utlsproxy.service`. Services start without user login and restart on failure.
- A stopped/crashed daemon leaves persistent hosts overrides in place. Service restart restores service; `hosts remove` is the recovery path for restoring ordinary resolution. Uninstall preserves CA, config, state, and logs.

## Delivery sequence

| Stage | Result |
| --- | --- |
| 1. Prove the connection path | CA generation, direct IPv4 DNS, SNI routing, verified uTLS handshake, stream relay, and early ALPN/ALPS checks against local fixtures and a fingerprint endpoint. |
| 2. Complete daemon and CLI | Configuration, certified profile registry, automatic DNS discovery/refresh, access limits, local status/control, reload, and diagnostic commands. |
| 3. Complete deployment | Managed hosts commands, platform paths/permissions, launchd/systemd installer, boot/restart/stop/uninstall, and recovery behavior. |
| 4. Validate and package | Native platform tests, Chrome QUIC-fallback checks on loopback/LAN, resource measurements, release artifacts, and operating documentation. |

Completion is judged against [the acceptance criteria](SPEC.md#12-validation-and-acceptance-criteria), including actual upstream fingerprint evidence and native service lifecycle tests. Cross-compiled binaries alone do not establish runtime support, and public-site checks are kept separate from deterministic automated tests.

The implementation, automated tests, local binaries, four-platform release packaging and a repeatable nonpersistent public fingerprint test are provided. The initial macOS tests used temporary/local CAs without system changes. Subsequent Arch Linux checks exercised installed CA trust and a user-operated foreground daemon; Chromium trust required a separate NSS import and restart. See [the validation record](docs/VALIDATION.md) for passed checks and the remaining Linux distribution coverage, LAN/QUIC, reboot/service and soak-test work. This is not yet a production-certified version 1 release.
