package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/unixapple/utlsproxy/internal/ca"
	"github.com/unixapple/utlsproxy/internal/config"
	"github.com/unixapple/utlsproxy/internal/control"
	"github.com/unixapple/utlsproxy/internal/dns"
	"github.com/unixapple/utlsproxy/internal/fsutil"
	"github.com/unixapple/utlsproxy/internal/hosts"
	"github.com/unixapple/utlsproxy/internal/logging"
	"github.com/unixapple/utlsproxy/internal/profiles"
	"github.com/unixapple/utlsproxy/internal/proxy"
	"github.com/unixapple/utlsproxy/internal/service"
	"github.com/unixapple/utlsproxy/internal/trust"
)

type coded struct {
	code int
	err  error
}

func (e coded) Error() string { return e.err.Error() }
func (e coded) Unwrap() error { return e.err }
func invalid(e error) error {
	if e == nil {
		return nil
	}
	return coded{2, e}
}
func Execute(args []string, out, errOut io.Writer, version string) int {
	err := run(args, out, errOut, version)
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	fmt.Fprintln(errOut, "error:", err)
	var c coded
	if errors.As(err, &c) {
		return c.code
	}
	if errors.Is(err, os.ErrPermission) {
		return 4
	}
	if errors.Is(err, service.ErrDegraded) {
		return 5
	}
	return 1
}

const help = `utlsproxy — IPv4 TLS fingerprint proxy

Usage: utlsproxy COMMAND [options]

  config init|validate|show     Create and inspect JSON configuration
  ca init|inspect               Generate or inspect a local CA
  ca trust|trust-status|untrust  Explicit system CA trust and owned removal
  profiles list|show NAME       Inspect versioned uTLS profiles
  serve                        Run the daemon in the foreground
  status                       Inspect daemon health and DNS selection
  connections                  Inspect active TLS connections
  reload                       Reload the daemon's existing configuration
  doctor [--domain NAME]        Local checks; explicit domain adds upstream probe
  test [--profile NAME]         Temporary direct/proxied fingerprint comparison
  hosts status|apply|remove     Manage a dedicated local hosts-file block
  install-service              Install, enable at boot, and start native service
  uninstall-service            Remove owned service files; preserve CA/config
  service start|stop|restart|status
  version

Use COMMAND --help for options. A quick temporary setup is:
  utlsproxy config init --local --output .local/config.json
  utlsproxy ca init --config .local/config.json
  utlsproxy serve --config .local/config.json
`

func emit(out io.Writer, v any) error {
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
func run(args []string, out, errOut io.Writer, version string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(out, help)
		return nil
	}
	cmd := args[0]
	rest := args[1:]
	sub := ""
	name := ""
	switch cmd {
	case "config", "ca", "profiles", "hosts", "service":
		if len(rest) == 0 {
			return invalid(fmt.Errorf("%s requires a subcommand", cmd))
		}
		if rest[0] == "--help" || rest[0] == "-h" {
			fmt.Fprint(out, help)
			return nil
		}
		sub = rest[0]
		rest = rest[1:]
		if cmd == "profiles" && sub == "show" {
			if len(rest) == 0 {
				return invalid(errors.New("profiles show requires NAME"))
			}
			name = rest[0]
			rest = rest[1:]
		}
	}
	f := flag.NewFlagSet(strings.TrimSpace(cmd+" "+sub), flag.ContinueOnError)
	f.SetOutput(errOut)
	path := f.String("config", config.PlatformPaths().Config, "JSON configuration path")
	asJSON := f.Bool("json", false, "machine-readable JSON output")
	socket := ""
	output := ""
	dir := ""
	cert := ""
	caName := "utlsproxy Local CA"
	validity := 10 * 365 * 24 * time.Hour
	listen := ""
	profile := ""
	alpn := ""
	dnsFlag := ""
	logFile := ""
	domain := ""
	address := ""
	dry := false
	local := false
	removeHosts := false
	keepHosts := false
	switch cmd {
	case "config":
		f.StringVar(&output, "output", "", "output path for config init")
		f.Bool("effective", false, "show effective configuration")
		f.BoolVar(&local, "local", false, "init with local paths and loopback port 8443")
	case "ca":
		switch sub {
		case "init":
			f.StringVar(&dir, "dir", "", "CA output directory")
			f.StringVar(&caName, "name", caName, "CA common name")
			f.DurationVar(&validity, "validity", validity, "CA validity")
		case "inspect", "trust", "untrust", "trust-status":
			f.StringVar(&cert, "cert", "", "public CA certificate path (no private key required)")
		default:
			return invalid(errors.New("use ca init, inspect, trust, trust-status or untrust"))
		}
		if sub == "trust" || sub == "untrust" {
			f.BoolVar(&dry, "dry-run", false, "inspect and show trust changes without writing")
		}
	case "serve":
		f.StringVar(&listen, "listen", "", "replace listener with IPv4:port")
		f.StringVar(&profile, "profile", "", "versioned TLS profile")
		f.StringVar(&alpn, "alpn-mode", "", "strict or compatible")
		f.StringVar(&dnsFlag, "dns", "", "auto or comma-separated IPv4:port servers")
		f.StringVar(&logFile, "log-file", "", "rotating log file (otherwise stderr)")
	case "status", "connections", "reload":
		f.StringVar(&socket, "socket", "", "control socket path override")
	case "doctor":
		f.StringVar(&domain, "domain", "", "configured domain for an explicit DNS/TLS probe")
	case "test":
		f.StringVar(&profile, "profile", "chrome-133", "versioned TLS profile to test")
		f.StringVar(&dnsFlag, "dns", "auto", "auto or comma-separated IPv4:port servers")
	case "hosts":
		f.StringVar(&address, "address", "", "hosts redirection IPv4 override")
		f.BoolVar(&dry, "dry-run", false, "show changes without writing")
	case "install-service", "uninstall-service":
		f.BoolVar(&dry, "dry-run", false, "show installation changes without writing")
		if cmd == "uninstall-service" {
			f.BoolVar(&removeHosts, "remove-hosts", false, "remove managed hosts entries before stopping")
			f.BoolVar(&keepHosts, "keep-hosts", false, "explicitly retain managed hosts entries")
		}
	case "profiles", "service", "version":
	default:
		return invalid(fmt.Errorf("unknown command %q", cmd))
	}
	if err := f.Parse(rest); err != nil {
		return invalid(err)
	}
	if f.NArg() > 0 {
		return invalid(fmt.Errorf("unexpected arguments: %v", f.Args()))
	}
	set := map[string]bool{}
	f.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	if cmd == "version" {
		deps := map[string]string{}
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, d := range info.Deps {
				if d.Path == "github.com/refraction-networking/utls" {
					deps[d.Path] = d.Version
				}
			}
		}
		if *asJSON {
			return emit(out, map[string]any{"schema_version": 1, "version": version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "dependencies": deps, "configuration_version": 1, "control_api_version": 1})
		}
		fmt.Fprintf(out, "utlsproxy %s (%s %s/%s; uTLS %s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH, deps["github.com/refraction-networking/utls"])
		return nil
	}
	if cmd == "test" {
		return temporaryTest(out, errOut, version, profile, dnsFlag, *asJSON)
	}
	if cmd == "profiles" {
		if sub == "list" {
			return emit(out, map[string]any{"schema_version": 1, "profiles": profiles.List()})
		}
		if sub == "show" {
			p, e := profiles.Get(name)
			if e != nil {
				return invalid(e)
			}
			return emit(out, p)
		}
		return invalid(errors.New("use profiles list or profiles show NAME"))
	}
	if cmd == "service" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		text, e := service.Native(ctx, sub)
		if *asJSON {
			_ = emit(out, map[string]any{"schema_version": 1, "action": sub, "native_status": text, "success": e == nil})
		} else {
			fmt.Fprintln(out, text)
		}
		if e != nil && sub == "status" {
			return coded{3, e}
		}
		return e
	}
	if cmd == "config" && sub == "init" {
		if output == "" {
			output = *path
		}
		abs, e := filepath.Abs(output)
		if e != nil {
			return e
		}
		c := config.Defaults()
		if local {
			base := filepath.Dir(abs)
			c.Listen = []string{"127.0.0.1:8443"}
			c.CA.Cert, c.CA.Key = filepath.Join(base, "ca", "ca.crt"), filepath.Join(base, "ca", "ca.key")
			c.Runtime.StateDir = filepath.Join(base, "state")
			c.Runtime.ControlSocket = filepath.Join(c.Runtime.StateDir, "control.sock")
		}
		if e = c.Validate(); e != nil {
			return invalid(e)
		}
		if e = os.MkdirAll(filepath.Dir(abs), 0700); e != nil {
			return e
		}
		b, e := json.MarshalIndent(c, "", "  ")
		if e != nil {
			return e
		}
		if e = fsutil.Exclusive(abs, append(b, '\n'), 0600); e != nil {
			return e
		}
		fmt.Fprintf(out, "Created %s\nEdit domains and settings before running.\n", abs)
		return nil
	}
	if cmd == "ca" {
		p := config.PlatformPaths()
		defaultCert, defaultKey := filepath.Join(p.CA, "ca.crt"), filepath.Join(p.CA, "ca.key")
		if set["config"] {
			c, e := config.Load(*path)
			if e != nil {
				return invalid(e)
			}
			defaultCert, defaultKey = c.CA.Cert, c.CA.Key
		}
		if sub == "trust" || sub == "untrust" || sub == "trust-status" {
			if cert == "" {
				cert = defaultCert
			}
			manager, e := trust.New()
			if e != nil {
				return e
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			report, e := manager.Execute(ctx, sub, cert, dry)
			if *asJSON {
				_ = emit(out, report)
			} else {
				managed := fmt.Sprint(report.Managed)
				if !report.OwnershipKnown {
					managed = "unknown (run with sudo to inspect receipts)"
				}
				fmt.Fprintf(out, "CA: %s\nCertificate: %s\nSHA-256: %s\nTrust store: %s\nManaged installation scope: %s\nInstalled: %t; trusted: %t; managed: %s\n%s\n", report.Subject, report.Certificate, report.SHA256, report.Store.Target, report.Store.Scope, report.Installed, report.Trusted, managed, report.Message)
				if report.Managed {
					fmt.Fprintf(out, "Receipt: %s\nRecovery certificate: %s\n", report.Receipt, report.RecoveryCertificate)
				}
			}
			if errors.Is(e, trust.ErrNotTrusted) && sub == "trust-status" {
				return coded{5, e}
			}
			return e
		}
		var info ca.Info
		var e error
		if sub == "init" {
			if dir == "" {
				if filepath.Dir(defaultCert) != filepath.Dir(defaultKey) || filepath.Base(defaultCert) != "ca.crt" || filepath.Base(defaultKey) != "ca.key" {
					return invalid(errors.New("ca init needs a directory containing ca.crt and ca.key; specify --dir"))
				}
				dir = filepath.Dir(defaultCert)
			}
			dir, e = filepath.Abs(dir)
			if e != nil {
				return e
			}
			info, e = ca.Init(dir, caName, validity)
		} else if sub == "inspect" {
			if cert == "" {
				cert = defaultCert
			}
			info, e = ca.Inspect(cert)
		} else {
			return invalid(errors.New("use ca init, inspect, trust, trust-status or untrust"))
		}
		if e != nil {
			return e
		}
		if *asJSON {
			return emit(out, info)
		}
		fmt.Fprintf(out, "CA: %s\nCertificate: %s\nSHA-256: %s\nExpires: %s\n", info.Subject, info.Certificate, info.SHA256, info.NotAfter.Format(time.RFC3339))
		if sub == "init" {
			fmt.Fprintln(out, "Use ca trust --cert with this public certificate for explicit system trust, or curl --cacert for a temporary test. Never import ca.key.")
		}
		return nil
	}
	if cmd == "hosts" && sub == "remove" {
		return changeHosts(out, nil, "", true, dry)
	}
	if cmd == "uninstall-service" {
		if removeHosts && keepHosts {
			return invalid(errors.New("choose only one of --remove-hosts and --keep-hosts"))
		}
		p, e := hosts.Prepare("/etc/hosts", nil, "", true)
		if e != nil {
			return e
		}
		if len(p.Managed) > 0 && !removeHosts && !keepHosts {
			return invalid(errors.New("managed hosts entries exist; specify --remove-hosts or --keep-hosts"))
		}
		if removeHosts {
			if e = changeHosts(out, nil, "", true, dry); e != nil {
				return e
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		text, e := service.Uninstall(ctx, dry)
		fmt.Fprintln(out, text)
		return e
	}
	load := func() (config.Config, error) {
		c, e := config.Load(*path)
		if e != nil {
			return c, e
		}
		if set["listen"] {
			c.Listen = []string{listen}
		}
		if set["profile"] {
			c.Upstream.Profile = profile
		}
		if set["alpn-mode"] {
			c.Upstream.ALPNMode = alpn
		}
		if set["dns"] {
			if dnsFlag == "auto" {
				c.DNS.Mode, c.DNS.Servers = "auto", nil
			} else {
				c.DNS.Mode, c.DNS.Servers = "manual", strings.Split(dnsFlag, ",")
			}
		}
		return c, c.Validate()
	}
	if (cmd == "status" || cmd == "connections" || cmd == "reload") && socket != "" {
		return inspect(out, cmd, socket, *asJSON)
	}
	c, err := load()
	if err != nil {
		return invalid(err)
	}
	if cmd == "status" || cmd == "connections" || cmd == "reload" {
		return inspect(out, cmd, c.Runtime.ControlSocket, *asJSON)
	}
	if cmd == "hosts" {
		if address == "" {
			address = c.Hosts.Address
		}
		ip, e := netip.ParseAddr(address)
		if e != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
			return invalid(errors.New("--address must be unicast IPv4"))
		}
		if sub == "status" {
			p, e := hosts.Prepare("/etc/hosts", c.Domains, address, false)
			if *asJSON {
				_ = emit(out, p)
			} else {
				fmt.Fprint(out, p.Diff)
				if len(p.Managed) > 0 {
					fmt.Fprintln(out, "Managed entries:", strings.Join(p.Managed, ", "))
				}
			}
			return e
		}
		if sub != "apply" {
			return invalid(errors.New("use hosts status, apply or remove"))
		}
		if !dry {
			if e = hostsPreflight(c, address); e != nil {
				return e
			}
		}
		return changeHosts(out, &c, address, false, dry)
	}
	if cmd == "config" && sub == "show" {
		return emit(out, c)
	}
	if _, err = ca.Load(c.CA.Cert, c.CA.Key); err != nil {
		return err
	}
	if cmd == "config" {
		if sub != "validate" {
			return invalid(errors.New("use config init, validate or show"))
		}
		fmt.Fprintln(out, "Configuration and CA are valid.")
		return nil
	}
	if cmd == "doctor" {
		return doctor(out, c, *path, domain)
	}
	if cmd == "install-service" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		p, text, e := service.Install(ctx, c, *path, dry)
		if dry || *asJSON {
			_ = emit(out, p)
		}
		fmt.Fprintln(out, text)
		return e
	}
	if cmd == "serve" {
		var destination io.Writer = errOut
		if logFile != "" {
			rot, e := logging.Open(logFile)
			if e != nil {
				return e
			}
			defer rot.Close()
			destination = rot
		}
		level := new(slog.LevelVar)
		var l slog.Level
		_ = l.UnmarshalText([]byte(c.Log.Level))
		level.Set(l)
		options := &slog.HandlerOptions{Level: level}
		var handler slog.Handler = slog.NewJSONHandler(destination, options)
		if c.Log.Format == "text" {
			handler = slog.NewTextHandler(destination, options)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		abs, e := filepath.Abs(*path)
		if e != nil {
			return e
		}
		s, e := proxy.New(ctx, c, abs, version, load, slog.New(handler), level)
		if e != nil {
			return e
		}
		signals := make(chan os.Signal, 4)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer signal.Stop(signals)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case sig := <-signals:
					if sig == syscall.SIGHUP {
						if e := s.Reload(ctx); e != nil {
							slog.New(handler).Error("reload rejected", "error", e)
						}
					} else {
						signal.Reset(os.Interrupt, syscall.SIGTERM)
						cancel()
						return
					}
				}
			}
		}()
		return s.Run(ctx)
	}
	return invalid(fmt.Errorf("unsupported command %s", cmd))
}
func inspect(out io.Writer, cmd, socket string, asJSON bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if cmd == "status" {
		var s proxy.Status
		if e := control.Request(ctx, socket, "GET", "/v1/status", &s); e != nil {
			return coded{3, e}
		}
		if asJSON {
			_ = emit(out, s)
		} else {
			fmt.Fprintf(out, "utlsproxy %s — %s (PID %d, uptime %s)\nListen: %s\nProfile: %s / %s\nConnections: %d active, %d total; sent %d, received %d bytes\nDNS: %s, %s, generation %d\n", s.Version, s.Health, s.PID, s.Uptime, strings.Join(s.Config.Listen, ", "), s.Config.Upstream.Profile, s.Config.Upstream.ALPNMode, s.Active, s.Total, s.BytesSent, s.BytesReceived, s.DNS.Mode, s.DNS.Source, s.DNS.Generation)
			for _, g := range s.DNS.Groups {
				fmt.Fprintf(out, "  %s (domains=%v, interface=%d)\n", strings.Join(g.Servers, ", "), g.Domains, g.Interface)
			}
			for _, reason := range s.Reasons {
				fmt.Fprintln(out, "  "+reason)
			}
		}
		if s.Health != "ready" {
			return service.ErrDegraded
		}
		return nil
	}
	path, method := "/v1/connections", "GET"
	if cmd == "reload" {
		path, method = "/v1/reload", "POST"
	}
	var v any
	if e := control.Request(ctx, socket, method, path, &v); e != nil {
		return coded{3, e}
	}
	return emit(out, v)
}
func doctor(out io.Writer, c config.Config, path, domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.Runtime.HandshakeTimeout.Value()+5*time.Second)
	defer cancel()
	r := dns.New(ctx, c.DNS)
	result := map[string]any{"schema_version": 1, "configuration": path, "configuration_valid": true, "ca_valid": true, "dns": r.Status(), "trust_installation": "manual; this check cannot prove trust in every application"}
	var state proxy.Status
	if e := control.Request(ctx, c.Runtime.ControlSocket, "GET", "/v1/status", &state); e == nil {
		result["daemon"] = state.Health
	} else {
		result["daemon"] = "not running at configured socket"
	}
	var probeErr error
	if domain != "" {
		host, e := config.Domain(domain)
		if e != nil || !c.AllowsDomain(host) {
			return invalid(errors.New("doctor --domain requires an exact configured domain"))
		}
		u, mods, ip, e := proxy.DialUpstream(ctx, c, r, host, []string{"h2", "http/1.1"})
		if e != nil {
			probeErr = e
			result["probe_error"] = e.Error()
		} else {
			st := u.ConnectionState()
			result["probe"] = map[string]any{"domain": host, "upstream": ip, "profile": c.Upstream.Profile, "modifications": mods, "tls_version": st.Version, "alpn": st.NegotiatedProtocol, "certificate_verified": len(st.VerifiedChains) > 0}
			u.Close()
		}
	}
	_ = emit(out, result)
	if probeErr != nil {
		return probeErr
	}
	if r.Status().LastError != "" {
		return service.ErrDegraded
	}
	return nil
}
func hostsPreflight(c config.Config, address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ip, _ := netip.ParseAddr(address)
	local, e := dns.LocalAddresses()
	if e != nil {
		return e
	}
	if !ip.IsLoopback() && !local[ip] {
		conn, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(address, "443"))
		if e != nil {
			return e
		}
		conn.Close()
		return nil
	}
	var s proxy.Status
	if e = control.Request(ctx, c.Runtime.ControlSocket, "GET", "/v1/status", &s); e != nil {
		return e
	}
	if s.Health != "ready" {
		return errors.New("hosts apply requires a ready daemon")
	}
	listening := false
	for _, l := range s.Config.Listen {
		a, e := netip.ParseAddrPort(l)
		if e == nil && a.Port() == 443 && (a.Addr() == ip || a.Addr().IsUnspecified()) {
			listening = true
		}
	}
	if !listening {
		return errors.New("daemon must listen on the hosts destination at port 443")
	}
	for _, d := range c.Domains {
		if !s.Config.AllowsDomain(d) {
			return fmt.Errorf("daemon does not allow %s; reload first", d)
		}
	}
	r := dns.New(ctx, s.Config.DNS)
	for _, d := range c.Domains {
		probe, cancel := context.WithTimeout(ctx, s.Config.Runtime.HandshakeTimeout.Value())
		u, _, _, e := proxy.DialUpstream(probe, s.Config, r, d, []string{"h2", "http/1.1"})
		cancel()
		if e != nil {
			return fmt.Errorf("hosts preflight %s: %w", d, e)
		}
		u.Close()
	}
	return nil
}
func changeHosts(out io.Writer, c *config.Config, address string, remove, dry bool) error {
	var domains []string
	stateDir := config.PlatformPaths().State
	if c != nil {
		domains = c.Domains
		stateDir = c.Runtime.StateDir
		local, e := dns.LocalAddresses()
		if e != nil {
			return e
		}
		ip, _ := netip.ParseAddr(address)
		if !ip.IsLoopback() && !local[ip] {
			fmt.Fprintln(out, "LAN target: only TCP reachability can be checked; verify the remote domain allowlist and CA trust on each client.")
		}
	}
	p, e := hosts.Prepare("/etc/hosts", domains, address, remove)
	if e != nil {
		return e
	}
	fmt.Fprint(out, p.Diff)
	if dry || !p.Changed {
		return nil
	}
	if os.Geteuid() != 0 {
		return os.ErrPermission
	}
	backup, e := hosts.Apply(p, stateDir)
	if e != nil {
		return e
	}
	fmt.Fprintf(out, "Hosts updated. Backup: %s\nRefresh browser connections; OS/browser DNS caches may need refreshing.\n", backup)
	return nil
}
