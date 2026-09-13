// Package service generates and manages native system-service definitions.
package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/unixapple/utlsproxy/internal/config"
	"github.com/unixapple/utlsproxy/internal/control"
	"github.com/unixapple/utlsproxy/internal/fsutil"
	"github.com/unixapple/utlsproxy/internal/proxy"
)

const Label = "local.utlsproxy"

type Plan struct {
	SchemaVersion  int    `json:"schema_version"`
	Executable     string `json:"executable"`
	DefinitionPath string `json:"definition_path"`
	Configuration  string `json:"configuration"`
	Definition     string `json:"definition"`
	Log            string `json:"log,omitempty"`
}
type Manifest struct {
	Version        int    `json:"version"`
	Executable     string `json:"executable"`
	ExecutableSHA  string `json:"executable_sha256"`
	DefinitionPath string `json:"definition_path"`
	DefinitionSHA  string `json:"definition_sha256"`
	Config         string `json:"config"`
	Socket         string `json:"socket"`
}

func escaped(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func systemdArg(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "$", "$$")
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}
func Generate(osName string, p config.Paths, c config.Config, path string) (Plan, error) {
	for _, s := range []string{path, p.Executable, p.Log} {
		if strings.ContainsAny(s, "\n\r\x00") {
			return Plan{}, errors.New("service paths must not contain newlines or NUL")
		}
	}
	plan := Plan{SchemaVersion: 1, Executable: p.Executable, DefinitionPath: p.Service, Configuration: path, Log: p.Log}
	if osName == "darwin" {
		plan.Definition = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string><string>serve</string><string>--config</string><string>%s</string><string>--log-file</string><string>%s</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>ExitTimeOut</key><integer>%d</integer>
<key>UserName</key><string>root</string><key>Umask</key><integer>63</integer>
</dict></plist>
`, Label, escaped(p.Executable), escaped(path), escaped(p.Log), int(c.Runtime.ShutdownTimeout.Value().Seconds())+5)
	} else if osName == "linux" {
		plan.Definition = fmt.Sprintf(`[Unit]
Description=utlsproxy TLS fingerprint proxy
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=%s serve --config %s
User=root
Restart=always
RestartSec=3
TimeoutStopSec=%d
UMask=0077
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, systemdArg(p.Executable), systemdArg(path), int(c.Runtime.ShutdownTimeout.Value().Seconds())+5)
	} else {
		return plan, fmt.Errorf("service installation unsupported on %s", osName)
	}
	return plan, nil
}
func tool() (string, error) {
	if runtime.GOOS == "darwin" {
		return "/bin/launchctl", nil
	}
	if runtime.GOOS == "linux" {
		for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
			if _, e := os.Stat(p); e == nil {
				return p, nil
			}
		}
	}
	return "", errors.New("native service manager unavailable; use foreground serve")
}
func run(ctx context.Context, args ...string) (string, error) {
	bin, err := tool()
	if err != nil {
		return "", err
	}
	b, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err != nil {
		return string(b), fmt.Errorf("%s %v: %w: %s", bin, args, err, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}
func Native(ctx context.Context, action string) (string, error) {
	p := config.PlatformPaths()
	if action != "status" && os.Geteuid() != 0 {
		return "", os.ErrPermission
	}
	if runtime.GOOS == "darwin" {
		switch action {
		case "status":
			return run(ctx, "print", "system/"+Label)
		case "start":
			if _, e := run(ctx, "print", "system/"+Label); e == nil {
				return run(ctx, "kickstart", "system/"+Label)
			}
			return run(ctx, "bootstrap", "system", p.Service)
		case "stop":
			return run(ctx, "bootout", "system/"+Label)
		case "restart":
			if _, e := run(ctx, "print", "system/"+Label); e == nil {
				return run(ctx, "kickstart", "-k", "system/"+Label)
			}
			return run(ctx, "bootstrap", "system", p.Service)
		}
	} else {
		if action == "status" {
			text, err := run(ctx, "show", "utlsproxy.service", "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,Result")
			if err == nil && !strings.Contains(text, "ActiveState=active\n") {
				err = errors.New("service is not active")
			}
			return text, err
		}
		if action == "restart" || action == "start" {
			_, _ = run(ctx, "reset-failed", "utlsproxy.service")
		}
		if action == "start" || action == "stop" || action == "restart" {
			return run(ctx, action, "utlsproxy.service")
		}
	}
	return "", fmt.Errorf("unknown service action %s", action)
}
func manifestPath() string {
	return filepath.Join(filepath.Dir(config.PlatformPaths().Config), "installation.json")
}
func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func readManifest() (Manifest, error) {
	var m Manifest
	b, e := os.ReadFile(manifestPath())
	if e != nil {
		return m, e
	}
	e = json.Unmarshal(b, &m)
	if e == nil && (m.Version != 1 || m.Executable != config.PlatformPaths().Executable || m.DefinitionPath != config.PlatformPaths().Service) {
		e = errors.New("invalid installation manifest")
	}
	return m, e
}
func inspectOwned(path, want string) error {
	if err := fsutil.Regular(path); err != nil {
		return err
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if sha(b) != want {
		return fmt.Errorf("owned installation file was modified: %s", path)
	}
	return nil
}
func Install(ctx context.Context, c config.Config, path string, dry bool) (Plan, string, error) {
	p := config.PlatformPaths()
	path, err := filepath.Abs(path)
	if err != nil {
		return Plan{}, "", err
	}
	plan, err := Generate(runtime.GOOS, p, c, path)
	if err != nil {
		return plan, "", err
	}
	if dry {
		return plan, "dry run: no files or service state changed", nil
	}
	if os.Geteuid() != 0 {
		return plan, "", os.ErrPermission
	}
	if _, err = tool(); err != nil {
		return plan, "", err
	}
	for _, f := range []string{path, c.CA.Cert, c.CA.Key} {
		if err = fsutil.RootOwned(f); err != nil {
			return plan, "", err
		}
		real, e := filepath.EvalSymlinks(f)
		if e != nil {
			return plan, "", e
		}
		if strings.HasPrefix(real, "/Volumes/") || strings.HasPrefix(real, "/media/") || strings.HasPrefix(real, "/run/user/") {
			return plan, "", fmt.Errorf("service path may be unavailable at boot: %s", real)
		}
	}
	if err = fsutil.PrivateDir(filepath.Dir(manifestPath())); err != nil {
		return plan, "", err
	}
	unlock, err := fsutil.Lock(manifestPath() + ".lock")
	if err != nil {
		return plan, "", err
	}
	defer unlock()
	old, oldErr := readManifest()
	exists := oldErr == nil
	if oldErr != nil && !os.IsNotExist(oldErr) {
		return plan, "", oldErr
	}
	for _, target := range []string{p.Executable, p.Service} {
		if _, e := os.Lstat(target); e == nil {
			if !exists {
				return plan, "", fmt.Errorf("unowned installation target exists: %s", target)
			}
			want := old.ExecutableSHA
			if target == p.Service {
				want = old.DefinitionSHA
			}
			if err = inspectOwned(target, want); err != nil {
				return plan, "", err
			}
		} else if !os.IsNotExist(e) {
			return plan, "", e
		}
	}
	self, err := os.Executable()
	if err != nil {
		return plan, "", err
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		return plan, "", err
	}
	var current proxy.Status
	if e := control.Request(ctx, c.Runtime.ControlSocket, "GET", "/v1/status", &current); e == nil && !exists {
		return plan, "", errors.New("foreground daemon is running; stop it before installing the service")
	}
	for _, dir := range []string{filepath.Dir(p.Executable), filepath.Dir(p.Service)} {
		if err = os.MkdirAll(dir, 0755); err != nil {
			return plan, "", err
		}
		if err = fsutil.RootOwned(dir); err != nil {
			return plan, "", err
		}
	}
	if err = fsutil.PrivateDir(c.Runtime.StateDir); err != nil {
		return plan, "", err
	}
	if err = fsutil.RootOwned(c.Runtime.StateDir); err != nil {
		return plan, "", err
	}
	if exists && old.ExecutableSHA == sha(binary) && old.DefinitionSHA == sha([]byte(plan.Definition)) && old.Config == path && old.Socket == c.Runtime.ControlSocket {
		if runtime.GOOS == "darwin" {
			_, err = run(ctx, "enable", "system/"+Label)
		} else {
			_, err = run(ctx, "enable", "utlsproxy.service")
		}
		if err != nil {
			return plan, "", err
		}
		if _, err = Native(ctx, "start"); err != nil {
			return plan, "", err
		}
		if err = awaitDaemon(ctx, c.Runtime.ControlSocket, path); err != nil {
			return plan, "installation unchanged; service health check did not pass", err
		}
		return plan, "installation unchanged; enabled at boot and running", nil
	}
	var oldBinary, oldDefinition, oldManifest []byte
	if exists {
		oldBinary, _ = os.ReadFile(p.Executable)
		oldDefinition, _ = os.ReadFile(p.Service)
		oldManifest, _ = os.ReadFile(manifestPath())
		backup := filepath.Join(c.Runtime.StateDir, "service-backup-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
		if err = fsutil.PrivateDir(backup); err != nil {
			return plan, "", err
		}
		for name, b := range map[string][]byte{"utlsproxy": oldBinary, "service": oldDefinition, "installation.json": oldManifest} {
			if err = fsutil.Exclusive(filepath.Join(backup, name), b, 0600); err != nil {
				return plan, "", err
			}
		}
	}
	wroteBin, wroteDef := false, false
	rollback := func(cause error) (Plan, string, error) {
		recovery, recoverCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer recoverCancel()
		_, _ = Native(recovery, "stop")
		var problems []error
		if wroteBin {
			if exists {
				problems = append(problems, fsutil.Atomic(p.Executable, oldBinary, 0755))
			} else {
				problems = append(problems, os.Remove(p.Executable))
			}
		}
		if wroteDef {
			if exists {
				problems = append(problems, fsutil.Atomic(p.Service, oldDefinition, 0644))
			} else {
				problems = append(problems, os.Remove(p.Service))
			}
		}
		if exists {
			problems = append(problems, fsutil.Atomic(manifestPath(), oldManifest, 0600))
		} else {
			if e := os.Remove(manifestPath()); !os.IsNotExist(e) {
				problems = append(problems, e)
			}
		}
		if runtime.GOOS == "linux" {
			_, e := run(recovery, "daemon-reload")
			problems = append(problems, e)
		}
		if exists {
			_, e := Native(recovery, "start")
			problems = append(problems, e)
		} else if runtime.GOOS == "linux" {
			_, _ = run(recovery, "disable", "utlsproxy.service")
		}
		return plan, "installation failed; restored previous owned files where possible", errors.Join(append([]error{cause}, problems...)...)
	}
	if exists {
		if _, e := Native(ctx, "status"); e == nil {
			if _, e = Native(ctx, "stop"); e != nil {
				return plan, "service update stopped before replacing files", e
			}
		}
	}
	if !exists || old.ExecutableSHA != sha(binary) {
		if err = fsutil.Atomic(p.Executable, binary, 0755); err != nil {
			return rollback(err)
		}
		wroteBin = true
	}
	if err = fsutil.Atomic(p.Service, []byte(plan.Definition), 0644); err != nil {
		return rollback(err)
	}
	wroteDef = true
	m := Manifest{1, p.Executable, sha(binary), p.Service, sha([]byte(plan.Definition)), path, c.Runtime.ControlSocket}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err = fsutil.Atomic(manifestPath(), b, 0600); err != nil {
		return rollback(err)
	}
	if runtime.GOOS == "darwin" {
		_, err = run(ctx, "enable", "system/"+Label)
	} else {
		if _, err = run(ctx, "daemon-reload"); err == nil {
			_, err = run(ctx, "enable", "utlsproxy.service")
		}
	}
	if err != nil {
		return rollback(err)
	}
	if _, err = Native(ctx, "start"); err != nil {
		return rollback(err)
	}
	if err = awaitDaemon(ctx, c.Runtime.ControlSocket, path); err != nil {
		if errors.Is(err, ErrDegraded) {
			return plan, "installed and started; daemon is degraded", err
		}
		return rollback(err)
	}
	return plan, "installed, enabled at boot, and running", nil
}

func awaitDaemon(ctx context.Context, socket, path string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var st proxy.Status
		probe, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		e := control.Request(probe, socket, "GET", "/v1/status", &st)
		cancel()
		if e == nil && st.ConfigPath == path {
			if st.Health != "ready" {
				return fmt.Errorf("%w: %s", ErrDegraded, strings.Join(st.Reasons, "; "))
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("service did not expose the expected control socket within 15s")
}

var ErrDegraded = errors.New("daemon is degraded")

func Uninstall(ctx context.Context, dry bool) (string, error) {
	if !dry {
		if os.Geteuid() != 0 {
			return "", os.ErrPermission
		}
		if _, e := os.Stat(filepath.Dir(manifestPath())); os.IsNotExist(e) {
			return "no owned service installation found", nil
		}
		unlock, e := fsutil.Lock(manifestPath() + ".lock")
		if e != nil {
			return "", e
		}
		defer unlock()
	}
	m, err := readManifest()
	if os.IsNotExist(err) {
		return "no owned service installation found", nil
	}
	if err != nil {
		return "", err
	}
	if dry {
		return fmt.Sprintf("Would stop/unregister service and remove %s, %s, %s; preserve CA/config/state/logs", m.Executable, m.DefinitionPath, manifestPath()), nil
	}
	if os.Geteuid() != 0 {
		return "", os.ErrPermission
	}
	for path, hash := range map[string]string{m.Executable: m.ExecutableSHA, m.DefinitionPath: m.DefinitionSHA} {
		if err = inspectOwned(path, hash); err != nil {
			return "", err
		}
	}
	_, stopErr := Native(ctx, "stop")
	if stopErr != nil {
		var st proxy.Status
		if e := control.Request(ctx, m.Socket, "GET", "/v1/status", &st); e == nil {
			return "", stopErr
		}
	}
	if runtime.GOOS == "linux" {
		if _, err = run(ctx, "disable", "utlsproxy.service"); err != nil {
			return "", err
		}
	}
	if err = os.Remove(m.DefinitionPath); err != nil {
		return "", err
	}
	if runtime.GOOS == "linux" {
		if _, err = run(ctx, "daemon-reload"); err != nil {
			return "", err
		}
	}
	if err = os.Remove(m.Executable); err != nil {
		return "", err
	}
	if err = os.Remove(manifestPath()); err != nil {
		return "", err
	}
	return "service uninstalled; CA, configuration, state and logs retained", nil
}
