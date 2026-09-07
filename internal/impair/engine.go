// SPDX-License-Identifier: GPL-3.0-only
package impair

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Runner interface{ Run(Command) ([]byte, error) }
type ExecRunner struct{}

var allowedTools = map[string]bool{"ip": true, "tc": true, "nft": true, "systemd-run": true, "systemctl": true, "ethtool": true}

func Tool(name string) (string, error) {
	if !allowedTools[name] {
		return "", fmt.Errorf("unsupported executable %q", name)
	}
	// Ignore PATH, including the caller's working directory, for privileged execution.
	for _, d := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p := filepath.Join(d, name)
		s, e := os.Stat(p)
		if e == nil && s.Mode().IsRegular() && s.Mode()&0111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s is missing; install the dependency (see README)", name)
}
func (ExecRunner) Run(c Command) ([]byte, error) {
	p, e := Tool(c.Args[0])
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, c.Args[1:]...)
	cmd.Stdin = strings.NewReader(c.Input)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s: %w: %s", strings.Join(c.Args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}
func run(r Runner, args ...string) ([]byte, error) { return r.Run(Command{Args: args}) }
func query[T any](r Runner, args ...string) (T, error) {
	var v T
	b, e := run(r, args...)
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(b, &v)
	return v, e
}

type Link struct {
	Index int    `json:"ifindex"`
	Name  string `json:"ifname"`
	Alias string `json:"ifalias"`
	Info  struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}
type Qdisc struct {
	Kind   string `json:"kind"`
	Handle string `json:"handle"`
	Root   bool   `json:"root"`
	Parent string `json:"parent"`
}
type State struct {
	Version           int            `json:"version"`
	ID                string         `json:"id"`
	Namespace         string         `json:"network_namespace"`
	Created           time.Time      `json:"created"`
	Expires           *time.Time     `json:"expires,omitempty"`
	Phase             string         `json:"phase"`
	Profile           Profile        `json:"profile"`
	Plan              Plan           `json:"plan"`
	Interfaces        map[string]int `json:"interfaces"`
	Timer             string         `json:"timer,omitempty"`
	CompletedCommands int            `json:"completed_commands"`
	LastError         string         `json:"last_error,omitempty"`
}
type Store struct {
	Dir  string
	lock *os.File
}

func OpenStore(dir string) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("state directory must be absolute")
	}
	// Refuse symlinks in the path. The leaf must be private and owned by the caller.
	for p := filepath.Clean(dir); p != "/"; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		if e == nil && s.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink in state directory path: %s", p)
		}
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	s, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || s.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("state directory must be owned by current user and mode 0700")
	}
	fd, e := syscall.Open(filepath.Join(dir, "lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "lock")
	if e = syscall.Flock(fd, syscall.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return &Store{Dir: dir, lock: f}, nil
}
func (s *Store) Close() { syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN); s.lock.Close() }
func (s *Store) Read() (*State, error) {
	b, e := os.ReadFile(filepath.Join(s.Dir, "active.json"))
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var state State
	e = json.Unmarshal(b, &state)
	if e != nil {
		return nil, e
	}
	if state.Version != 1 || len(state.ID) != 16 {
		return nil, fmt.Errorf("unrecognized state; refusing cleanup")
	}
	return &state, nil
}
func (s *Store) Save(v *State) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.Dir, "state-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, filepath.Join(s.Dir, "active.json")); e != nil {
		return e
	}
	d, e := os.Open(s.Dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (s *Store) Clear() error {
	e := os.Remove(filepath.Join(s.Dir, "active.json"))
	if os.IsNotExist(e) {
		return nil
	}
	return e
}
func namespace() (string, error) { return os.Readlink("/proc/self/ns/net") }
func newID() (string, error) {
	b := make([]byte, 8)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}

func Preflight(r Runner, p Profile, plan Plan) (map[string]int, error) {
	links, e := query[[]Link](r, "ip", "-j", "-d", "link", "show")
	if e != nil {
		return nil, e
	}
	lm := map[string]Link{}
	for _, l := range links {
		lm[l.Name] = l
	}
	indices := map[string]int{}
	need := func(name string) error {
		l, ok := lm[name]
		if !ok {
			return fmt.Errorf("interface %s does not exist", name)
		}
		indices[name] = l.Index
		return nil
	}
	for _, rule := range p.Rules {
		if e = need(rule.Interface); e != nil {
			return nil, e
		}
		if rule.Match.InputInterface != "" {
			if e = need(rule.Match.InputInterface); e != nil {
				return nil, e
			}
		}
		qs, e := query[[]Qdisc](r, "tc", "-j", "qdisc", "show", "dev", rule.Interface)
		if e != nil {
			return nil, e
		}
		for _, q := range qs {
			if rule.Direction == "ingress" && (q.Kind == "ingress" || q.Kind == "clsact") {
				return nil, fmt.Errorf("%s already has ingress/clsact; refusing to replace it", rule.Interface)
			}
			if rule.Direction == "egress" && q.Kind != "ingress" && q.Kind != "clsact" {
				defaults := map[string]bool{"noqueue": true, "mq": true, "fq_codel": true, "fq": true, "pfifo_fast": true}
				if q.Handle != "0:" || !defaults[q.Kind] {
					return nil, fmt.Errorf("%s has custom qdisc %s %s; use a dedicated test interface", rule.Interface, q.Kind, q.Handle)
				}
			}
		}
		if rule.Direction == "egress" {
			fs, e := query[[]json.RawMessage](r, "tc", "-j", "filter", "show", "dev", rule.Interface, "root")
			if e != nil {
				return nil, e
			}
			if len(fs) > 0 {
				return nil, fmt.Errorf("%s has root filters", rule.Interface)
			}
		}
	}
	if p.Gateway != nil {
		for _, name := range []string{p.Gateway.Inside, p.Gateway.Outside} {
			if e = need(name); e != nil {
				return nil, e
			}
		}
	}
	for _, res := range plan.Resources {
		if res.Kind == "ifb" {
			if _, ok := lm[res.Device]; ok {
				return nil, fmt.Errorf("IFB name collision: %s", res.Device)
			}
		}
	}
	if p.Gateway != nil {
		raw, e := run(r, "nft", "-j", "list", "tables")
		if e != nil {
			return nil, e
		}
		for _, res := range plan.Resources {
			if res.Kind == "nft" && bytes.Contains(raw, []byte(res.Name)) {
				return nil, fmt.Errorf("nftables name collision")
			}
		}
		for _, c := range plan.Commands {
			if c.Args[0] == "nft" {
				_, e = r.Run(Command{Args: []string{"nft", "--check", "-f", "-"}, Input: c.Input})
				if e != nil {
					return nil, fmt.Errorf("nftables validation: %w", e)
				}
			}
		}
	}
	return indices, nil
}

type ApplyOptions struct {
	Duration   time.Duration
	NoWatchdog bool
	Executable string
}

func Apply(store *Store, r Runner, p Profile, opt ApplyOptions) (*State, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	old, e := store.Read()
	if e != nil {
		return nil, e
	}
	if old != nil {
		return nil, fmt.Errorf("experiment %s is %s; stop it before applying another profile", old.ID, old.Phase)
	}
	if !opt.NoWatchdog && (opt.Duration < 5*time.Second || opt.Duration > 24*time.Hour) {
		return nil, fmt.Errorf("duration must be 5s..24h")
	}
	if p.Gateway != nil {
		v, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if e != nil {
			return nil, e
		}
		if strings.TrimSpace(string(v)) != "1" {
			return nil, fmt.Errorf("gateway requires net.ipv4.ip_forward=1; enable it explicitly as described in README")
		}
	}
	ns, e := namespace()
	if e != nil {
		return nil, e
	}
	id, e := newID()
	if e != nil {
		return nil, e
	}
	plan := Build(p, id)
	indices, e := Preflight(r, p, plan)
	if e != nil {
		return nil, e
	}
	s := &State{Version: 1, ID: id, Namespace: ns, Created: time.Now().UTC(), Phase: "applying", Profile: p, Plan: plan, Interfaces: indices}
	if !opt.NoWatchdog {
		// Timers execute in the host network namespace. Never silently expire in a different one.
		host, e := os.Readlink("/proc/1/ns/net")
		if e != nil || host != ns {
			return nil, fmt.Errorf("systemd expiry requires the host network namespace; isolated tests may use --no-watchdog")
		}
		if _, e = run(r, "systemctl", "show", "--property=Version", "--value"); e != nil {
			return nil, fmt.Errorf("systemd is required for automatic expiry: %w", e)
		}
		if !filepath.IsAbs(opt.Executable) {
			return nil, fmt.Errorf("watchdog executable path must be absolute")
		}
		expires := time.Now().UTC().Add(opt.Duration)
		s.Expires = &expires
		s.Timer = "impair-" + id
	}
	if e = store.Save(s); e != nil {
		return nil, e
	}
	fail := func(cause error) (*State, error) {
		s.LastError = cause.Error()
		s.Phase = "cleanup-needed"
		_ = store.Save(s)
		clean := Stop(store, r, id)
		if clean != nil {
			return nil, errors.Join(cause, fmt.Errorf("rollback incomplete; run impair stop: %w", clean))
		}
		return nil, cause
	}
	if s.Timer != "" {
		_, e = run(r, "systemd-run", "--quiet", "--collect", "--unit="+s.Timer, "--on-active="+fmt.Sprintf("%.3fs", opt.Duration.Seconds()), "--timer-property=AccuracySec=1s", "--property=Type=oneshot", "--property=Restart=on-failure", "--property=RestartSec=5s", opt.Executable, "stop", "--state-dir", store.Dir, "--token", id)
		if e != nil {
			return fail(fmt.Errorf("could not arm expiry timer: %w", e))
		}
	}
	for i, c := range plan.Commands {
		if _, e = r.Run(c); e != nil {
			return fail(e)
		}
		s.CompletedCommands = i + 1
		if e = store.Save(s); e != nil {
			return fail(e)
		}
	}
	s.Phase = "active"
	if e = store.Save(s); e != nil {
		return fail(e)
	}
	return s, nil
}

func Stop(store *Store, r Runner, token string) error {
	s, e := store.Read()
	if e != nil || s == nil {
		return e
	}
	if token != "" && s.ID != token {
		return nil
	}
	ns, e := namespace()
	if e != nil {
		return e
	}
	if ns != s.Namespace {
		return fmt.Errorf("experiment belongs to another network namespace; refusing cleanup")
	}
	s.Phase = "stopping"
	if e = store.Save(s); e != nil {
		return e
	}
	for i := len(s.Plan.Resources) - 1; i >= 0; i-- {
		if e = removeResource(r, s, s.Plan.Resources[i]); e != nil {
			s.Phase = "cleanup-needed"
			s.LastError = e.Error()
			_ = store.Save(s)
			return e
		}
	}
	// Do not stop the service: it may be this very cleanup process.
	if s.Timer != "" {
		if _, e = run(r, "systemctl", "stop", s.Timer+".timer"); e != nil {
			// A collected / already-triggered timer is harmless; check before ignoring a stop error.
			out, check := run(r, "systemctl", "show", s.Timer+".timer", "--property=LoadState", "--value")
			if check != nil || strings.TrimSpace(string(out)) != "not-found" {
				s.LastError = e.Error()
				_ = store.Save(s)
				return e
			}
		}
	}
	return store.Clear()
}
func removeResource(r Runner, s *State, res Resource) error {
	if res.Kind == "nft" {
		b, e := run(r, "nft", "-j", "list", "tables")
		if e != nil {
			return e
		}
		var v struct {
			Nftables []struct {
				Table *struct {
					Family string `json:"family"`
					Name   string `json:"name"`
				} `json:"table"`
			} `json:"nftables"`
		}
		if e = json.Unmarshal(b, &v); e != nil {
			return e
		}
		for _, o := range v.Nftables {
			if o.Table != nil && o.Table.Family == "ip" && o.Table.Name == res.Name {
				_, e = run(r, "nft", "delete", "table", "ip", res.Name)
				return e
			}
		}
		return nil
	}
	ls, e := query[[]Link](r, "ip", "-j", "-d", "link", "show")
	if e != nil {
		return e
	}
	var link *Link
	for i := range ls {
		if ls[i].Name == res.Device {
			link = &ls[i]
			break
		}
	}
	if link == nil {
		return nil
	}
	if res.Kind == "ifb" {
		if link.Alias != res.Alias || link.Info.Kind != "ifb" {
			return fmt.Errorf("IFB ownership changed: %s", res.Device)
		}
		_, e = run(r, "ip", "link", "delete", "dev", res.Device)
		return e
	}
	if link.Index != s.Interfaces[res.Device] {
		return fmt.Errorf("interface identity changed: %s", res.Device)
	}
	qs, e := query[[]Qdisc](r, "tc", "-j", "qdisc", "show", "dev", res.Device)
	if e != nil {
		return e
	}
	for _, q := range qs {
		relevant := (res.Kind == "root" && q.Root) || (res.Kind == "ingress" && (q.Kind == "ingress" || q.Kind == "clsact"))
		if !relevant {
			continue
		}
		if res.Kind == "root" && q.Handle == "0:" {
			continue
		}
		if q.Handle != res.Handle || q.Kind != res.Qdisc {
			return fmt.Errorf("qdisc ownership changed on %s; refusing deletion", res.Device)
		}
		tail := "root"
		if res.Kind == "ingress" {
			tail = "ingress"
		}
		_, e = run(r, "tc", "qdisc", "del", "dev", res.Device, tail, "handle", res.Handle)
		return e
	}
	return nil
}

func Inspect(r Runner, s *State) (map[string]any, error) {
	out := map[string]any{"experiment": s}
	ls, e := query[[]Link](r, "ip", "-j", "-d", "link", "show")
	if e != nil {
		return out, e
	}
	out["links"] = ls
	q := map[string]json.RawMessage{}
	filters := map[string]json.RawMessage{}
	if s != nil {
		ns, e := namespace()
		if e != nil || ns != s.Namespace {
			return out, fmt.Errorf("status requested from a different network namespace")
		}
		for _, res := range s.Plan.Resources {
			if res.Device == "" {
				continue
			}
			b, e := run(r, "tc", "-j", "-s", "qdisc", "show", "dev", res.Device)
			if e != nil {
				return out, e
			}
			q[res.Device] = b
			if res.Kind == "root" || res.Kind == "ingress" {
				b, e = run(r, "tc", "-j", "-s", "filter", "show", "dev", res.Device, "parent", res.Handle)
				if e != nil {
					return out, e
				}
				filters[res.Device+"/"+res.Kind] = b
			}
		}
		if s.Profile.Gateway != nil {
			for _, res := range s.Plan.Resources {
				if res.Kind == "nft" {
					b, e := run(r, "nft", "-j", "list", "table", "ip", res.Name)
					if e != nil {
						return out, e
					}
					out["nftables"] = json.RawMessage(b)
				}
			}
		}
	}
	out["qdiscs"] = q
	out["filters"] = filters
	return out, nil
}
