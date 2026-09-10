// SPDX-License-Identifier: GPL-3.0-only
//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	app "impair.local/impair/internal/impair"
)

const usage = `impair: Linux network impairment appliance

Usage:
  impair example --mode host --interface ens5 > profile.json
  impair validate --profile profile.json
  impair plan --profile profile.json [--json]
  sudo impair doctor [--interface ens5] [--gateway]
  sudo impair apply --profile profile.json [--duration 10m] [--dry-run]
  sudo impair status [--json]
  sudo impair stop

Commands:
  example   Print a starter profile (host or gateway).
  validate  Validate JSON, units, selectors, and parameter combinations.
  plan      Show exact commands without changing the host; not a capability test.
  doctor    Read-only dependency, privilege, interface, and ENA diagnostics.
  apply     Apply a profile, with independent systemd expiry by default.
  status    Show journal and live kernel counters.
  stop      Remove only the current experiment's owned resources; safe to repeat.
  version   Print application version.

A profile may contain multiple interfaces, with one rule per direction each.
Run any command with --help for its flags. See README for routing prerequisites.
`

func main() {
	if e := mainErr(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "impair:", e)
		os.Exit(1)
	}
}
func output(v any) error              { e := json.NewEncoder(os.Stdout); e.SetIndent("", "  "); return e.Encode(v) }
func flags(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ContinueOnError) }
func parse(f *flag.FlagSet, args []string) error {
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", f.Arg(0))
	}
	return nil
}
func root() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root; use sudo")
	}
	return nil
}
func mainErr(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "version", "--version":
		fmt.Println("impair", app.Version)
		return nil
	case "example":
		return example(args[1:])
	case "doctor":
		return doctor(args[1:])
	case "validate", "plan", "apply":
		name := args[0]
		f := flags(name)
		path := f.String("profile", "", "JSON profile path (required)")
		js := f.Bool("json", false, "print structured JSON")
		dry := false
		noWatch := false
		dur := 10 * time.Minute
		dir := "/run/impair"
		if name == "apply" {
			f.BoolVar(&dry, "dry-run", false, "print plan only; makes no changes")
			f.BoolVar(&noWatch, "no-watchdog", false, "explicitly disable expiry (isolated labs only)")
			f.DurationVar(&dur, "duration", 10*time.Minute, "automatic expiry: 5s..24h")
			f.StringVar(&dir, "state-dir", dir, "private state directory")
		}
		if e := parse(f, args[1:]); e != nil {
			if e == flag.ErrHelp {
				return nil
			}
			return e
		}
		if *path == "" {
			return fmt.Errorf("--profile is required")
		}
		p, e := app.Load(*path)
		if e != nil {
			return e
		}
		if name == "validate" {
			if *js {
				return output(p)
			}
			fmt.Printf("Valid profile: %s (%d rules)\n", p.Name, len(p.Rules))
			return nil
		}
		if name == "plan" || dry {
			plan := app.Build(p, "0000000000000000")
			if *js {
				return output(plan)
			}
			fmt.Println("# Offline plan. Runtime IDs will differ; apply also performs preflight and arms expiry.")
			if p.Gateway != nil {
				fmt.Println("# Prerequisite: IPv4 forwarding, routes, and host/VPC firewall permissions.")
			}
			if p.ManagementPolicy == "separate" {
				fmt.Println("# Separate management: selected transit traffic has no automatic port/address bypasses. Provision forwarding, routes, and an independent management path.")
			}
			for _, check := range plan.TransportChecks {
				fmt.Printf("# IPv4 transport %s: required provisioned Ethernet MTU %d = BLACK MTU %d - overhead %d; netem overhead %d accounts in outer IP bytes. No tunnel headers are created.\n", check.Device, check.InnerMTU, check.BlackMTU, check.OverheadBytes, check.NetemOverheadBytes)
			}
			for _, c := range plan.Commands {
				fmt.Println(c.String())
			}
			return nil
		}
		if e = root(); e != nil {
			return e
		}
		store, e := app.OpenStore(dir)
		if e != nil {
			return e
		}
		defer store.Close()
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		exe, e = filepath.EvalSymlinks(exe)
		if e != nil {
			return e
		}
		s, e := app.Apply(store, app.ExecRunner{}, p, app.ApplyOptions{Duration: dur, NoWatchdog: noWatch, Executable: exe})
		if e != nil {
			return e
		}
		if *js {
			return output(s)
		}
		fmt.Printf("Applied %s (id %s).\n", p.Name, s.ID)
		if s.Expires != nil {
			fmt.Println("Expires:", s.Expires.Format(time.RFC3339))
		} else {
			fmt.Println("No watchdog: run 'sudo impair stop' to remove this experiment.")
		}
		return nil
	case "status", "stop":
		f := flags(args[0])
		dir := f.String("state-dir", "/run/impair", "private state directory")
		js := f.Bool("json", false, "print structured JSON")
		token := f.String("token", "", "internal expiry token; ignores a different experiment")
		if e := parse(f, args[1:]); e != nil {
			if e == flag.ErrHelp {
				return nil
			}
			return e
		}
		if e := root(); e != nil {
			return e
		}
		store, e := app.OpenStore(*dir)
		if e != nil {
			return e
		}
		defer store.Close()
		if args[0] == "stop" {
			if e = app.Stop(store, app.ExecRunner{}, *token); e != nil {
				return e
			}
			if *js {
				return output(map[string]string{"status": "stopped-or-already-absent"})
			}
			fmt.Println("Cleanup complete (or no matching experiment). ")
			return nil
		}
		s, e := store.Read()
		if e != nil {
			return e
		}
		live, e := app.Inspect(app.ExecRunner{}, s)
		if e != nil {
			return e
		}
		if *js {
			return output(live)
		}
		if s == nil {
			fmt.Println("No active experiment.")
			return nil
		}
		fmt.Printf("%s | %s | %s\n", s.ID, s.Profile.Name, s.Phase)
		if s.Expires != nil {
			fmt.Println("Expires:", s.Expires.Format(time.RFC3339))
		}
		if s.LastError != "" {
			fmt.Println("Last error:", s.LastError)
		}
		fmt.Println("Live counters:")
		return output(map[string]any{"qdiscs": live["qdiscs"], "filters": live["filters"], "nftables": live["nftables"]})
	default:
		return fmt.Errorf("unknown command %q; run impair --help", args[0])
	}
}

func example(args []string) error {
	f := flags("example")
	mode := f.String("mode", "host", "host or gateway")
	iface := f.String("interface", "ens5", "host interface")
	inside := f.String("inside", "ens6", "gateway client-facing interface")
	outside := f.String("outside", "ens5", "gateway server-facing interface")
	if e := parse(f, args); e != nil {
		if e == flag.ErrHelp {
			return nil
		}
		return e
	}
	n := app.Impairment{Delay: "50ms", Jitter: "10ms", Distribution: "normal", Rate: "10mbit", Loss: 0.1, Limit: 10000}
	p := app.Profile{Version: 1, Name: "WAN example", Rules: []app.Rule{{Interface: *iface, Direction: "egress", Match: app.Match{Destination: "198.51.100.20/32"}, Impairment: n}, {Interface: *iface, Direction: "ingress", Match: app.Match{Source: "198.51.100.20/32"}, Impairment: n}}}
	switch *mode {
	case "host":
	case "gateway":
		p.Name = "Routed WAN example"
		p.Rules = []app.Rule{{Interface: *outside, Direction: "egress", Match: app.Match{InputInterface: *inside, Family: "ipv4"}, Impairment: n}, {Interface: *inside, Direction: "egress", Match: app.Match{InputInterface: *outside, Family: "ipv4"}, Impairment: n}}
		p.Gateway = &app.Gateway{Inside: *inside, Outside: *outside, ClientCIDR: "10.10.1.0/24", Masquerade: false}
	default:
		return fmt.Errorf("mode must be host or gateway")
	}
	if e := p.Validate(); e != nil {
		return e
	}
	return output(p)
}

func doctor(args []string) error {
	f := flags("doctor")
	iface := f.String("interface", "", "optional interface for qdisc and ENA diagnostics")
	gateway := f.Bool("gateway", false, "also require nftables and IPv4 forwarding")
	if e := parse(f, args); e != nil {
		if e == flag.ErrHelp {
			return nil
		}
		return e
	}
	r := app.ExecRunner{}
	bad := false
	fmt.Println("impair", app.Version, "| read-only diagnostics")
	names := []string{"ip", "tc"}
	if *gateway {
		names = append(names, "nft")
	}
	for _, name := range names {
		p, e := app.Tool(name)
		if e != nil {
			fmt.Println("FAIL", e)
			bad = true
			continue
		}
		fmt.Println("OK", name, p)
	}
	b, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return e
	}
	caps := uint64(0)
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			caps, _ = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		}
	}
	if caps&(1<<12) == 0 {
		fmt.Println("FAIL CAP_NET_ADMIN is unavailable (rerun as root on the target Linux host)")
		bad = true
	} else {
		fmt.Println("OK CAP_NET_ADMIN")
	}
	b, e = r.Run(app.Command{Args: []string{"systemctl", "show", "--property=Version", "--value"}})
	if e != nil {
		fmt.Println("WARN systemd expiry unavailable; normal apply will refuse without --no-watchdog")
	} else {
		fmt.Println("OK systemd", strings.TrimSpace(string(b)))
	}
	b, e = os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if e == nil {
		fmt.Println("IPv4 forwarding:", strings.TrimSpace(string(b)))
		if *gateway && strings.TrimSpace(string(b)) != "1" {
			bad = true
			fmt.Println("FAIL enable IPv4 forwarding before gateway mode")
		}
	}
	b, e = r.Run(app.Command{Args: []string{"ip", "-j", "-d", "link", "show"}})
	if e != nil {
		return e
	}
	fmt.Println("Interfaces:", string(b))
	if *iface != "" {
		// Validation prevents option injection even though subprocesses never use a shell.
		p := app.Profile{Version: 1, Name: "doctor", Rules: []app.Rule{{Interface: *iface, Direction: "egress", Impairment: app.Impairment{Delay: "1ms"}}}}
		if e = p.Validate(); e != nil {
			return e
		}
		for _, argv := range [][]string{{"tc", "-j", "-s", "qdisc", "show", "dev", *iface}, {"ethtool", "-i", *iface}, {"ethtool", "-k", *iface}, {"ethtool", "-S", *iface}} {
			b, e = r.Run(app.Command{Args: argv})
			if e != nil {
				fmt.Println("WARN", e)
			} else {
				fmt.Println(strings.Join(argv, " ") + ":\n" + string(b))
			}
		}
	}
	fmt.Println("Kernel qdisc/filter support is checked by apply; doctor does not create probe devices or load modules.")
	fmt.Println("EC2 route tables, security groups, NACLs, and source/destination checks must be verified separately.")
	if bad {
		return fmt.Errorf("one or more required checks failed")
	}
	return nil
}
