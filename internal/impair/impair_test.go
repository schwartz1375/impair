// SPDX-License-Identifier: GPL-3.0-only
package impair

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sample(t *testing.T) Profile {
	t.Helper()
	p := Profile{Version: 1, Name: "test", Rules: []Rule{{Interface: "ens5", Direction: "egress", Match: Match{Destination: "192.0.2.2/32", Protocol: "tcp", DestinationPort: 443}, Impairment: Impairment{Delay: "50ms", Jitter: "10ms", Rate: "10mbit", Loss: 1}}, {Interface: "ens5", Direction: "ingress", Match: Match{Source: "192.0.2.2/32", Protocol: "tcp", SourcePort: 443}, Impairment: Impairment{Delay: "20ms"}}}}
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestProfileRejectsBadInputs(t *testing.T) {
	tests := map[string]func(*Profile){
		"shell interface":        func(p *Profile) { p.Rules[0].Interface = "eth0;id" },
		"negative loss":          func(p *Profile) { p.Rules[0].Impairment.Loss = -1 },
		"loss over 100":          func(p *Profile) { p.Rules[0].Impairment.Loss = 101 },
		"jitter alone":           func(p *Profile) { p.Rules[0].Impairment.Delay = "" },
		"unit ambiguity":         func(p *Profile) { p.Rules[0].Impairment.Rate = "10mbps" },
		"bad delay":              func(p *Profile) { p.Rules[0].Impairment.Delay = "$(id)" },
		"bare delay":             func(p *Profile) { p.Rules[0].Impairment.Delay = "50" },
		"mixed families":         func(p *Profile) { p.Rules[0].Match.Source = "2001:db8::1" },
		"port without transport": func(p *Profile) { p.Rules[0].Match.Protocol = "" },
		"duplicate direction":    func(p *Profile) { p.Rules[1].Direction = "egress" },
		"zero rate":              func(p *Profile) { p.Rules[0].Impairment.Rate = "0mbit" },
		"huge rate":              func(p *Profile) { p.Rules[0].Impairment.Rate = "99999gbit" },
		"negative queue":         func(p *Profile) { p.Rules[0].Impairment.Limit = -1 },
		"reorder no delay":       func(p *Profile) { p.Rules[1].Impairment = Impairment{Reorder: 1} },
		"mapped IPv6":            func(p *Profile) { p.Rules[0].Match.Source = "::ffff:192.0.2.1" },
		"wrong icmp":             func(p *Profile) { p.Rules[1].Match = Match{Family: "ipv6", Protocol: "icmp"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := sample(t)
			mutate(&p)
			if p.Validate() == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}
func TestStrictJSON(t *testing.T) {
	for _, s := range []string{`{"version":1,"name":"x","rules":[],"typo":1}`, `{} {}`, `{"version":2,"name":"x"}`, `{"version":1,"name":"empty"}`} {
		if _, e := Decode(strings.NewReader(s)); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
func TestNetemArguments(t *testing.T) {
	seed := uint32(5)
	n := Impairment{Delay: "100ms", Jitter: "10ms", Correlation: 25, Distribution: "normal", Loss: 0.5, Duplicate: 1, Corrupt: 2, Reorder: 3, Rate: "8mbit", Seed: &seed}
	if e := n.validate(); e != nil {
		t.Fatal(e)
	}
	got := strings.Join(n.Args(), " ")
	want := "netem limit 10000 delay 100.000000ms 10.000000ms 25% distribution normal loss 0.5% duplicate 1% corrupt 2% reorder 3% rate 8mbit seed 5"
	if got != want {
		t.Fatalf("%s", got)
	}
	n.Distribution = "uniform"
	if strings.Contains(strings.Join(n.Args(), " "), "distribution") {
		t.Fatal("uniform should use netem's built-in jitter distribution")
	}
}
func TestPlanTrafficPathAndProtection(t *testing.T) {
	p := sample(t)
	p.SSHPorts = []int{2222}
	p.Protect = []string{"10.20.0.0/16"}
	plan := Build(p, "0123456789abcdef")
	var egress, ingress []Command
	for _, c := range plan.Commands {
		v := strings.Join(c.Args, " ")
		if strings.Contains(v, "filter add") {
			if strings.Contains(v, "parent 7a00:") {
				egress = append(egress, c)
			} else {
				ingress = append(ingress, c)
			}
		}
	}
	for _, set := range [][]Command{egress, ingress} {
		joined := ""
		for _, c := range set {
			joined += strings.Join(c.Args, " ") + "\n"
		}
		for _, key := range []string{"src_port 22", "dst_port 22", "dst_port 2222", "169.254.0.0/16", "fe80::/10", "10.20.0.0/16", "ip_proto icmpv6 type 135"} {
			if !strings.Contains(joined, key) {
				t.Errorf("missing bypass: %s", key)
			}
		}
		if !strings.Contains(strings.Join(set[len(set)-1].Args, " "), "192.0.2.2/32") {
			t.Fatal("target selector must be after protections")
		}
	}
	if !strings.Contains(strings.Join(ingress[len(ingress)-1].Args, " "), "action mirred egress redirect dev im0123456701") {
		t.Fatal("missing IFB redirect")
	}
	if !strings.Contains(strings.Join(egress[len(egress)-1].Args, " "), "classid 7a00:3") {
		t.Fatal("target not assigned to impairment band")
	}
}
func TestIPv6Selection(t *testing.T) {
	p := sample(t)
	p.Rules = p.Rules[:1]
	p.Rules[0].Match = Match{Destination: "2001:db8::2", Protocol: "udp", DestinationPort: 443}
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	plan := Build(p, "0123456789abcdef")
	last := strings.Join(plan.Commands[len(plan.Commands)-1].Args, " ")
	if !strings.Contains(last, "protocol ipv6") || !strings.Contains(last, "dst_ip 2001:db8::2/128") {
		t.Fatal(last)
	}
}
func TestGatewayScope(t *testing.T) {
	p := sample(t)
	p.Gateway = &Gateway{Inside: "ens6", Outside: "ens5", ClientCIDR: "10.0.1.0/24", Masquerade: true, Publish: []PortForward{{Protocol: "tcp", ListenPort: 8443, Target: "10.0.1.10", TargetPort: 443}}}
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	rules := gatewayRules(*p.Gateway, "impair_test")
	for _, s := range []string{`iifname "ens6" oifname "ens5" ip saddr 10.0.1.0/24 counter masquerade`, `fib daddr type local tcp dport 8443 counter dnat to 10.0.1.10:443`} {
		if !strings.Contains(rules, s) {
			t.Fatal(rules)
		}
	}
	if strings.Contains(rules, "flush") {
		t.Fatal("global flush")
	}
	p.Gateway.Publish[0].ListenPort = 22
	if p.Validate() == nil {
		t.Fatal("allowed publishing SSH")
	}
	p.Gateway.Publish[0].ListenPort = 8443
	p.Gateway.Publish[0].Target = "10.9.0.1"
	if p.Validate() == nil {
		t.Fatal("accepted target outside client subnet")
	}
}

// A deterministic kernel model exercises lifecycle behavior, not packet fidelity.
type fakeKernel struct {
	links     map[string]Link
	q         map[string][]Qdisc
	tables    map[string]bool
	mutations int
	failAt    int
	calls     []Command
	timer     bool
}

func kernel() *fakeKernel {
	k := &fakeKernel{links: map[string]Link{"ens5": {Index: 2, Name: "ens5"}, "ens6": {Index: 3, Name: "ens6"}}, q: map[string][]Qdisc{}, tables: map[string]bool{}}
	k.q["ens5"] = []Qdisc{{Kind: "mq", Handle: "0:", Root: true}}
	return k
}
func arg(a []string, key string) string {
	for i, s := range a {
		if s == key && i+1 < len(a) {
			return a[i+1]
		}
	}
	return ""
}
func contains(a []string, key string) bool {
	for _, s := range a {
		if s == key {
			return true
		}
	}
	return false
}
func data(v any) ([]byte, error) { return json.Marshal(v) }
func (k *fakeKernel) Run(c Command) ([]byte, error) {
	k.calls = append(k.calls, c)
	a := c.Args
	if a[0] == "ip" && contains(a, "-j") {
		ls := []Link{}
		for _, l := range k.links {
			ls = append(ls, l)
		}
		return data(ls)
	}
	if a[0] == "tc" && contains(a, "show") {
		if contains(a, "filter") {
			return []byte("[]"), nil
		}
		return data(k.q[arg(a, "dev")])
	}
	if a[0] == "nft" && contains(a, "list") {
		v := []any{}
		for name := range k.tables {
			v = append(v, map[string]any{"table": map[string]string{"family": "ip", "name": name}})
		}
		return data(map[string]any{"nftables": v})
	}
	if a[0] == "nft" && contains(a, "--check") {
		return nil, nil
	}
	if a[0] == "systemctl" {
		if contains(a, "stop") {
			k.timer = false
			return nil, nil
		}
		return []byte("252\n"), nil
	}
	k.mutations++
	if k.failAt == k.mutations {
		return nil, fmt.Errorf("injected command failure %d", k.failAt)
	}
	if a[0] == "systemd-run" {
		k.timer = true
		return nil, nil
	}
	if a[0] == "ip" {
		if contains(a, "add") {
			l := Link{Name: arg(a, "name"), Index: 100 + len(k.links), Alias: arg(a, "alias")}
			l.Info.Kind = "ifb"
			k.links[l.Name] = l
			k.q[l.Name] = []Qdisc{{Kind: "noqueue", Handle: "0:", Root: true}}
		}
		if contains(a, "delete") {
			delete(k.links, arg(a, "dev"))
			delete(k.q, arg(a, "dev"))
		}
		return nil, nil
	}
	if a[0] == "tc" && a[1] == "qdisc" {
		dev := arg(a, "dev")
		qs := k.q[dev]
		if a[2] == "del" {
			next := []Qdisc{}
			for _, q := range qs {
				if contains(a, "ingress") {
					if q.Kind != "ingress" {
						next = append(next, q)
					}
				} else {
					if q.Kind == "ingress" {
						next = append(next, q)
					}
				}
			}
			if contains(a, "root") {
				next = append(next, Qdisc{Kind: "mq", Handle: "0:", Root: true})
			}
			k.q[dev] = next
			return nil, nil
		}
		q := Qdisc{Handle: arg(a, "handle"), Root: contains(a, "root"), Parent: arg(a, "parent")}
		for _, kind := range []string{"prio", "netem", "ingress"} {
			if contains(a, kind) {
				q.Kind = kind
			}
		}
		if q.Root {
			next := []Qdisc{}
			for _, old := range qs {
				if !old.Root {
					next = append(next, old)
				}
			}
			qs = next
		}
		k.q[dev] = append(qs, q)
	}
	if a[0] == "nft" {
		if contains(a, "delete") {
			delete(k.tables, a[len(a)-1])
		} else {
			fields := strings.Fields(c.Input)
			k.tables[fields[2]] = true
		}
	}
	return nil, nil
}
func openTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := OpenStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
func TestLifecycle(t *testing.T) {
	s := openTestStore(t)
	k := kernel()
	p := sample(t)
	state, e := Apply(s, k, p, ApplyOptions{NoWatchdog: true})
	if e != nil {
		t.Fatal(e)
	}
	if state.Phase != "active" || len(k.links) != 3 {
		t.Fatalf("unexpected state: %+v", state)
	}
	if _, e = Apply(s, k, p, ApplyOptions{NoWatchdog: true}); e == nil {
		t.Fatal("second apply should refuse")
	}
	if e = Stop(s, k, "wrong-token"); e != nil {
		t.Fatal(e)
	}
	if len(k.links) != 3 {
		t.Fatal("stale expiry removed active experiment")
	}
	if e = Stop(s, k, state.ID); e != nil {
		t.Fatal(e)
	}
	if len(k.links) != 2 {
		t.Fatal("IFB leaked")
	}
	if e = Stop(s, k, ""); e != nil {
		t.Fatal("cleanup not idempotent", e)
	}
	if got, _ := s.Read(); got != nil {
		t.Fatal("journal not cleared")
	}
	if len(k.q["ens5"]) != 1 || k.q["ens5"][0].Handle != "0:" {
		t.Fatalf("qdiscs leaked: %+v", k.q)
	}
}
func TestRollbackEveryApplyCommand(t *testing.T) {
	p := sample(t)
	count := len(Build(p, "0123456789abcdef").Commands)
	for n := 1; n <= count; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s := openTestStore(t)
			k := kernel()
			k.failAt = n
			if _, e := Apply(s, k, p, ApplyOptions{NoWatchdog: true}); e == nil {
				t.Fatal("failure not propagated")
			}
			if state, _ := s.Read(); state != nil {
				t.Fatalf("rollback left state: %+v", state)
			}
			if len(k.links) != 2 {
				t.Fatal("IFB leaked")
			}
			if len(k.q["ens5"]) != 1 || k.q["ens5"][0].Handle != "0:" {
				t.Fatalf("qdiscs leaked at command %d: %+v", n, k.q)
			}
		})
	}
}
func TestConflictRefusedBeforeMutation(t *testing.T) {
	for _, q := range []Qdisc{{Kind: "htb", Handle: "1:", Root: true}, {Kind: "clsact", Handle: "ffff:"}, {Kind: "netem", Handle: "7a00:", Root: true}} {
		t.Run(q.Kind, func(t *testing.T) {
			s := openTestStore(t)
			k := kernel()
			k.q["ens5"] = append(k.q["ens5"], q)
			if _, e := Apply(s, k, sample(t), ApplyOptions{NoWatchdog: true}); e == nil {
				t.Fatal("accepted conflict")
			}
			if k.mutations != 0 {
				t.Fatal("mutated before rejecting conflict")
			}
		})
	}
}
func TestChangedOwnershipPreserved(t *testing.T) {
	for _, kind := range []string{"ifindex", "qdisc", "ifb-alias"} {
		t.Run(kind, func(t *testing.T) {
			s := openTestStore(t)
			k := kernel()
			state, e := Apply(s, k, sample(t), ApplyOptions{NoWatchdog: true})
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "ifindex":
				l := k.links["ens5"]
				l.Index = 999
				k.links["ens5"] = l
			case "qdisc":
				for i := range k.q["ens5"] {
					if k.q["ens5"][i].Kind == "ingress" {
						k.q["ens5"][i].Kind = "clsact"
					}
				}
			case "ifb-alias":
				for name, l := range k.links {
					if l.Info.Kind == "ifb" {
						l.Alias = "someone-else"
						k.links[name] = l
					}
				}
			}
			if e = Stop(s, k, state.ID); e == nil {
				t.Fatal("deleted changed ownership")
			}
			if st, _ := s.Read(); st == nil || st.Phase != "cleanup-needed" {
				t.Fatal("lost recovery state")
			}
		})
	}
}
func TestStopFailureCanRetry(t *testing.T) {
	s := openTestStore(t)
	k := kernel()
	_, e := Apply(s, k, sample(t), ApplyOptions{NoWatchdog: true})
	if e != nil {
		t.Fatal(e)
	}
	k.failAt = k.mutations + 1
	if e = Stop(s, k, ""); e == nil {
		t.Fatal("ignored deletion failure")
	}
	k.failAt = 0
	if e = Stop(s, k, ""); e != nil {
		t.Fatal(e)
	}
}
func TestStoreRoundTripAndSymlink(t *testing.T) {
	s := openTestStore(t)
	v := &State{Version: 1, ID: "0123456789abcdef", Phase: "applying", Created: time.Now().UTC()}
	if e := s.Save(v); e != nil {
		t.Fatal(e)
	}
	got, e := s.Read()
	if e != nil || !reflect.DeepEqual(v, got) {
		t.Fatalf("roundtrip %v", e)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if e = os.Symlink(s.Dir, link); e != nil {
		t.Fatal(e)
	}
	if x, e := OpenStore(link); e == nil {
		x.Close()
		t.Fatal("accepted symlink")
	}
}
func TestNamespaceGuard(t *testing.T) {
	s := openTestStore(t)
	k := kernel()
	state, e := Apply(s, k, sample(t), ApplyOptions{NoWatchdog: true})
	if e != nil {
		t.Fatal(e)
	}
	state.Namespace = "net:[different]"
	if e = s.Save(state); e != nil {
		t.Fatal(e)
	}
	before := k.mutations
	if e = Stop(s, k, ""); e == nil {
		t.Fatal("accepted namespace mismatch")
	}
	if k.mutations != before {
		t.Fatal("mutated wrong namespace")
	}
}
func TestUnsafeExecutableRejected(t *testing.T) {
	if _, e := Tool("sh"); e == nil {
		t.Fatal("shell allowed")
	}
	if _, e := Tool("/tmp/tc"); e == nil {
		t.Fatal("arbitrary executable allowed")
	}
}

func TestGatewayPreflightAndScopedCleanup(t *testing.T) {
	s := openTestStore(t)
	k := kernel()
	k.tables["existing_firewall"] = true
	p := Profile{Version: 1, Name: "gateway only", Gateway: &Gateway{Inside: "ens6", Outside: "ens5", ClientCIDR: "10.0.1.0/24", Masquerade: true}}
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	plan := Build(p, "0123456789abcdef")
	indices, e := Preflight(k, p, plan)
	if e != nil {
		t.Fatal(e)
	}
	if k.mutations != 0 {
		t.Fatal("preflight mutated the host")
	}
	for _, c := range plan.Commands {
		if _, e = k.Run(c); e != nil {
			t.Fatal(e)
		}
	}
	ns, e := namespace()
	if e != nil {
		t.Fatal(e)
	}
	state := &State{Version: 1, ID: "0123456789abcdef", Namespace: ns, Profile: p, Plan: plan, Interfaces: indices}
	if e = s.Save(state); e != nil {
		t.Fatal(e)
	}
	if e = Stop(s, k, ""); e != nil {
		t.Fatal(e)
	}
	if len(k.tables) != 1 || !k.tables["existing_firewall"] {
		t.Fatal("cleanup removed an unrelated table or leaked its own", k.tables)
	}
}
