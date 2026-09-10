// SPDX-License-Identifier: GPL-3.0-only
package impair

import (
	"strings"
	"testing"
)

func transportProfile() Profile {
	return Profile{Version: 1, Name: "Synthetic BLACK transport", ManagementPolicy: "separate", Rules: []Rule{{
		Interface: "ens5", Direction: "egress", Component: "black_transport",
		Match:         Match{Family: "ipv4", InputInterface: "ens6"},
		Impairment:    Impairment{Rate: "4mbit"},
		IPv4Transport: &IPv4Transport{BlackMTU: 1500, OverheadBytes: 64},
	}}}
}

func TestTransportValidation(t *testing.T) {
	cases := map[string]func(*Profile){
		"unknown management":  func(p *Profile) { p.ManagementPolicy = "none" },
		"automatic bypass":    func(p *Profile) { p.ManagementPolicy = "automatic" },
		"protected ports":     func(p *Profile) { p.SSHPorts = []int{22} },
		"protected subnet":    func(p *Profile) { p.Protect = []string{"10.0.0.0/24"} },
		"ingress":             func(p *Profile) { p.Rules[0].Direction = "ingress" },
		"local traffic":       func(p *Profile) { p.Rules[0].Match.InputInterface = "" },
		"same interface":      func(p *Profile) { p.Rules[0].Match.InputInterface = "ens5" },
		"IPv6":                func(p *Profile) { p.Rules[0].Match.Family = "ipv6" },
		"unspecified family":  func(p *Profile) { p.Rules[0].Match.Family = "" },
		"wrong component":     func(p *Profile) { p.Rules[0].Component = "encryptor_a" },
		"unknown component":   func(p *Profile) { p.Rules[0].Component = "a" },
		"no rate":             func(p *Profile) { p.Rules[0].Impairment = Impairment{Delay: "1ms"} },
		"missing MTU":         func(p *Profile) { p.Rules[0].IPv4Transport.BlackMTU = 0 },
		"MTU too large":       func(p *Profile) { p.Rules[0].IPv4Transport.BlackMTU = 65536 },
		"negative overhead":   func(p *Profile) { p.Rules[0].IPv4Transport.OverheadBytes = -1 },
		"inner MTU too small": func(p *Profile) { p.Rules[0].IPv4Transport.OverheadBytes = 1433 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := transportProfile()
			mutate(&p)
			if p.Validate() == nil {
				t.Fatal("accepted unsupported model")
			}
		})
	}
	for _, overhead := range []int{0, 14, 64, 1432} {
		p := transportProfile()
		p.Rules[0].IPv4Transport.OverheadBytes = overhead
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTransportPlanAndManagement(t *testing.T) {
	p := transportProfile()
	seed := uint32(9)
	p.Rules[0].Impairment.Seed = &seed
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	plan := Build(p, "0123456789abcdef")
	if len(plan.TransportChecks) != 1 || plan.TransportChecks[0].InnerMTU != 1436 || plan.TransportChecks[0].NetemOverheadBytes != 50 {
		t.Fatalf("incorrect size contract: %+v", plan.TransportChecks)
	}
	var filters int
	for _, c := range plan.Commands {
		s := strings.Join(c.Args, " ")
		if strings.Contains(s, "netem") && !strings.Contains(s, "rate 4mbit 50 seed 9") {
			t.Fatalf("incorrect transport accounting: %s", s)
		}
		if strings.Contains(s, "filter add") {
			filters++
			if !strings.Contains(s, "protocol ip") || !strings.Contains(s, "indev ens6 classid 7a00:3") || strings.Contains(s, "port") {
				t.Fatalf("transit selector has an unexpected bypass: %s", s)
			}
		}
		if c.Args[0] != "tc" {
			t.Fatalf("unexpected topology mutation: %s", s)
		}
	}
	if filters != 1 {
		t.Fatalf("got %d filters", filters)
	}
	// Zero envelope still normalizes the existing Ethernet header out of accounting.
	p.Rules[0].IPv4Transport.OverheadBytes = 0
	if !strings.Contains(strings.Join(p.Rules[0].netemArgs(), " "), "rate 4mbit -14 seed 9") {
		t.Fatal("zero-overhead baseline must count IP bytes")
	}
	// Processing stages do not acquire transport overhead simply from their label.
	p.Rules[0].IPv4Transport = nil
	p.Rules[0].Component = "encryptor_b"
	if got := strings.Join(p.Rules[0].netemArgs(), " "); !strings.Contains(got, "rate 4mbit seed 9") {
		t.Fatal(got)
	}
}

func TestTransportPreflightAndRecovery(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-mtu", "missing-mtu", "non-ethernet", "vlan", "veth"} {
		t.Run(scenario, func(t *testing.T) {
			p := transportProfile()
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			k := kernel()
			l := k.links["ens5"]
			l.MTU, l.Type = 1436, "ether"
			switch scenario {
			case "wrong-mtu":
				l.MTU = 1500
			case "missing-mtu":
				l.MTU = 0
			case "non-ethernet":
				l.Type = "none"
			case "vlan":
				l.Info.Kind = "vlan"
			case "veth":
				l.Info.Kind = "veth"
			}
			k.links["ens5"] = l
			_, err := Preflight(k, p, Build(p, "0123456789abcdef"))
			valid := scenario == "valid" || scenario == "veth"
			if (err == nil) != valid {
				t.Fatalf("preflight: %v", err)
			}
			if k.mutations != 0 {
				t.Fatal("preflight mutated topology")
			}
		})
	}
	p := transportProfile()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	// Fail every apply command, then exercise successful apply/stop as well.
	for failAt := 0; failAt <= len(Build(p, "0123456789abcdef").Commands); failAt++ {
		s := openTestStore(t)
		k := kernel()
		l := k.links["ens5"]
		l.MTU, l.Type = 1436, "ether"
		k.links["ens5"] = l
		k.failAt = failAt
		_, err := Apply(s, k, p, ApplyOptions{NoWatchdog: true})
		if (err == nil) != (failAt == 0) {
			t.Fatalf("failure %d: %v", failAt, err)
		}
		if err := Stop(s, k, ""); err != nil {
			t.Fatal(err)
		}
		if k.links["ens5"].MTU != 1436 {
			t.Fatal("cleanup changed provisioned MTU")
		}
		if st, err := s.Read(); err != nil || st != nil {
			t.Fatalf("journal leaked: %+v %v", st, err)
		}
		if len(k.q["ens5"]) != 1 || k.q["ens5"][0].Handle != "0:" {
			t.Fatal("qdisc leaked")
		}
	}
}

func TestSeparateManagementPortPublishing(t *testing.T) {
	p := transportProfile()
	p.Gateway = &Gateway{Inside: "ens6", Outside: "ens5", ClientCIDR: "10.0.1.0/24", Publish: []PortForward{{Protocol: "tcp", ListenPort: 22, Target: "10.0.1.2", TargetPort: 22}}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.ManagementPolicy = "automatic"
	p.Rules[0].IPv4Transport = nil
	if p.Validate() == nil {
		t.Fatal("legacy management must still protect published port 22")
	}
}
