// SPDX-License-Identifier: GPL-3.0-only
package impair

import (
	"fmt"
	"strconv"
	"strings"
)

const rootHandle = "7a00:"
const netemHandle = "7a10:"

type Command struct {
	Args  []string `json:"argv"`
	Input string   `json:"stdin,omitempty"`
}
type Resource struct {
	Kind   string `json:"kind"`
	Device string `json:"device,omitempty"`
	Handle string `json:"handle,omitempty"`
	Qdisc  string `json:"qdisc,omitempty"`
	Name   string `json:"name,omitempty"`
	Alias  string `json:"alias,omitempty"`
}
type Plan struct {
	Commands        []Command        `json:"commands"`
	Resources       []Resource       `json:"resources"`
	TransportChecks []TransportCheck `json:"transport_checks,omitempty"`
}

// These are checked prerequisites, never resources owned or restored by impair.
type TransportCheck struct {
	Device             string `json:"device"`
	BlackMTU           int    `json:"black_mtu"`
	InnerMTU           int    `json:"required_interface_mtu"`
	OverheadBytes      int    `json:"overhead_bytes"`
	NetemOverheadBytes int    `json:"netem_overhead_bytes"`
}

func (p *Plan) add(args ...string)  { p.Commands = append(p.Commands, Command{Args: args}) }
func (p *Plan) resource(r Resource) { p.Resources = append(p.Resources, r) }

func Build(p Profile, id string) Plan {
	var plan Plan
	for i, r := range p.Rules {
		if t := r.IPv4Transport; t != nil {
			plan.TransportChecks = append(plan.TransportChecks, TransportCheck{Device: r.Interface, BlackMTU: t.BlackMTU, InnerMTU: t.InnerMTU(), OverheadBytes: t.OverheadBytes, NetemOverheadBytes: t.NetemOverhead()})
		}
		if r.Direction == "egress" {
			plan.resource(Resource{Kind: "root", Device: r.Interface, Handle: rootHandle, Qdisc: "prio"})
			plan.add("tc", "qdisc", "add", "dev", r.Interface, "root", "handle", rootHandle, "prio", "bands", "3", "priomap", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0")
			args := []string{"tc", "qdisc", "replace", "dev", r.Interface, "parent", "7a00:3", "handle", netemHandle}
			plan.add(append(args, r.netemArgs()...)...)
			addFilters(&plan, p, r, rootHandle, "")
		} else {
			name := fmt.Sprintf("im%s%02d", id[:8], i)
			alias := "impair:" + id
			plan.resource(Resource{Kind: "ifb", Device: name, Alias: alias})
			plan.add("ip", "link", "add", "name", name, "alias", alias, "type", "ifb")
			plan.add("ip", "link", "set", "dev", name, "up")
			// The IFB is entirely owned; deleting it also removes its root qdisc.
			args := []string{"tc", "qdisc", "add", "dev", name, "root", "handle", netemHandle}
			plan.add(append(args, r.netemArgs()...)...)
			plan.resource(Resource{Kind: "ingress", Device: r.Interface, Handle: "ffff:", Qdisc: "ingress"})
			plan.add("tc", "qdisc", "add", "dev", r.Interface, "handle", "ffff:", "ingress")
			addFilters(&plan, p, r, "ffff:", name)
		}
	}
	if p.Gateway != nil {
		table := "impair_" + id
		plan.resource(Resource{Kind: "nft", Name: table})
		plan.Commands = append(plan.Commands, Command{Args: []string{"nft", "-f", "-"}, Input: gatewayRules(*p.Gateway, table)})
	}
	return plan
}

func addFilters(plan *Plan, p Profile, r Rule, parent, ifb string) {
	pref := 10
	filter := func(family string, match []string, bypass bool) {
		a := []string{"tc", "filter", "add", "dev", r.Interface, "parent", parent, "protocol", family, "pref", strconv.Itoa(pref), "flower", "skip_hw"}
		pref++
		a = append(a, match...)
		if ifb != "" {
			if bypass {
				a = append(a, "action", "pass")
			} else {
				a = append(a, "action", "mirred", "egress", "redirect", "dev", ifb)
			}
		} else {
			class := "7a00:3"
			if bypass {
				class = "7a00:1"
			}
			a = append(a, "classid", class)
		}
		plan.add(a...)
	}
	// Legacy profiles retain automatic bypasses. Separate management selects only
	// forwarded traffic by incoming interface, without transit port exceptions.
	if p.ManagementPolicy != "separate" {
		for _, family := range []string{"ip", "ipv6"} {
			for _, port := range p.protectedSSHPorts() {
				for _, side := range []string{"src_port", "dst_port"} {
					filter(family, []string{"ip_proto", "tcp", side, strconv.Itoa(port)}, true)
				}
			}
			ports := []int{67, 68}
			if family == "ipv6" {
				ports = []int{546, 547}
			}
			for _, port := range ports {
				for _, side := range []string{"src_port", "dst_port"} {
					filter(family, []string{"ip_proto", "udp", side, strconv.Itoa(port)}, true)
				}
			}
		}
		networks := append([]string{"169.254.0.0/16", "fe80::/10", "ff02::/16"}, p.Protect...)
		for _, s := range networks {
			n, _ := prefix(s)
			f := "ipv6"
			if n.Addr().Is4() {
				f = "ip"
			}
			for _, side := range []string{"src_ip", "dst_ip"} {
				filter(f, []string{side, n.String()}, true)
			}
		}
		for _, t := range []string{"133", "134", "135", "136", "137"} {
			filter("ipv6", []string{"ip_proto", "icmpv6", "type", t}, true)
		}
	}
	m := r.Match
	families := []string{"ip", "ipv6"}
	if m.Family == "ipv4" {
		families = []string{"ip"}
	}
	if m.Family == "ipv6" {
		families = []string{"ipv6"}
	}
	for _, family := range families {
		args := []string{}
		if m.Source != "" {
			n, _ := prefix(m.Source)
			args = append(args, "src_ip", n.String())
		}
		if m.Destination != "" {
			n, _ := prefix(m.Destination)
			args = append(args, "dst_ip", n.String())
		}
		if m.Protocol != "" {
			args = append(args, "ip_proto", m.Protocol)
		}
		if m.SourcePort != 0 {
			args = append(args, "src_port", strconv.Itoa(m.SourcePort))
		}
		if m.DestinationPort != 0 {
			args = append(args, "dst_port", strconv.Itoa(m.DestinationPort))
		}
		if m.InputInterface != "" {
			args = append(args, "indev", m.InputInterface)
		}
		filter(family, args, false)
	}
}

func gatewayRules(g Gateway, name string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table ip %s {\n", name)
	fmt.Fprintf(&b, "  chain forward {\n    type filter hook forward priority 0; policy accept;\n    iifname %q oifname %q ip saddr %s counter accept\n    iifname %q oifname %q ip daddr %s ct state established,related counter accept\n", g.Inside, g.Outside, g.ClientCIDR, g.Outside, g.Inside, g.ClientCIDR)
	for _, f := range g.Publish {
		fmt.Fprintf(&b, "    iifname %q oifname %q ip daddr %s %s dport %d ct status dnat counter accept\n", g.Outside, g.Inside, f.Target, f.Protocol, f.TargetPort)
	}
	b.WriteString("  }\n  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, f := range g.Publish {
		fmt.Fprintf(&b, "    iifname %q fib daddr type local %s dport %d counter dnat to %s:%d\n", g.Outside, f.Protocol, f.ListenPort, f.Target, f.TargetPort)
	}
	b.WriteString("  }\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	if g.Masquerade {
		fmt.Fprintf(&b, "    iifname %q oifname %q ip saddr %s counter masquerade\n", g.Inside, g.Outside, g.ClientCIDR)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func (c Command) String() string {
	a := make([]string, len(c.Args))
	for i, s := range c.Args {
		a[i] = "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
	}
	s := strings.Join(a, " ")
	if c.Input != "" {
		s += " <<'IMPAIR_NFT'\n" + c.Input + "IMPAIR_NFT"
	}
	return s
}
