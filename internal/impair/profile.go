// SPDX-License-Identifier: GPL-3.0-only
package impair

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"time"
)

const Version = "1.0.0"

type Profile struct {
	Version          int      `json:"version"`
	Name             string   `json:"name"`
	Rules            []Rule   `json:"rules"`
	Protect          []string `json:"protect,omitempty"`
	SSHPorts         []int    `json:"ssh_ports,omitempty"`
	Gateway          *Gateway `json:"gateway,omitempty"`
	ManagementPolicy string   `json:"management_policy,omitempty"`
}
type Rule struct {
	Interface     string         `json:"interface"`
	Direction     string         `json:"direction"`
	Match         Match          `json:"match"`
	Impairment    Impairment     `json:"impairment"`
	Component     string         `json:"component,omitempty"`
	IPv4Transport *IPv4Transport `json:"ipv4_transport,omitempty"`
}

// IPv4Transport is a fixed size envelope, not an encapsulation backend.
// The egress interface is provisioned externally with MTU = BlackMTU - OverheadBytes.
type IPv4Transport struct {
	BlackMTU      int `json:"black_mtu"`
	OverheadBytes int `json:"overhead_bytes"`
}

func (t IPv4Transport) InnerMTU() int { return t.BlackMTU - t.OverheadBytes }

// Untagged Ethernet egress already includes 14 bytes outside the inner IP packet.
// Subtract those bytes so rate accounts for inner IP length + envelope overhead.
func (t IPv4Transport) NetemOverhead() int { return t.OverheadBytes - 14 }

func (p Profile) protectedSSHPorts() []int {
	if p.ManagementPolicy == "separate" {
		return nil
	}
	return append([]int{22}, p.SSHPorts...)
}

type Match struct {
	Family          string `json:"family,omitempty"`
	Source          string `json:"source,omitempty"`
	Destination     string `json:"destination,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	InputInterface  string `json:"input_interface,omitempty"`
}
type Impairment struct {
	Delay        string  `json:"delay,omitempty"`
	Jitter       string  `json:"jitter,omitempty"`
	Correlation  float64 `json:"correlation_percent,omitempty"`
	Distribution string  `json:"distribution,omitempty"`
	Loss         float64 `json:"loss_percent,omitempty"`
	Duplicate    float64 `json:"duplicate_percent,omitempty"`
	Corrupt      float64 `json:"corrupt_percent,omitempty"`
	Reorder      float64 `json:"reorder_percent,omitempty"`
	Rate         string  `json:"rate,omitempty"`
	Limit        int     `json:"queue_packets,omitempty"`
	Seed         *uint32 `json:"seed,omitempty"`
}
type Gateway struct {
	Inside     string        `json:"inside"`
	Outside    string        `json:"outside"`
	ClientCIDR string        `json:"client_cidr"`
	Masquerade bool          `json:"masquerade,omitempty"`
	Publish    []PortForward `json:"publish,omitempty"`
}
type PortForward struct {
	Protocol   string `json:"protocol"`
	ListenPort int    `json:"listen_port"`
	Target     string `json:"target"`
	TargetPort int    `json:"target_port"`
}

var ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
var ratePattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)(bit|kbit|mbit|gbit)$`)

func Load(path string) (Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return Profile{}, err
	}
	defer f.Close()
	return Decode(f)
}
func Decode(r io.Reader) (Profile, error) {
	var p Profile
	d := json.NewDecoder(io.LimitReader(r, 1024*1024+1))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return p, fmt.Errorf("profile must contain exactly one JSON object")
	}
	return p, p.Validate()
}
func validPort(p int) bool { return p >= 1 && p <= 65535 }
func duration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 || d > time.Hour {
		return 0, fmt.Errorf("invalid duration %q: use 0..1h with units such as 50ms", s)
	}
	return d, nil
}
func prefix(s string) (netip.Prefix, error) {
	if p, e := netip.ParsePrefix(s); e == nil && !p.Addr().Is4In6() {
		return p.Masked(), nil
	}
	if a, e := netip.ParseAddr(s); e == nil && a.Zone() == "" && !a.Is4In6() {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("invalid IP address or CIDR %q", s)
}
func (p *Profile) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("profile version must be 1")
	}
	if len(p.Name) == 0 || len(p.Name) > 100 {
		return fmt.Errorf("name must contain 1..100 characters")
	}
	if len(p.Rules) == 0 && p.Gateway == nil {
		return fmt.Errorf("provide rules or gateway")
	}
	if len(p.Rules) > 32 || len(p.Protect) > 64 || len(p.SSHPorts) > 32 {
		return fmt.Errorf("too many rules, protected networks, or SSH ports")
	}
	switch p.ManagementPolicy {
	case "", "automatic":
	case "separate":
		if len(p.Protect) != 0 || len(p.SSHPorts) != 0 {
			return fmt.Errorf("separate management requires an independent management path, without protect or ssh_ports bypasses")
		}
	default:
		return fmt.Errorf("management_policy must be automatic or separate")
	}
	for _, port := range p.SSHPorts {
		if !validPort(port) {
			return fmt.Errorf("invalid SSH port %d", port)
		}
	}
	for _, s := range p.Protect {
		if _, e := prefix(s); e != nil {
			return e
		}
	}
	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if !ifacePattern.MatchString(r.Interface) {
			return fmt.Errorf("rule %d: invalid interface", i)
		}
		if r.Direction != "egress" && r.Direction != "ingress" {
			return fmt.Errorf("rule %d: direction must be egress or ingress", i)
		}
		key := r.Interface + "/" + r.Direction
		if seen[key] {
			return fmt.Errorf("only one rule per interface/direction: %s", key)
		}
		seen[key] = true
		if err := r.Match.validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		if r.Direction == "ingress" && r.Match.InputInterface != "" {
			return fmt.Errorf("input_interface is only valid on egress rules")
		}
		if p.ManagementPolicy == "separate" && (r.Direction != "egress" || r.Match.InputInterface == "" || r.Match.InputInterface == r.Interface) {
			return fmt.Errorf("rule %d: separate management requires egress transit selection from a different input_interface", i)
		}
		switch r.Component {
		case "", "encryptor_a", "black_transport", "encryptor_b":
		default:
			return fmt.Errorf("rule %d: unknown component", i)
		}
		if t := r.IPv4Transport; t != nil {
			if r.Component != "black_transport" || p.ManagementPolicy != "separate" || r.Match.Family != "ipv4" {
				return fmt.Errorf("rule %d: ipv4_transport requires component black_transport, separate management, and IPv4 selection", i)
			}
			if t.BlackMTU < 68 || t.BlackMTU > 65535 || t.OverheadBytes < 0 || t.OverheadBytes > t.BlackMTU-68 {
				return fmt.Errorf("rule %d: black_mtu must be 68..65535 and overhead_bytes must leave an inner MTU of at least 68", i)
			}
			if r.Impairment.Rate == "" {
				return fmt.Errorf("rule %d: ipv4_transport requires an explicit rate in modeled outer IP bits/s", i)
			}
		}
		if err := r.Impairment.validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	if p.Gateway != nil {
		g := p.Gateway
		if !ifacePattern.MatchString(g.Inside) || !ifacePattern.MatchString(g.Outside) || g.Inside == g.Outside {
			return fmt.Errorf("gateway requires two different valid interfaces")
		}
		n, e := netip.ParsePrefix(g.ClientCIDR)
		if e != nil || !n.Addr().Is4() || n.Bits() == 0 || n.Masked() != n {
			return fmt.Errorf("gateway client_cidr must be a canonical, non-default IPv4 subnet")
		}
		if len(g.Publish) > 64 {
			return fmt.Errorf("too many published ports")
		}
		ports := map[string]bool{}
		for _, f := range g.Publish {
			a, e := netip.ParseAddr(f.Target)
			if e != nil || !a.Is4() || !n.Contains(a) || a.IsUnspecified() || a.IsMulticast() {
				return fmt.Errorf("published target must be an IPv4 address inside client_cidr")
			}
			if (f.Protocol != "tcp" && f.Protocol != "udp") || !validPort(f.ListenPort) || !validPort(f.TargetPort) {
				return fmt.Errorf("invalid published protocol or port")
			}
			if f.Protocol == "tcp" {
				for _, sp := range p.protectedSSHPorts() {
					if f.ListenPort == sp {
						return fmt.Errorf("cannot publish protected SSH port %d", sp)
					}
				}
			}
			key := f.Protocol + strconv.Itoa(f.ListenPort)
			if ports[key] {
				return fmt.Errorf("duplicate published port")
			}
			ports[key] = true
		}
	}
	return nil
}
func (m *Match) validate() error {
	if m.Family == "" {
		m.Family = "any"
	}
	if m.Family != "any" && m.Family != "ipv4" && m.Family != "ipv6" {
		return fmt.Errorf("family must be any, ipv4, or ipv6")
	}
	for _, s := range []string{m.Source, m.Destination} {
		if s == "" {
			continue
		}
		n, e := prefix(s)
		if e != nil {
			return e
		}
		f := "ipv6"
		if n.Addr().Is4() {
			f = "ipv4"
		}
		if m.Family == "any" {
			m.Family = f
		}
		if m.Family != f {
			return fmt.Errorf("address families must match")
		}
	}
	switch m.Protocol {
	case "", "tcp", "udp", "icmp", "icmpv6":
	default:
		return fmt.Errorf("protocol must be tcp, udp, icmp, or icmpv6")
	}
	if m.Protocol == "icmp" {
		if m.Family == "ipv6" {
			return fmt.Errorf("icmp requires IPv4")
		}
		m.Family = "ipv4"
	}
	if m.Protocol == "icmpv6" {
		if m.Family == "ipv4" {
			return fmt.Errorf("icmpv6 requires IPv6")
		}
		m.Family = "ipv6"
	}
	if m.SourcePort != 0 || m.DestinationPort != 0 {
		if m.Protocol != "tcp" && m.Protocol != "udp" {
			return fmt.Errorf("port selection requires tcp or udp")
		}
		if (m.SourcePort != 0 && !validPort(m.SourcePort)) || (m.DestinationPort != 0 && !validPort(m.DestinationPort)) {
			return fmt.Errorf("invalid port")
		}
	}
	if m.InputInterface != "" && !ifacePattern.MatchString(m.InputInterface) {
		return fmt.Errorf("invalid input_interface")
	}
	return nil
}
func (n *Impairment) validate() error {
	d, e := duration(n.Delay)
	if e != nil {
		return e
	}
	j, e := duration(n.Jitter)
	if e != nil {
		return e
	}
	if j > 0 && d == 0 {
		return fmt.Errorf("jitter requires positive delay")
	}
	if n.Correlation != 0 && j == 0 {
		return fmt.Errorf("correlation requires jitter")
	}
	for _, p := range []float64{n.Loss, n.Duplicate, n.Corrupt, n.Reorder, n.Correlation} {
		if math.IsNaN(p) || math.IsInf(p, 0) || p < 0 || p > 100 {
			return fmt.Errorf("percentages must be finite values in 0..100")
		}
	}
	if n.Reorder > 0 && d == 0 {
		return fmt.Errorf("reordering requires delay")
	}
	switch n.Distribution {
	case "", "uniform", "normal", "pareto", "paretonormal":
	default:
		return fmt.Errorf("unknown delay distribution")
	}
	if n.Distribution != "" && j == 0 {
		return fmt.Errorf("distribution requires jitter")
	}
	if n.Rate != "" {
		m := ratePattern.FindStringSubmatch(n.Rate)
		if m == nil {
			return fmt.Errorf("rate requires bit/kbit/mbit/gbit units, e.g. 10mbit")
		}
		value, e := strconv.ParseFloat(m[1], 64)
		mult := map[string]float64{"bit": 1, "kbit": 1e3, "mbit": 1e6, "gbit": 1e9}[m[2]]
		if e != nil || value*mult < 1 || value*mult > 1e12 {
			return fmt.Errorf("rate must be between 1 bit/s and 1 Tbit/s")
		}
	}
	if n.Limit == 0 {
		n.Limit = 10000
	}
	if n.Limit < 1 || n.Limit > 10000000 {
		return fmt.Errorf("queue_packets must be 1..10000000")
	}
	if d == 0 && n.Loss == 0 && n.Duplicate == 0 && n.Corrupt == 0 && n.Reorder == 0 && n.Rate == "" {
		return fmt.Errorf("rule must specify at least one impairment")
	}
	return nil
}
func (n Impairment) Args() []string {
	return n.args(nil)
}

func (r Rule) netemArgs() []string {
	if r.IPv4Transport != nil {
		overhead := r.IPv4Transport.NetemOverhead()
		return r.Impairment.args(&overhead)
	}
	return r.Impairment.Args()
}

func (n Impairment) args(overhead *int) []string {
	a := []string{"netem", "limit", strconv.Itoa(n.Limit)}
	d, _ := duration(n.Delay)
	j, _ := duration(n.Jitter)
	ms := func(d time.Duration) string {
		return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', 6, 64) + "ms"
	}
	pct := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) + "%" }
	if d > 0 {
		a = append(a, "delay", ms(d))
		if j > 0 {
			a = append(a, ms(j))
			if n.Correlation > 0 {
				a = append(a, pct(n.Correlation))
			}
			if n.Distribution != "" && n.Distribution != "uniform" {
				a = append(a, "distribution", n.Distribution)
			}
		}
	}
	for _, v := range []struct {
		k string
		v float64
	}{{"loss", n.Loss}, {"duplicate", n.Duplicate}, {"corrupt", n.Corrupt}, {"reorder", n.Reorder}} {
		if v.v > 0 {
			a = append(a, v.k, pct(v.v))
		}
	}
	if n.Rate != "" {
		a = append(a, "rate", n.Rate)
		if overhead != nil {
			a = append(a, strconv.Itoa(*overhead))
		}
	}
	if n.Seed != nil {
		a = append(a, "seed", strconv.FormatUint(uint64(*n.Seed), 10))
	}
	return a
}
