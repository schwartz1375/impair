# impair

A single Linux CLI application for delay, jitter, bandwidth limits, packet loss,
duplication, corruption, reordering, and optional routed-appliance NAT.

Modern successor to my 2007 NETEM utility and the `impair2`,
`forwardALLTCP`, and `stopForward` scripts. GPL-3.0-only; see [LICENSE](LICENSE).

## What is included

- One executable; `make release` produces Linux x86-64 and ARM64/Graviton builds in `dist/`.
- Separate ingress and egress rules, each with its own impairment settings.
- IPv4/IPv6 address, subnet, TCP/UDP port, protocol, and incoming-interface selectors.
- Strict JSON profiles, offline command previews, diagnostics, and live kernel counters.
- Independent systemd expiry, a durable-on-write runtime journal, serialized changes,
  rollback after command failures, and repeatable cleanup.
- Optional IPv4 forwarding rules, scoped masquerading, and explicit TCP/UDP DNAT ports.
- A synthetic IPv4 inline model with fixed envelope accounting and a checked MTU prerequisite.
- Go source without third-party Go dependencies, unit tests, and privileged packet tests.

This release is a CLI application. It has no browser interface, HTTP API, packet
capture service, AWS provisioning, or container/Kubernetes controller. Saved
profiles are ordinary JSON files. One active experiment per state directory can
contain up to 32 interface/direction rules. Use the default directory in normal
operation; different directories do not coordinate ownership of interfaces.

## Why Go instead of Rust or shell?

We chose Go for the configuration and recovery logic. Linux handles the packets
through `tc`/netem; the application validates profiles, configures kernel resources,
records ownership, and manages cleanup. The choice of Go does not make packet
impairment faster or more accurate than an equivalent Rust or shell implementation
using the same kernel configuration.

| Option | Fit for this project | Tradeoff |
|---|---|---|
| **Go** | Typed configuration, standard-library JSON and process execution, explicit error handling, and one compiled executable per target architecture. | A practical balance of deployment simplicity and maintainable lifecycle code; still depends on Linux networking tools. |
| **Rust** | Also supports a single executable, with strong compile-time memory and resource-safety guarantees. | A sound alternative. For this implementation, its additional ownership/lifetime modeling was not needed to meet the configuration and recovery requirements. |
| **Shell** | Well suited to a small, fixed lab setup like the original scripts. | Profiles, validation, locking, state journals, and partial-failure recovery are possible, but require increasingly careful quoting, error propagation, and state handling. |

Go's standard library covers the current application without third-party Go
modules. It also leaves room for a future API or local interface to share the same
profile and lifecycle logic. Rust could support that architecture equally well;
this was a maintainability and implementation choice, not a claim that Go is
inherently safer or faster.

“Single application” means one user-facing executable, not a dependency-free
network stack. It invokes installed `ip` and `tc`, optionally `nft`, and systemd
for normal automatic expiry. Commands use argument arrays rather than a shell.
Correct validation, resource ownership, and recovery behavior remain essential
regardless of implementation language.

## Target platforms

Target platforms are Ubuntu Server 24.04/26.04 LTS and Amazon Linux 2023 on x86-64
or ARM64, with their Linux kernel traffic-control features available. Compatibility
depends on the actual kernel/modules and iproute2 build, not just the OS name.
Ubuntu 26.04 is available on EC2. [Canonical release information](https://discourse.ubuntu.com/t/ubuntu-26-04-lts-resolute-raccoon-now-available-on-aws-secure-ai-ready-and-built-for-scale/80830)

## Install

Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y iproute2 nftables ethtool
```

Amazon Linux 2023:

```bash
sudo dnf install -y iproute iproute-tc nftables ethtool
```

The AL2023 package set includes `iproute-tc`.
[AWS package reference](https://docs.aws.amazon.com/linux/al2023/release-notes/all-packages.html)

Build with `make release` first, or obtain a release containing `dist/`. From the
project directory, verify and install the appropriate binary:

```bash
cd dist
sha256sum -c SHA256SUMS
cd ..

# Intel / AMD EC2 or other x86-64 Linux:
sudo install -m 0755 dist/impair-linux-amd64 /usr/local/bin/impair

# On ARM64 / AWS Graviton, use this instead:
# sudo install -m 0755 dist/impair-linux-arm64 /usr/local/bin/impair

impair version
```

Checksums detect accidental corruption; they are not a publisher signature. The
repository does not track prebuilt binaries. Build releases with your organization's
current supported Go toolchain. The source requires Go 1.22 or newer:

```bash
make test
make build
sudo install -m 0755 dist/impair /usr/local/bin/impair
```

Runtime tools are resolved only from `/usr/sbin`, `/usr/bin`, `/sbin`, and `/bin`.
Changing `PATH` will not substitute privileged executables. No shell is used to
execute network configuration commands. `nft` is only required for gateway rules;
`ethtool` is optional diagnostics. Normal apply requires a working host systemd.

### Build on macOS

You can build the application on a Mac, but execution and tests require Linux.
The Makefile explicitly targets Linux; the source's Linux build constraint is
intentional and should stay in place.

```bash
# Build both Linux architectures, with portable checksum generation:
make release

# Or build only the architecture of your Linux target:
make GOARCH=amd64   # Intel / AMD EC2; output: dist/impair
make GOARCH=arm64   # AWS Graviton; output: dist/impair
```

Plain `make` builds a Linux executable matching the Go toolchain's host
architecture. On Apple Silicon with a native Go installation this is ARM64;
choose `GOARCH=amd64` explicitly for an x86-64 EC2 target. Copy the binary to the
Linux machine and install it there. A Linux executable cannot run directly on
macOS. `make test` and `make install` report this requirement on a Mac.

If using the original Makefile, `GOOS=linux GOARCH=amd64 make` also works for a
single x86-64 build. The corrected `make release` uses `shasum -a 256` when
`sha256sum` is unavailable, as is typical on macOS.

Kernel features used: `sch_prio`, `sch_netem`, `cls_flower`, `sch_ingress`, `ifb`,
`act_mirred`, and `act_gact`, plus nftables/NAT support for gateway mode. These may
be built in or available as modules. If the AMI omits them, install its matching
kernel module package. Do not assume one distribution's module package name works
on another. Apply fails and rolls back when a required operation is unsupported.

## Quick start: impair one Linux host

Find the test interface and generate a profile:

```bash
ip -br address
impair example --mode host --interface ens5 > host.json
```

Edit `host.json`. Replace the documentation address `198.51.100.20` with the remote
test endpoint. Add your management subnet to `protect` if needed. The example
adds 50 ms delay, 10 ms jitter, 0.1% loss, and a 10 Mbit/s limit in each direction.
Ingress and egress match fields describe packets as observed in that direction:
the remote endpoint is a **destination on egress** and a **source on ingress**.
The app does not silently reverse selectors.

```bash
impair validate --profile host.json
impair plan --profile host.json
sudo impair doctor --interface ens5
sudo impair apply --profile host.json --duration 10m
sudo impair status
sudo impair stop
```

`plan` and `apply --dry-run` are offline and require no privileges. They validate
configuration and show commands; they do not prove that an interface exists or
that the host supports a feature. Preview resource IDs are placeholders.

`apply` preflights interfaces and conflicts, writes the recovery journal, arms
expiry, and then configures the kernel. Failures produce a nonzero exit status.
Repeated `apply` is refused while an experiment exists. Change a profile with
`stop`, edit/validate it, then `apply`; there is a gap between experiments. There
is no seamless hot-update command in this release.

## Profiles

Example: asymmetric link to an HTTPS endpoint, with protected management access:

```json
{
  "version": 1,
  "name": "Asymmetric HTTPS link",
  "protect": ["10.20.0.0/24"],
  "ssh_ports": [2222],
  "rules": [
    {
      "interface": "ens5",
      "direction": "egress",
      "match": {
        "destination": "198.51.100.20/32",
        "protocol": "tcp",
        "destination_port": 443
      },
      "impairment": {
        "delay": "40ms",
        "jitter": "10ms",
        "distribution": "normal",
        "loss_percent": 0.5,
        "rate": "5mbit",
        "queue_packets": 10000
      }
    },
    {
      "interface": "ens5",
      "direction": "ingress",
      "match": {
        "source": "198.51.100.20/32",
        "protocol": "tcp",
        "source_port": 443
      },
      "impairment": {
        "delay": "80ms",
        "jitter": "20ms",
        "distribution": "normal",
        "rate": "20mbit"
      }
    }
  ]
}
```

| Setting | Meaning |
|---|---|
| `match.family` | `any` (default), `ipv4`, or `ipv6`; addresses infer their family. Mixed families are rejected. |
| `match.source`, `destination` | Literal IP or CIDR. No DNS resolution. |
| `match.protocol` | Omit for all IP protocols, or choose `tcp`, `udp`, `icmp`, `icmpv6`. |
| `match.source_port`, `destination_port` | One port, 1–65535. Requires TCP or UDP. |
| `match.input_interface` | Egress rules only: select forwarded packets that entered this interface. Useful when NAT changes addresses. |
| `delay`, `jitter` | Durations with units, e.g. `50ms`, `500us`, `1s`, bounded to 0–1h. Jitter requires positive delay. |
| `correlation_percent` | Delay correlation, 0–100; requires jitter. |
| `distribution` | `uniform` (also the implicit default), `normal`, `pareto`, or `paretonormal`; requires jitter. |
| `loss_percent`, `duplicate_percent`, `corrupt_percent`, `reorder_percent` | Independent configured impairments, 0–100. Reordering requires delay. |
| `rate` | Bits per second: `bit`, `kbit`, `mbit`, `gbit`; e.g. `1.5mbit`. Bytes/s units such as `mbps` are deliberately rejected. |
| `queue_packets` | Netem queue capacity, default 10,000 packets; accepted range 1–10,000,000. |
| `seed` | Optional unsigned 32-bit netem random seed. Requires iproute2/kernel support; omitted by default for portability. |
| `protect` | Additional IPs/subnets excluded in both directions, before any target selection. |
| `ssh_ports` | Additional protected TCP ports under the default `automatic` management policy, which also protects port 22. |
| `management_policy` | `automatic` (default) or `separate`; see management protection and the inline model below. |
| `rules[].component` | Optional attribution: `encryptor_a`, `black_transport`, or `encryptor_b`. Labels do not construct or order a topology. |
| `rules[].ipv4_transport` | Fixed envelope size and provisioned-MTU contract for an IPv4 BLACK transport rule; see below. |

Unknown JSON properties and invalid option combinations are rejected. Each rule
must specify at least one impairment. Source, destination, protocol, ports, and
incoming interface within a rule are AND conditions. Empty `match` selects all
IPv4 and IPv6 traffic except the protections below. Non-IP traffic remains bypassed.
Port-based matching is not a complete classifier for non-initial fragments or
arbitrary encapsulated traffic; use an unfragmented test path or subnet selection.

Queue limits are part of the experiment: too-small queues add unintended overflow
loss; huge queues increase memory use and queuing delay. At 100 Mbit/s and 100 ms,
the bandwidth-delay product is about 1.25 MB, roughly 834 full-size 1500-byte
packets, before allowing for bursts. Set and report a deliberate queue budget.
`rate` is a configured link cap, not guaranteed application goodput.

## Management protection

With `management_policy` omitted or set to `automatic`, the application bypasses:

- TCP source or destination port 22, plus configured `ssh_ports`.
- IPv4 link-local `169.254.0.0/16`, IPv6 link-local `fe80::/10`, and link-local
  multicast `ff02::/16`.
- DHCP UDP ports 67/68 and DHCPv6 UDP ports 546/547.
- ICMPv6 router/neighbor discovery and redirect types 133–137.
- Any configured `protect` address/subnet, as either source or destination.

These are traffic classifications, not identity-based access control. An application
using a protected port also bypasses impairment. DNS, arbitrary HTTPS management,
and SSM's remote service endpoints are not automatically excluded. When testing
all traffic, protect the actual management path or use a separate management
interface. A protected SSH port does not guarantee access if DNS, routing, or the
host itself fails. Root processes and local administrators remain trusted.

`management_policy: "separate"` explicitly opts into an independent management
path. Every rule must be egress and specify a different `match.input_interface`.
Only selected forwarded traffic is impaired; there are no automatic SSH, DHCP,
or address bypass filters. Transit TCP port 22 is ordinary test traffic. `protect`
and `ssh_ports` are rejected with this policy to avoid exceptions hidden within
the transit model. Locally generated traffic and traffic from other incoming
interfaces do not match these rules. Provision and verify the actual management
path separately; this policy does not create a management interface or firewall.

## Routed appliance: Linux / EC2

For two interfaces, the forward path leaves the server-facing interface; the
return path leaves the client-facing interface. Configure one egress rule on each.
An IFB is not needed for this arrangement. Endpoints must actually route through
the appliance in both directions.

```bash
impair example --mode gateway --inside ens6 --outside ens5 > gateway.json
```

Edit the interfaces and `gateway.client_cidr`. The supplied rules use
`input_interface` to select transit traffic, including after source NAT. Their
IPv4 selectors affect all forwarded IPv4 traffic between the named interfaces;
add a destination or narrower selection if required. For a one-ENI EC2 appliance,
omit `gateway`, use a host-style ingress/egress profile, and configure routing and
forwarding separately. The managed gateway configuration requires two interfaces.

Before applying gateway rules, explicitly enable IPv4 forwarding on the dedicated
appliance and configure Linux routes and the existing host firewall:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo impair doctor --interface ens5 --gateway
sudo impair apply --profile gateway.json --duration 15m
```

The app deliberately does not toggle this global sysctl: changing it resets other
IPv4 host/router defaults. It does not change route tables, reverse-path filtering,
or system boot configuration. Configure these as part of the appliance deployment.
[Linux forwarding sysctl behavior](https://docs.kernel.org/networking/ip-sysctl.html)

Gateway configuration accepts this optional NAT/port publishing section:

```json
"gateway": {
  "inside": "ens6",
  "outside": "ens5",
  "client_cidr": "10.10.1.0/24",
  "masquerade": true,
  "publish": [
    {"protocol": "tcp", "listen_port": 8443, "target": "10.10.1.10", "target_port": 443},
    {"protocol": "udp", "listen_port": 9000, "target": "10.10.1.10", "target_port": 9000}
  ]
}
```

This is a fragment to insert into a complete profile, not a standalone JSON file.
Masquerading is restricted to the client subnet entering `inside` and leaving
`outside`. Published ports match traffic arriving on `outside` for a local
appliance address. Targets must be inside the client subnet. Publishing protected
SSH listening ports is rejected under the automatic management policy. With
separate management, explicit transit port-22 publishing is allowed. Broad “forward all TCP” behavior is intentionally
replaced by explicit mappings. There is no hairpin-NAT or IPv6-NAT mode.

The app creates one uniquely named `table ip impair_<id>`, containing its own
forwarding and NAT chains. It does not flush existing tables, change existing
policies, disable UFW/firewalld, or override another chain's drop verdict. Its
forward chain adds scoped accept/counter rules and otherwise has accept policy;
it is **not a perimeter firewall**. Existing firewall rules must permit the intended
forwarded flows. If another NAT manager handles overlapping traffic, use a
dedicated appliance or resolve that overlap explicitly.

Stopping removes the experiment's NAT rules but does not flush conntrack. Existing
NAT connections may retain their mappings until they close or expire; use fresh
connections when measuring post-cleanup behavior.

For EC2 deployment:

1. Use a dedicated instance/subnet arrangement with symmetric VPC routes through
   the appliance. Verify the Linux return routes for multi-ENI configurations.
2. Disable source/destination checks on the forwarding appliance's relevant ENIs.
3. Permit test traffic in security groups, NACLs, and the Linux firewall, including
   the required return traffic. Route insertion alone does not grant permission.
4. Measure the unimpeded baseline and choose an instance with bandwidth/PPS
   headroom. Inspect ENA allowance counters with `doctor --interface <name>`.
5. Validate both directions on the actual AMI and instance architecture.

The app does not make AWS API calls or change cloud networking settings.
[AWS middlebox routing](https://docs.aws.amazon.com/vpc/latest/userguide/middlebox-routing-console.html),
[ENI source/destination checks](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html),
[ENA allowance metrics](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-network-performance-ena.html).

## Packet processing and fidelity

Egress uses an owned `prio` root (`7a00:`). Its priority map sends unmatched
traffic to the bypass band; software flower filters send selected traffic to a
netem child (`7a10:`) on band 3. Netem's native `rate` option handles rate limiting.
There is no HTB default-class mismatch or shell-generated class hierarchy.

Ingress uses an owned ingress qdisc and flower filters. Selected traffic is
redirected to an owned IFB; a netem root on that IFB applies impairment. Bypass
filters execute before redirection. This follows Linux's IFB redirection approach.
[Traffic redirection reference](https://man7.org/linux/man-pages/man8/tc-mirred.8.html)

The bypass band has higher priority than the impaired band. Saturating the same
interface with bypass traffic can reduce impaired-flow throughput; isolate the
experiment from competing workloads. The application replaces the default root
scheduler on a shaped egress interface, which also changes multiqueue behavior.
It is not designed to preserve peak ENA line rate while emulating a constrained link.

Netem is a kernel emulator, not a hard real-time instrument. Timer granularity,
queueing, and TCP Small Queues affect measurements. Receiver ingress is preferable
to sender-only egress for realistic TCP tests. A seed controls netem randomness;
it does not guarantee identical results across different timing, traffic, kernels,
or hosts. [Netem reference](https://man7.org/linux/man-pages/man8/tc-netem.8.html)

Record offload settings and packet sizes with test results. `doctor` reads driver,
offload, and ENA statistics through `ethtool` but does not change those settings.
Packets in different directions encounter independent queues: 50 ms added each
way contributes approximately 100 ms to RTT; 1% loss each way is not simply a
single 1% end-to-end experiment. A bandwidth cap, added latency, and loss all
influence TCP goodput.

## Ownership, expiry, and recovery

- The default journal is `/run/impair/active.json`, in a private 0700 directory.
  Writes use fsync and atomic rename. A file lock serializes apply/stop/status.
- Applying refuses custom root qdiscs and root filters on an egress interface.
  Recognized handle-0 defaults are allowed. Ingress requires no existing ingress
  or clsact qdisc, even if it belongs to another program such as a CNI.
- Cleanup verifies interface indices, qdisc handle/kind, and IFB kind/alias before
  removing resources. Changed ownership stops cleanup and retains the journal.
  The uniquely named nftables table is reserved for the experiment.
- Root cleanup restores the kernel's default scheduler. It does not reconstruct
  arbitrary prior qdisc trees, settings, queued packets, or counters. Do not edit
  app-owned qdiscs/tables or reuse their identifiers during an experiment.
- Multiple tc commands are not one kernel transaction. The journal supports
  compensating cleanup; brief partial configuration is possible during apply or
  a failure. nftables table creation is submitted as one batch.
- Default expiry is 10 minutes; `--duration` accepts 5 seconds through 24 hours.
  A separate transient systemd timer calls this same installed executable with
  an experiment token. A stale callback cannot stop a newer experiment.
- Expiry is best effort: system load and an in-progress locked operation can delay
  cleanup. Failed timer cleanup retries using systemd's service restart policy.
  It is not a guarantee against kernel, host, or systemd failure.
- Keep the installed binary and journal available until stop/expiry completes.
  Do not delete `/run/impair` to “reset” the app. A failed cleanup requires fixing
  the reported conflict and rerunning `stop` in the original network namespace.
- Reboot clears runtime network state, transient timers, and the default `/run`
  journal. Experiments are intentionally not reapplied at boot. Existing system
  services may independently reinstall their own network configuration.

```bash
sudo impair status --json
sudo impair stop
sudo systemctl list-timers 'impair-*'
sudo journalctl -u 'impair-*'
```

For an isolated namespace/container test without host systemd, explicitly use
`apply --no-watchdog` and call `stop` yourself. There is then no automatic expiry
and no signal-triggered cleanup. A container also needs the appropriate namespace
privileges and access to the host kernel features. Never assume a container's
default network namespace represents the host's traffic path.

## Test and build

```bash
make test       # On Linux: race detection, coverage, and go vet
make release    # Static linux/amd64 and linux/arm64 executables + SHA256SUMS
```

Unit tests cover invalid/injected input, both address families, impairment command
generation, management bypass ordering, NAT scope, journal persistence, conflicts,
stale tokens, wrong namespaces, ownership changes, repeatable cleanup, and rollback
at every command in a bidirectional apply. These tests use a deterministic kernel
model and do not prove real packet behavior.

### Native Linux

On a disposable Ubuntu Linux VM with Go 1.22 or newer installed, run from the
repository root. Race tests need a C compiler; the packet tests need root and
network namespace privileges.

```bash
sudo apt-get update
sudo apt-get install -y build-essential iproute2 nftables iputils-ping ethtool iperf3 python3 tcpdump
make test
make build
sudo python3 -u tests/transport.py --binary "$PWD/dist/impair"
sudo python3 -u tests/integration.py --binary "$PWD/dist/impair"

# Separately, on a host running systemd:
sudo bash tests/watchdog.sh "$PWD/dist/impair"
```

`integration.py` creates three named namespaces with veth links, changes sysctls
only inside the router namespace, and removes its own resources afterward. It
checks bidirectional delay, SSH bypass, IPv6/IFB, jitter, statistical loss, TCP rate limiting,
masquerading, DNAT, counters, and preservation of an unrelated nftables table.
The watchdog test creates a temporary dummy interface on a systemd host and
checks independent automatic removal. These tests should not be run on a host where
other automation might mutate their temporary resources. Tests print PASS only
after their assertions succeed. Timing tests need an otherwise idle VM.

`transport.py` checks the synthetic A/BLACK/B model in six namespaces, including
its separate management network, byte accounting, and IPv4 PMTU behavior. See the
inline-model section below for the detailed scope.

### Docker on macOS or Linux

Use a Docker engine running Linux containers. On macOS, tests run on the Docker
VM's Linux kernel. [tests/Dockerfile](tests/Dockerfile) installs the packet-test
tools and Go's build dependencies; its default Go 1.22 image checks the minimum
supported toolchain. This is a local test image, not a deployment image. To test a
different Go toolchain, pass `--build-arg GO_IMAGE=<official-golang-image-tag>`.

From the repository root, build the image and run the Go checks without networking
privileges. The source mount is read-only; test output and Go caches stay inside
the disposable container.

```bash
docker build -t impair-test -f tests/Dockerfile tests
docker run --rm \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  impair-test make test
```

For packet tests, start a container and build a Linux executable inside it. The
explicit `--privileged` option permits network namespace creation and kernel
network configuration inside the test environment. Use a dedicated test Docker
environment; do not add host networking or mount the host's network/state paths.

```bash
docker run -d --rm --privileged --name impair-test-run \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  impair-test sleep infinity
docker exec impair-test-run go build -buildvcs=false -o /tmp/impair ./cmd/impair
docker exec impair-test-run python3 -u tests/transport.py --binary /tmp/impair
docker exec impair-test-run python3 -u tests/integration.py --binary /tmp/impair
```

Run the two packet suites independently so a failure in one does not hide the
other's result. After changing source, repeat the build before rerunning a suite.
When finished, including after a failed test, stop the container; `--rm` removes
its writable layer and any remaining test namespaces with it:

```bash
docker stop impair-test-run
```

This container does not run systemd. Its packet fixtures use `--no-watchdog` and
explicit cleanup; test automatic expiry with `tests/watchdog.sh` on a native
systemd Linux host. Docker results do not establish Ubuntu/AL2023 or EC2 support.
The current OrbStack validation found a pre-existing IFB alias/cleanup failure in
`integration.py`; the inline `transport.py` suite passed. See
[VALIDATION.md](VALIDATION.md) for the exact environment, evidence, and remaining
acceptance work. A failed ownership check must not be bypassed to make tests pass.

For deployment acceptance, run these on Ubuntu 24.04, Ubuntu 26.04, and AL2023,
on each intended architecture; then test the real ENI/VPC route path. Record AMI ID,
kernel, instance type, iproute2/nftables versions, offload settings, baseline RTT,
target/observed rate and loss, and the cleanup result. A namespace test does not
validate AWS route tables or instance networking allowances.

## Synthetic inline IPv4 model

This is an application-testing model for a provisioned routed path:

```text
client <-> device A <-> BLACK transport <-> device B <-> server
             |                |               |
             +------ independent management ---+
```

Use [inline-a.json](examples/inline-a.json),
[inline-black.json](examples/inline-black.json), and
[inline-b.json](examples/inline-b.json) on the respective stages. All values are
synthetic examples. No TACLANE model has been selected, and this feature claims
no TACLANE compatibility, Type 1 equivalence, or device-specific fidelity.
Packets remain plaintext. No encryptor, security boundary, or tunnel is created.

Each device contributes its own configured delay and queue, in each direction.
These delays approximate processing latency; they do not model CPU service time,
packet-rate capacity, or shared device throughput. BLACK transport owns the link
rate, envelope accounting, transport delay and any configured loss. Component
labels are attribution metadata in the profile/journal; actual routing must place
the stages in sequence. A sum of delays on one queue does not reproduce three
separate queues. Configure zero-delay stages by omitting their rules when no
other impairment is needed.

An `ipv4_transport` rule requires `component: "black_transport"`,
`management_policy: "separate"`, IPv4 selection, and an explicit `impairment.rate`.
For `black_mtu = M` and `overhead_bytes = H`, the model defines:

- Modeled outer IP length = inner IPv4 total length + H.
- Effective inner MTU = M − H.
- Rate is modeled outer IP bits/s, excluding BLACK Ethernet framing, FCS,
  preamble, and interpacket gaps. It is not application goodput.

The supported egress path is plain, untagged Ethernet or veth. Its qdisc already
counts the 14-byte Ethernet header, so the generated netem rate uses an adjustment
of `H − 14`. With H=64 this is `rate 4mbit 50`; with H=0 it is `rate 4mbit -14`.
This accounts for the envelope once on each direction's BLACK bottleneck. Device
A and B do not acquire envelope accounting from their component labels.
[Netem rate accounting](https://github.com/iproute2/iproute2/blob/main/man/man8/tc-netem.8)

Preflight requires the selected egress interface MTU to equal M−H. It also rejects
non-Ethernet, VLAN, bridge, and tunnel link kinds for this mode. M is bounded to
68–65535; H must be nonnegative and leave at least 68 bytes for inner IPv4. For
the example M=1500, H=64, provision **both BLACK interfaces and their A/B peer
interfaces at MTU 1436**. Keep client/server and RED-facing interfaces larger.
A and B then generate PMTU feedback when a packet cannot enter the modeled BLACK
path. Matching both ends matters: a smaller receive-side veth MTU can drop a large
packet before IP forwarding has an opportunity to return ICMP. This interface
MTU applies to all packets using that interface, including unmatched packets; use
dedicated transit interfaces. `impair` does not set, own, or restore MTUs, routes,
forwarding sysctls, or offloads. The MTU check is a snapshot at apply, not ongoing
enforcement against external changes. `plan`/`--dry-run` report the requirement
without inspecting the host, and `status --json` includes current link MTUs.

Use TSO/GSO/GRO-disabled paths for packet-level acceptance and record the settings.
Aggregation can invalidate per-packet envelope accounting. Link type and MTU checks
alone do not verify peer MTUs, offloads, routing, forwarding, firewall permissions, or other
lower path MTUs. The fixture verifies the byte basis through qdisc counters.

The supported fidelity is steady-state, unfragmented IPv4 with working DF/PMTU
feedback. The provisioned router returns ICMP fragmentation-needed with the reduced
MTU, allowing applications to adapt. This is a reduced inner-path MTU surrogate;
there is no outer packet or tunnel ICMP translation. DF-clear traffic follows the
underlying Linux fragmentation behavior, which is outside the supported model.
No padding/alignment, inner-versus-outer fragmentation policy, IPv6 envelope, or
PMTU black-hole scenario is implemented.
[IPv4 PMTU discovery](https://www.rfc-editor.org/rfc/rfc1191.html)

The ordinary impairment settings still act on plaintext packets; for example,
corruption does not reproduce ciphertext authentication failure. Tunnel setup,
successful rekey, disruptive changeover, peer failure, recovery, QoS classes,
packet-rate limits, multicast, Layer 2/VLAN behavior, and XFRM/IPsec remain deferred.
Future device profiles need a recorded model, software version, configuration,
parameter source, and measured or documented evidence.

`stop` and expiry end an experiment by removing impairment. They do not simulate
a failed, closed encryptor. Each namespace has its own journal and must use a
different state directory; namespace fixtures use `--no-watchdog` and explicit
cleanup. There is no atomic A/BLACK/B transition or multi-namespace coordinator.

On a disposable Linux VM with the earlier packet-test dependencies plus `ethtool`
and `tcpdump`:

```bash
sudo python3 tests/transport.py --binary /usr/local/bin/impair
```

The fixture creates six namespaces (client, A, BLACK, B, server, management),
provisions routes/MTUs, disables TSO/GSO/GRO only on its own links, and cleans up
afterward. It checks separate and combined stage delays, transit SSH and management,
UDP size/rate sweeps with zero and nonzero envelope overhead, Ethernet byte
accounting, MTU prerequisite rejection, IPv4 DF boundaries in both directions,
captured TCP PMTU feedback and adaptation, and preservation of provisioned MTUs
after `stop`.

## Migration from the original scripts

| Original | Modern equivalent |
|---|---|
| `impair --delay ... --jitter ...` | JSON profile with explicit interface/direction and `impair apply --profile ...`. |
| `impair --bandwidth ...` | `impairment.rate`, with unambiguous bit/s units. |
| `impair2 start/stop/status` | `impair apply`, `impair stop`, `impair status`. |
| `forwardALLTCP` | Explicit gateway client subnet and published TCP/UDP ports. |
| `stopForward` | Scoped cleanup of the experiment's own resources. |
| Reset all interfaces | No global reset; only the current experiment is cleaned up. |

Future extensions can add scenario timelines, burst-loss models, a local UI/API,
or additional backends. They should share this configuration/ownership layer and
keep packet handling in the kernel.
