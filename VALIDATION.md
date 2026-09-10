# Validation record

Recorded during the 2026-09-09/10 development session. These results apply to the
working-tree synthetic IPv4 transport increment based on commit `b050174`.
They are not a blanket platform or device certification. The handoff's earlier
report of 94 passing cases had no local result artifact and is not reused here.

## Environment

- Development/build host: macOS, arm64, Go 1.27.1.
- Linux test runtime: local OrbStack Docker, linux/arm64.
- Kernel: `7.0.14-orbstack-00380-ga7e0a2dc9535`.
- Test userspace: Debian bookworm, official `golang:1.22-bookworm`, Go 1.22.12.
- Base image digest: `sha256:3d699e4d15d0f8f13c9195c0632a16702b8cbdece2955af1c23b37ae5d55a253`.
- iproute2/tc 6.1.0; libbpf 1.1.2; nftables package 1.0.6-2+deb12u2;
  iperf3 3.12; ethtool 6.1; tcpdump 4.99.3.
- Packet tests use private network namespaces in a privileged disposable container,
  with the repository mounted read-only. They do not use host networking.
- The inline fixture disables and checks TSO/GSO/GRO on its own veth interfaces.

The repository's [test Dockerfile](tests/Dockerfile) packages this toolchain and
the packet dependencies. Package revisions may change on a later image rebuild;
record versions again when reproducing. See [README test instructions](README.md#test-and-build)
for native Linux and Docker commands, including container creation and cleanup.

## Results

| Check | Result | Scope |
|---|---|---|
| Linux Go tests with race detection and coverage | Passed | Validation, command plans, simulated-kernel lifecycle and rollback |
| `go vet ./...` | Passed | Linux/arm64 with Go 1.22.12 |
| `make release` from macOS | Passed | Static Linux amd64 and arm64 ELF executables using Go 1.27.1 |
| Release checksums with `shasum -a 256 -c SHA256SUMS` | Passed | Both generated binaries |
| Cross-built arm64 executable: inline example validation and JSON plan | Passed | Offline execution in Linux; MTU 1436 and netem adjustment 50 reported |
| `tests/transport.py` | Passed | Real namespace packet behavior for the synthetic inline model; details below |
| `tests/integration.py` | Failed | IFB cleanup ownership check, reproduced on unchanged `b050174` |
| `tests/watchdog.sh` / independent systemd expiry | Not run | Test containers do not run host systemd |
| Native Ubuntu 24.04/26.04, Amazon Linux 2023, EC2/Graviton | Not run | Docker userspace/kernel results do not establish deployment compatibility |
| Device-specific TACLANE behavior or compatibility | Not tested or claimed | No model, software/configuration, or measured device parameters selected |

The README's Docker image build, unprivileged `make test`, and privileged inline
packet workflow were also executed using `tests/Dockerfile`. Go coverage was
38.7% for the CLI and 74.1% for the internal package. The inline repeat passed
with baseline RTT 0.160 ms, added RTT 144.84 ms, all six UDP accounting checks,
and TCP PMTU 1244 at 0.792 Mbit/s. This verifies the documented Docker procedure;
the native systemd-host procedure remains unexecuted.

## Inline packet acceptance

The topology is client → A → BLACK → B → server, with a separate management
namespace connected directly to A, BLACK, and B. Each stage has a separate
journal. No systemd timer or tunnel is involved.

The completed run recorded baseline median RTT 0.129 ms. Independent stage-delay
checks passed; combined added RTT was 144.87 ms for 135 ms of configured round-trip
delay (30 ms acceptance tolerance). Transit TCP port 22 was delayed, while TCP
port 22 on each separate management link remained reachable within its timing
bound. The fixture uses a 2000-packet queue budget.

UDP trains contain 400 datagrams at a modeled outer-IP rate of 1 Mbit/s. Every
datagram arrived, no netem drops were added, and qdisc counter deltas exactly
matched `400 × (UDP payload + 28 IPv4/UDP bytes + 14 Ethernet bytes)`.
The measured interval excludes the first packet's serialization, so its expected
value is `399 × (payload + 28 + H) × 8 / 1,000,000` seconds.

| Envelope H (bytes) | UDP payload (bytes) | Expected interval (s) | Observed interval (s) |
|---|---|---|---|
| 0 | 128 | 0.498 | 0.499 |
| 0 | 512 | 1.724 | 1.723 |
| 0 | 1200 | 3.920 | 3.919 |
| 256 | 128 | 1.315 | 1.316 |
| 256 | 512 | 2.541 | 2.543 |
| 256 | 1200 | 4.737 | 4.737 |

These measurements verify the `H − 14` netem adjustment for the tested plain
Ethernet/veth egress path. They do not establish byte accounting for aggregated
packets, VLANs, other link types, or actual encapsulation.

With BLACK MTU 1500 and H=256, the effective inner MTU is 1244. Both directions
passed DF probes of total IPv4 length 1243 and 1244, and rejected length 1245 with
router-generated ICMP advertising MTU 1244. A fresh TCP destination produced
captured fragmentation-needed feedback, `ss` reported PMTU 1244, and iperf3
transferred data at 0.792 Mbit/s. This verifies adaptation, not a general TCP
goodput guarantee. Stopping removed the owned qdiscs and journals, preserved the
provisioned MTUs, and restored baseline small-packet RTT. No named test namespaces
remained after fixture cleanup.

The fixture initially set a lower MTU only on BLACK's interfaces. On this veth
path, full-size TCP packets were dropped before IPv4 forwarding could return
ICMP, even though probes just one byte above the effective MTU received feedback.
Provisioning matching MTUs at both ends of the BLACK-facing links resolved that
failure: A/B now generate PMTU feedback at entry to BLACK. This requirement is
documented in the README. The program checks only its selected egress interfaces;
it does not inspect peer namespaces or establish that the full path is correct.

## Existing IFB issue

The general packet suite reached its first ingress/egress delay, SSH bypass, and
counter assertions, then failed at cleanup with:

```text
impair: IFB ownership changed: <experiment IFB name>
```

The same failure occurred with source exported from unchanged commit `b050174`,
compiled with the same Go toolchain and run with its original integration script.
A separate minimal reproduction in a temporary namespace ran:

```text
ip link add name imifbcheck alias impair:0123456789abcdef type ifb
ip -j -d link show
```

The command succeeded, but link JSON reported `info_kind: ifb` with no `ifalias`.
The existing cleanup guard therefore correctly refused to delete an interface
whose ownership marker was absent. This is an unresolved compatibility/lifecycle
issue, not a regression introduced by the IPv4 transport fields. It has not been
fixed by weakening ownership checks. Later IPv6, jitter, loss, and gateway/NAT
assertions in that suite were not reached and are not claimed as validated here.

The inline fixture uses routed egress shaping and does not require IFB. Its pass
does not imply that ingress shaping or the entire legacy suite passed.

## Remaining acceptance

Resolve the IFB creation/ownership issue with a recovery-safe mechanism, then rerun
the complete general packet suite. Run independent expiry on a systemd Linux
host. Run both packet suites and expiry on each intended Ubuntu/AL2023 architecture,
then test actual EC2 ENI/VPC paths, including Graviton. Record AMI, kernel, instance
type, tool versions, offloads, routes, baseline, queue budget, target and observed
delay/rate/loss, and cleanup results for every deployment acceptance run.

No actual tunnel headers, cryptography, DF-clear tunnel fragmentation/reassembly,
IPv6 envelope, setup/rekey/failure/recovery, closed-boundary behavior, or atomic
cross-component transitions have been validated by this increment.
