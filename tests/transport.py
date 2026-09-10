#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic IPv4 envelope acceptance test on a disposable Linux host.

sudo python3 tests/transport.py --binary /absolute/path/to/impair
Requires iproute2, ping, ethtool, iperf3, tcpdump, Python 3 and namespace privileges.
All links, routes, MTUs, offload changes and sysctls belong to this test's namespaces.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import tempfile
import time
import uuid


ECHO = '''import socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",22));s.listen();print("READY",flush=True)
while True:
 c,_=s.accept()
 with c:
  c.recv(32);c.sendall(b"ok")
'''
UDP_RECEIVE = '''import socket,sys,time,json
n=int(sys.argv[1]);s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4000000)
s.bind(("0.0.0.0",9000));s.settimeout(15);print("READY",flush=True)
times=[];sizes=[]
for _ in range(n):
 data,_=s.recvfrom(65535);times.append(time.monotonic());sizes.append(len(data))
print(json.dumps({"packets":len(times),"bytes":sum(sizes),"seconds":times[-1]-times[0]}))
'''
UDP_SEND = '''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP,10,2) # IP_MTU_DISCOVER = IP_PMTUDISC_DO
for _ in range(int(sys.argv[3])):s.sendto(b"x"*int(sys.argv[2]),(sys.argv[1],9000))
'''
TCP_ECHO = '''import socket,sys
with socket.create_connection((sys.argv[1],22),3) as s:
 s.sendall(b"test");assert s.recv(32)==b"ok"
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    if os.geteuid() != 0:
        parser.error('run as root on a disposable Linux host')
    for tool in ['ip', 'tc', 'ping', 'ethtool', 'iperf3', 'tcpdump', 'sysctl']:
        if not shutil.which(tool):
            parser.error(f'missing {tool}')
    suffix = uuid.uuid4().hex[:8]
    nodes = {n: f'imenv-{suffix}-{n}' for n in ['c', 'a', 'black', 'b', 's', 'mgmt']}
    created, children, active = [], [], []
    work = Path(tempfile.mkdtemp(prefix='impair-transport-'))

    def run(*argv, ns=None, check=True, timeout=45):
        command = (['ip', 'netns', 'exec', nodes[ns]] if ns else []) + list(argv)
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f'{command}\n{result.stdout}\n{result.stderr}')
        return result

    def app(ns, command, *argv, check=True):
        return run(binary, command, '--state-dir', str(work / ns), *argv, ns=ns, check=check)

    def stop():
        for ns in list(reversed(active)):
            app(ns, 'stop')
            app(ns, 'stop')
            active.remove(ns)

    def profile(component, forward, reverse, overhead=None):
        rules = []
        for device, incoming, delay in [('right', 'left', forward), ('left', 'right', reverse)]:
            impairment = {'delay': f'{delay}ms', 'queue_packets': 2000} if delay else {'rate': '1mbit', 'queue_packets': 2000}
            rule = {'interface': device, 'direction': 'egress', 'component': component,
                    'match': {'family': 'ipv4', 'input_interface': incoming}, 'impairment': impairment}
            if overhead is not None:
                impairment['rate'] = '1mbit'
                rule['ipv4_transport'] = {'black_mtu': 1500, 'overhead_bytes': overhead}
            rules.append(rule)
        return {'version': 1, 'name': f'Synthetic {component}', 'management_policy': 'separate', 'rules': rules}

    def apply(ns, p, check=True):
        path = work / f'{ns}.json'
        path.write_text(json.dumps(p))
        if ns not in active:
            active.append(ns)  # Attempt cleanup even if apply fails partway.
        return app(ns, 'apply', '--profile', str(path), '--no-watchdog', check=check)

    def start(ns, *argv, ready=False):
        proc = subprocess.Popen(['ip', 'netns', 'exec', nodes[ns], *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(proc)
        if ready:
            # Readiness has a deadline; a failed server must not hang the fixture.
            import select
            if not select.select([proc.stdout], [], [], 5)[0] or proc.stdout.readline().strip() != 'READY':
                raise RuntimeError(f'server failed to become ready: {argv}')
        return proc

    def connect(first, fdev, faddr, second, sdev, saddr):
        run('ip', 'link', 'add', fdev, 'type', 'veth', 'peer', 'name', 'impeer', ns=first)
        run('ip', 'link', 'set', 'impeer', 'netns', nodes[second], ns=first)
        run('ip', 'link', 'set', 'impeer', 'name', sdev, ns=second)
        for ns, dev, address in [(first, fdev, faddr), (second, sdev, saddr)]:
            run('ip', 'addr', 'add', address + '/24', 'dev', dev, ns=ns)
            run('ip', 'link', 'set', dev, 'up', ns=ns)
            run('ethtool', '-K', dev, 'tso', 'off', 'gso', 'off', 'gro', 'off', ns=ns)
            features = run('ethtool', '-k', dev, ns=ns).stdout
            for name in ['tcp-segmentation-offload', 'generic-segmentation-offload', 'generic-receive-offload']:
                assert re.search(rf'^{name}: off', features, re.M), features

    def mtu(overhead):
        # Match both ends of each BLACK-facing link. A smaller receive-side
        # veth MTU can silently drop full TCP packets before IPv4 forwarding
        # can generate ICMP. A/B enforce the inner limit on entry to BLACK.
        for dev in ['left', 'right']:
            run('ip', 'link', 'set', dev, 'mtu', str(1500 - overhead), ns='black')
        for ns, dev in [('a', 'right'), ('b', 'left')]:
            run('ip', 'link', 'set', dev, 'mtu', str(1500 - overhead), ns=ns)

    def rtt():
        output = run('ping', '-n', '-c', '6', '-i', '0.05', '-W', '2', '10.211.4.2', ns='c').stdout
        values = [float(v) for v in re.findall(r'time[=<]([\d.]+)', output)]
        assert len(values) == 6, output
        return statistics.median(values)

    def counters(device='right'):
        qs = json.loads(run('tc', '-j', '-s', 'qdisc', 'show', 'dev', device, ns='black').stdout)
        return next(q for q in qs if q['kind'] == 'netem')

    try:
        print(run('uname', '-srmo').stdout.strip(), flush=True)
        for argv in [('ip', '-V'), ('tc', '-V'), ('iperf3', '--version')]:
            print(run(*argv).stdout.splitlines()[0], flush=True)
        for ns in nodes.values():
            run('ip', 'netns', 'add', ns)
            created.append(ns)
            run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        connect('c', 'eth0', '10.211.1.2', 'a', 'left', '10.211.1.1')
        connect('a', 'right', '10.211.2.1', 'black', 'left', '10.211.2.2')
        connect('black', 'right', '10.211.3.1', 'b', 'left', '10.211.3.2')
        connect('b', 'right', '10.211.4.1', 's', 'eth0', '10.211.4.2')
        for i, ns in enumerate(['a', 'black', 'b'], 1):
            connect(ns, 'mgmt', f'10.212.{i}.1', 'mgmt', f'm{i}', f'10.212.{i}.2')
            run('sysctl', '-q', '-w', 'net.ipv4.ip_forward=1', ns=ns)
            start(ns, 'python3', '-u', '-c', ECHO, ready=True)
        for ns, via in [('c', '10.211.1.1'), ('a', '10.211.2.2'), ('b', '10.211.3.1'), ('s', '10.211.4.1')]:
            run('ip', 'route', 'add', 'default', 'via', via, ns=ns)
        run('ip', 'route', 'add', '10.211.1.0/24', 'via', '10.211.2.1', ns='black')
        run('ip', 'route', 'add', '10.211.4.0/24', 'via', '10.211.3.2', ns='black')
        start('s', 'python3', '-u', '-c', ECHO, ready=True)
        baseline = rtt()
        print(f'Baseline RTT {baseline:.3f} ms; all fixture TSO/GSO/GRO disabled', flush=True)

        # Reject incorrect prerequisites without leaving an experiment or qdisc.
        rejected = apply('black', profile('black_transport', 0, 0, 64), check=False)
        assert rejected.returncode and 'requires provisioned MTU 1436' in rejected.stderr, rejected
        assert not (work / 'black' / 'active.json').exists()
        stop()
        print('PASS MTU mismatch rejected before mutation', flush=True)

        stages = [('a', 'encryptor_a', 10, 15), ('black', 'black_transport', 30, 35), ('b', 'encryptor_b', 20, 25)]
        for ns, component, forward, reverse in stages:
            apply(ns, profile(component, forward, reverse))
            observed = rtt() - baseline
            assert abs(observed - forward - reverse) < 20, (ns, observed)
            stop()
        for ns, component, forward, reverse in stages:
            apply(ns, profile(component, forward, reverse))
        observed = rtt() - baseline
        assert abs(observed - 135) < 30, observed
        start_time = time.monotonic()
        run('python3', '-c', TCP_ECHO, '10.211.4.2', ns='c')
        transit_time = time.monotonic() - start_time
        assert transit_time > 0.20, transit_time
        for i in range(1, 4):
            start_time = time.monotonic()
            run('python3', '-c', TCP_ECHO, f'10.212.{i}.1', ns='mgmt')
            assert time.monotonic() - start_time < 0.15, 'management path delayed or host overloaded'
        print(f'PASS independent stages, combined RTT +{observed:.2f} ms, transit SSH and separate management', flush=True)
        stop()

        # Finite UDP trains saturate the queue without queue overflow. Qdisc byte
        # deltas establish the actual Ethernet length basis independently of rate.
        for overhead in [0, 256]:
            mtu(overhead)
            udp_profile = profile('black_transport', 0, 0, overhead)
            for rule in udp_profile['rules']:
                rule['match'].update({'protocol': 'udp', 'destination_port': 9000})
            apply('black', udp_profile)
            for payload in [128, 512, 1200]:
                count = 400
                before = counters()
                receiver = start('s', 'python3', '-u', '-c', UDP_RECEIVE, str(count), ready=True)
                run('python3', '-c', UDP_SEND, '10.211.4.2', str(payload), str(count), ns='c')
                stdout, stderr = receiver.communicate(timeout=20)
                assert receiver.returncode == 0, stderr
                sample = json.loads(stdout)
                after = counters()
                assert sample['packets'] == count and sample['bytes'] == count * payload, sample
                assert after['packets'] - before['packets'] == count, (before, after)
                assert after['bytes'] - before['bytes'] == count * (payload + 28 + 14), (before, after)
                assert after.get('drops', 0) == before.get('drops', 0), (before, after)
                expected_seconds = (count - 1) * (payload + 28 + overhead) * 8 / 1e6
                assert abs(sample['seconds'] / expected_seconds - 1) < 0.15, (overhead, payload, sample, expected_seconds)
                print(f'PASS UDP H={overhead} payload={payload}: {sample["seconds"]:.3f}s / expected {expected_seconds:.3f}s; Ethernet byte basis confirmed', flush=True)
            stop()

        mtu(256)
        apply('black', profile('black_transport', 0, 0, 256))
        inner_mtu = 1244
        run('ip', 'addr', 'add', '10.211.4.10/24', 'dev', 'eth0', ns='s')
        run('ip', 'addr', 'add', '10.211.1.10/24', 'dev', 'eth0', ns='c')
        for ns, target, router in [('c', '10.211.4.10', '10.211.1.1'), ('s', '10.211.1.10', '10.211.4.1')]:
            # Fresh destinations avoid earlier PMTU cache entries. Test oversize
            # last, and require an ICMP response from A/B at the BLACK boundary.
            for length in [inner_mtu - 1, inner_mtu]:
                run('ping', '-n', '-c', '1', '-W', '2', '-M', 'do', '-s', str(length - 28), target, ns=ns)
            result = run('ping', '-n', '-c', '1', '-W', '2', '-M', 'do', '-s', str(inner_mtu + 1 - 28), target, ns=ns, check=False)
            assert result.returncode and f'From {router}' in result.stdout and re.search(r'mtu\s*[= ]\s*1244', result.stdout, re.I), result
        print('PASS IPv4 DF probes below/at/above effective MTU, ICMP next-hop MTU 1244 in both directions', flush=True)

        # Use fresh addresses so the TCP sender must learn PMTU for this connection.
        run('ip', 'addr', 'add', '10.211.4.3/24', 'dev', 'eth0', ns='s')
        capture = start('c', 'tcpdump', '-l', '-n', '-i', 'eth0', '-vv', '-c', '8', 'icmp')
        iperf = start('s', 'iperf3', '-s', '-1')
        time.sleep(0.25)
        client = start('c', 'iperf3', '-c', '10.211.4.3', '-t', '5', '-J')
        deadline = time.monotonic() + 4
        learned = False
        while time.monotonic() < deadline:
            sockets = run('ss', '-tin', 'dst', '10.211.4.3', ns='c').stdout
            if 'pmtu:1244' in sockets:
                learned = True
                break
            time.sleep(0.1)
        stdout, stderr = client.communicate(timeout=15)
        assert client.returncode == 0, stderr
        rate = json.loads(stdout)['end']['sum_received']['bits_per_second']
        capture.terminate()
        feedback, capture_errors = capture.communicate(timeout=5)
        assert learned and rate > 100000 and 'mtu 1244' in feedback, (learned, rate, sockets, feedback, capture_errors)
        iperf.communicate(timeout=5)
        print(f'PASS TCP learned PMTU 1244 and transferred data ({rate / 1e6:.3f} Mbit/s)', flush=True)
        stop()
        assert rtt() - baseline < 20
        for ns in ['a', 'black', 'b']:
            assert not (work / ns / 'active.json').exists()
            for dev in ['left', 'right']:
                assert '7a00:' not in run('tc', 'qdisc', 'show', 'dev', dev, ns=ns).stdout
        for link in json.loads(run('ip', '-j', 'link', 'show', ns='black').stdout):
            if link['ifname'] in ['left', 'right']:
                assert link['mtu'] == inner_mtu, link
        print('PASS cleanup removes impairment and preserves externally provisioned MTUs', flush=True)
        print('Synthetic namespace acceptance passed; this is not device, systemd, distro, or EC2 validation.', flush=True)
    finally:
        try:
            stop()
        finally:
            for proc in children:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
            for ns in reversed(created):
                run('ip', 'netns', 'delete', ns, check=False)
            shutil.rmtree(work)


if __name__ == '__main__':
    main()
