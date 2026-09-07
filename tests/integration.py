#!/usr/bin/env python3
"""Privileged, isolated Linux packet tests. Only creates its own namespaces.

Run on a disposable Linux VM: sudo python3 tests/integration.py --binary ./dist/impair-linux-amd64
Requires iproute2, nftables, iputils-ping, iperf3, Python 3, and network namespace privileges.
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    if os.geteuid() != 0:
        parser.error('run as root on a disposable Linux VM')
    for tool in ['ip', 'tc', 'nft', 'ping', 'iperf3', 'sysctl']:
        if not shutil.which(tool):
            parser.error(f'missing {tool}')
    suffix = uuid.uuid4().hex[:8]
    client, router, server = [f'imtest-{suffix}-{n}' for n in ['c', 'r', 's']]
    created, children = [], []
    work = Path(tempfile.mkdtemp(prefix='impair-integration-'))
    state = work / 'state'
    owner = None

    def run(*argv, ns=None, check=True, text=None):
        command = (['ip', 'netns', 'exec', ns] if ns else []) + list(argv)
        result = subprocess.run(command, input=text, text=True, capture_output=True, timeout=45)
        if check and result.returncode:
            raise RuntimeError(f'{command}\n{result.stdout}\n{result.stderr}')
        return result

    def app(command, *argv, ns=None):
        return run(binary, command, '--state-dir', str(state), *argv, ns=ns)

    def stop():
        nonlocal owner
        if owner:
            app('stop', ns=owner)
            app('stop', ns=owner)  # Idempotence.
            owner = None

    def apply(profile, ns):
        nonlocal owner
        path = work / 'profile.json'
        path.write_text(json.dumps(profile))
        owner = ns  # Retain namespace even if apply fails halfway.
        app('apply', '--profile', str(path), '--no-watchdog', ns=ns)

    def ping_rtt(address, count=6):
        result = run('ping', '-n', '-c', str(count), '-i', '0.05', '-W', '2', address, ns=client)
        match = re.search(r'= [\d.]+/([\d.]+)/', result.stdout)
        if not match:
            raise AssertionError(result.stdout)
        return float(match.group(1))

    echo_code = '''import socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",int(sys.argv[1])));s.listen()
while True:
 c,a=s.accept()
 with c:
  c.recv(32);c.sendall(a[0].encode())
'''

    def start_echo(ns, port):
        proc = subprocess.Popen(['ip', 'netns', 'exec', ns, 'python3', '-u', '-c', echo_code, str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        children.append(proc)
        time.sleep(0.25)
        if proc.poll() is not None:
            raise RuntimeError(proc.stderr.read().decode())

    def echo(ns, address, port):
        code = 'import socket,sys;s=socket.create_connection((sys.argv[1],int(sys.argv[2])),3);s.sendall(b"test");print(s.recv(128).decode());s.close()'
        return run('python3', '-c', code, address, str(port), ns=ns).stdout.strip()

    try:
        for ns in [client, router, server]:
            run('ip', 'netns', 'add', ns)
            created.append(ns)
            run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        for ns, side, subnet in [(client, 'left', '1'), (server, 'right', '2')]:
            run('ip', '-n', ns, 'link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', side)
            run('ip', '-n', ns, 'link', 'set', side, 'netns', router)
            for target, device, host in [(ns, 'eth0', '2'), (router, side, '1')]:
                run('ip', '-n', target, 'addr', 'add', f'10.203.{subnet}.{host}/24', 'dev', device)
                run('ip', '-n', target, '-6', 'addr', 'add', f'2001:db8:203:{subnet}::{host}/64', 'dev', device, 'nodad')
                run('ip', '-n', target, 'link', 'set', device, 'up')
            run('ip', '-n', ns, 'route', 'add', 'default', 'via', f'10.203.{subnet}.1')
            run('ip', '-n', ns, '-6', 'route', 'add', 'default', 'via', f'2001:db8:203:{subnet}::1')
        run('sysctl', '-q', '-w', 'net.ipv4.ip_forward=1', ns=router)
        run('sysctl', '-q', '-w', 'net.ipv6.conf.all.forwarding=1', ns=router)
        baseline = ping_rtt('10.203.2.2')
        baseline6 = ping_rtt('2001:db8:203:2::2')

        # Two independent directions; verify aggregate added RTT and port-22 bypass.
        start_echo(server, 22)
        host = {'version': 1, 'name': 'host-duplex', 'rules': [
            {'interface': 'eth0', 'direction': 'egress', 'match': {'destination': '10.203.2.2'}, 'impairment': {'delay': '80ms'}},
            {'interface': 'eth0', 'direction': 'ingress', 'match': {'source': '10.203.2.2'}, 'impairment': {'delay': '120ms'}},
        ]}
        apply(host, client)
        observed = ping_rtt('10.203.2.2') - baseline
        assert 160 < observed < 350, observed
        start = time.monotonic()
        assert echo(client, '10.203.2.2', 22) == '10.203.1.2'
        assert time.monotonic() - start < 0.15, 'SSH-port bypass failed or VM too overloaded'
        status = json.loads(app('status', '--json', ns=client).stdout)
        assert status['experiment']['phase'] == 'active'
        assert any(q.get('kind') == 'netem' and q.get('packets', 0) > 0 for qs in status['qdiscs'].values() for q in qs)
        stop()
        assert ping_rtt('10.203.2.2') - baseline < 40
        print('PASS ingress/egress delay, management bypass, counters, cleanup')

        v6 = {'version': 1, 'name': 'IPv6', 'rules': [{'interface': 'eth0', 'direction': 'ingress', 'match': {'source': '2001:db8:203:2::2'}, 'impairment': {'delay': '80ms'}}]}
        apply(v6, client)
        observed = ping_rtt('2001:db8:203:2::2') - baseline6
        assert 55 < observed < 180, observed
        stop()
        print('PASS IPv6 selection and IFB')

        jitter = {'version': 1, 'name': 'jitter', 'rules': [{'interface': 'eth0', 'direction': 'ingress', 'match': {'source': '10.203.2.2'}, 'impairment': {'delay': '80ms', 'jitter': '20ms', 'distribution': 'normal'}}]}
        apply(jitter, client)
        result = run('ping', '-n', '-c', '40', '-i', '0.05', '-W', '2', '10.203.2.2', ns=client)
        samples = [float(v) for v in re.findall(r'time=([\d.]+) ms', result.stdout)]
        assert len(samples) >= 35, result.stdout
        spread = statistics.stdev(samples)
        assert 5 < spread < 60, spread
        assert 45 < statistics.mean(samples) - baseline < 120, samples
        stop()
        print('PASS delay distribution and observed jitter')

        loss = {'version': 1, 'name': 'loss', 'rules': [{'interface': 'eth0', 'direction': 'egress', 'match': {'destination': '10.203.2.2', 'protocol': 'icmp'}, 'impairment': {'loss_percent': 30}}]}
        apply(loss, client)
        result = run('ping', '-n', '-c', '80', '-i', '0.02', '-W', '1', '10.203.2.2', ns=client, check=False)
        match = re.search(r'([\d.]+)% packet loss', result.stdout)
        assert match and 5 < float(match.group(1)) < 60, result.stdout
        stop()
        print('PASS statistical packet loss')

        # Scoped NAT, published TCP, rate limiting, and an unrelated table survive cleanup.
        sentinel = 'impair_sentinel_' + suffix
        run('nft', 'add', 'table', 'inet', sentinel, ns=router)
        gateway = {'version': 1, 'name': 'gateway', 'rules': [
            {'interface': 'right', 'direction': 'egress', 'match': {'family': 'ipv4', 'input_interface': 'left'}, 'impairment': {'rate': '4mbit', 'delay': '10ms'}},
            {'interface': 'left', 'direction': 'egress', 'match': {'family': 'ipv4', 'input_interface': 'right'}, 'impairment': {'delay': '10ms'}},
        ], 'gateway': {'inside': 'left', 'outside': 'right', 'client_cidr': '10.203.1.0/24', 'masquerade': True, 'publish': [{'protocol': 'tcp', 'listen_port': 8080, 'target': '10.203.1.2', 'target_port': 8081}]}}
        start_echo(server, 5555)
        start_echo(client, 8081)
        iperf = subprocess.Popen(['ip', 'netns', 'exec', server, 'iperf3', '-s'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        children.append(iperf)
        time.sleep(0.25)
        apply(gateway, router)
        assert echo(client, '10.203.2.2', 5555) == '10.203.2.1', 'masquerade failed'
        assert echo(server, '10.203.2.1', 8080) == '10.203.2.2', 'DNAT failed'
        rates = json.loads(run('iperf3', '-c', '10.203.2.2', '-t', '5', '-O', '1', '-J', ns=client).stdout)
        rate = rates['end']['sum_received']['bits_per_second']
        assert 2e6 < rate < 5e6, rate
        stop()
        run('nft', 'list', 'table', 'inet', sentinel, ns=router)
        assert ping_rtt('10.203.2.2') - baseline < 40
        print(f'PASS gateway NAT, published port, rate ({rate / 1e6:.2f} Mbit/s), unrelated-table preservation')
        print('All packet tests passed. Record kernel/AMI/architecture before claiming platform validation.')
    finally:
        try:
            stop()
        finally:
            for proc in children:
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
