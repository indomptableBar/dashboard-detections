import ipaddress
import os
import re
from datetime import datetime

SUSPICIOUS_PORTS = {
    21: 'FTP - Brute force / anonymous access',
    22: 'SSH - Brute force target',
    23: 'Telnet - Unencrypted protocol',
    25: 'SMTP - Spam relay',
    53: 'DNS - Tunneling / exfiltration',
    135: 'MSRPC - SMB / worm propagation',
    137: 'NetBIOS - Reconnaissance',
    139: 'NetBIOS - SMB',
    445: 'SMB - EternalBlue / ransomware',
    1433: 'MSSQL - Brute force',
    1521: 'Oracle - Brute force',
    3306: 'MySQL - Brute force',
    3389: 'RDP - BlueKeep / brute force',
    4848: 'GlassFish - Admin panel',
    4899: 'Radmin - Remote admin',
    5000: 'UPnP / Docker - Container escape',
    5432: 'PostgreSQL - Brute force',
    5900: 'VNC - Unencrypted remote access',
    5901: 'VNC - Remote access',
    5985: 'WinRM - PowerShell remoting',
    5986: 'WinRM - PowerShell remoting SSL',
    6379: 'Redis - Unauthorized access',
    8080: 'HTTP Proxy - Tunneling',
    8443: 'HTTPS Alt - C2 traffic',
    9100: 'Print Job - Printer exploit',
    9200: 'Elasticsearch - RCE',
    9300: 'Elasticsearch - Cluster comm',
    11211: 'Memcached - DDoS amplification',
    27017: 'MongoDB - Unauthorized access',
    31337: 'Back Orifice / elite',
    4444: 'Metasploit default / reverse shell',
    4445: 'Metasploit reverse HTTP',
    5555: 'Android ADB / Hydra',
    6666: 'IRC / malware C2',
    6667: 'IRC / malware C2',
    6668: 'IRC / malware C2',
    6670: 'DeepThroat trojan',
    6969: 'Backdoor / trojan',
    7000: 'Backdoor / Kazaa',
    7001: 'Backdoor / NetBus',
    7777: 'Backdoor / trojan',
    8000: 'Alternative HTTP / proxy',
    8001: 'Alternative HTTP / proxy',
    8443: 'Alternative HTTPS',
    8888: 'Alternative HTTP / C2',
    9001: 'Tor OR port / C2',
    9050: 'Tor SOCKS proxy',
    9051: 'Tor control port',
    10000: 'Webmin / backdoor',
    12345: 'NetBus trojan',
    12346: 'NetBus trojan',
    16660: 'Stacheldraht DDoS',
    20034: 'NetBus 2.0',
    27374: 'SubSeven trojan',
    31338: 'Back Orifice',
    45576: 'EternalRocks',
    47871: 'EternalRocks',
    49351: 'EternalRocks',
    65535: 'Generic backdoor',
}

SUSPICIOUS_PROCESS_NAMES = [
    'nc', 'ncat', 'netcat', 'nmap', 'zenmap', 'masscan', 'zmap',
    'hydra', 'medusa', 'john', 'hashcat', 'aircrack',
    'metasploit', 'msfconsole', 'msfvenom', 'msf',
    'sqlmap', 'sqlninja',
    'beef', 'beef-xss',
    'wireshark', 'tshark', 'tcpdump', 'ettercap', 'bettercap',
    'burpsuite', 'owasp-zap', 'nikto', 'wapiti',
    'socat', 'ncat', 'ncat',
    'cryptominer', 'minerd', 'xmrig', 'cpuminer', 'ccminer',
    'kbminer', 'ethminer', 'sgminer', 'bfgminer',
    'mimikatz', 'procdump', 'pwdump', 'fgdump',
    'shellter', 'veil', 'backdoor-factory',
    'stunnel', 'proxychains', 'connect-proxy',
    'tor', 'torify', 'torsocks',
    'chisel', 'frpc', 'frps', 'ngrok', 'serveo',
    'plink', 'putty', 'slogin',
    'powershell', 'pwsh',
    'crackmapexec', 'smbclient',
    'responder', 'impacket',
    'bloodhound', 'sharphound',
]

SUSPICIOUS_PROCESS_LOCATIONS = [
    '/tmp', '/dev/shm', '/var/tmp', '/run/shm',
    '/var/crash', '/var/tmp', '/dev',
]

SHELL_PROCESSES = {'bash', 'sh', 'zsh', 'dash', 'ksh', 'csh', 'tcsh', 'fish', 'ash'}
SCRIPT_INTERPRETERS = {'python', 'python3', 'perl', 'ruby', 'lua', 'php', 'node', 'nodejs', 'java'}

KNOWN_THREAT_IPS = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
]


def _is_private_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False


def _process_has_network_connection(pid, process_name, connections):
    for conn in connections:
        if conn['pid'] == pid:
            return True
    return False


def _check_suspicious_ports(ports):
    alerts = []
    seen_ports = set()
    for port_info in ports:
        port = port_info['port']
        if port in seen_ports:
            continue
        seen_ports.add(port)
        if port in SUSPICIOUS_PORTS:
            alerts.append({
                'severity': 'medium',
                'type': 'suspicious_port',
                'message': f"Port {port} ({SUSPICIOUS_PORTS[port]}) is LISTENING - process: {port_info['process']} (PID: {port_info['pid']})",
                'timestamp': datetime.now().isoformat(),
                'port': port,
                'protocol': port_info['protocol'],
                'process': port_info['process'],
                'pid': port_info['pid'],
            })
        elif port < 1024 and not port_info.get('process', '').lower() in ['systemd', 'sshd', 'nginx', 'apache2', 'httpd', 'named', 'mysqld', 'postgresql', 'postgres', 'cupsd', 'slapd', 'dhcpd', 'rpcbind', 'chronyd', 'ntpd', 'rsyslogd', 'saned', 'cups-browsed', 'avahi-daemon', 'bluetoothd', 'gdm3', 'lightdm', 'accounts-daemon', 'packagekitd', 'polkitd', 'udisksd', 'colord', 'upowerd', 'whoopsie', 'fwupd', 'rtkit-daemon', 'pipewire', 'wireplumber', 'dbus-daemon', 'dbus']:
            if port_info['process'] and port_info['pid']:
                alerts.append({
                    'severity': 'high',
                    'type': 'unknown_service_port',
                    'message': f"Unknown service on privileged port {port} - process: {port_info['process']} (PID: {port_info['pid']})",
                    'timestamp': datetime.now().isoformat(),
                    'port': port,
                    'protocol': port_info['protocol'],
                    'process': port_info['process'],
                    'pid': port_info['pid'],
                })
    return alerts


def _detect_reverse_shells(processes, connections):
    alerts = []
    for proc in processes:
        pid = proc['pid']
        name = proc['name'].lower()
        cmdline = proc.get('cmdline', '').lower()

        has_net = proc.get('has_network', False)
        if not has_net:
            for conn in connections:
                if conn['pid'] == pid:
                    has_net = True
                    break

        if not has_net:
            continue

        reverse_shell_indicators = [
            '/dev/tcp/', '/dev/udp/', '/dev/tcp', '/dev/udp',
            'bash -i', 'sh -i', 'zsh -i',
            'exec 5<>/dev/tcp', 'exec 5<>',
            'bash -c "exec', '/dev/tcp/',
            'sh -c "exec', 'zsh -c',
            'python -c "import', 'python -c \'import',
            'python3 -c "import', 'python3 -c \'import',
            'perl -e ', 'perl -MIO',
            'ruby -rsocket', 'ruby -e',
            'nc -e ', 'ncat -e ',
            'mkfifo /tmp', 'mknod /tmp',
            'socat ', 'ncat ',
            'ncat -l', 'nc -l', 'nc -lvp',
        ]

        for indicator in reverse_shell_indicators:
            if indicator in cmdline:
                alerts.append({
                    'severity': 'critical',
                    'type': 'reverse_shell',
                    'message': f"Reverse shell detected: {proc['name']} (PID: {pid}) - {proc.get('cmdline', '')[:150]}",
                    'timestamp': datetime.now().isoformat(),
                    'pid': pid,
                    'process': proc['name'],
                    'cmdline': proc.get('cmdline', ''),
                    'detection': indicator,
                })
                break

        if name in SHELL_PROCESSES:
            for conn in connections:
                if conn['pid'] == pid:
                    remote = conn.get('remote', '')
                    if remote and not remote.startswith('127.0.0.1') and not remote.startswith('::1') and not remote.startswith('0.0.0.0:') and conn.get('state') == 'ESTABLISHED':
                        alerts.append({
                            'severity': 'critical',
                            'type': 'interactive_shell_outbound',
                            'message': f"Shell ({name}) has outbound connection: {remote} (PID: {pid})",
                            'timestamp': datetime.now().isoformat(),
                            'pid': pid,
                            'process': proc['name'],
                            'remote': remote,
                        })
                        break

    return alerts


def _detect_malware_processes(processes):
    alerts = []
    for proc in processes:
        name = proc['name'].lower()
        cmdline = proc.get('cmdline', '').lower()
        exe_path = ''

        if cmdline:
            parts = cmdline.split()
            if parts:
                exe_path = parts[0]

        if name in [p.lower() for p in SUSPICIOUS_PROCESS_NAMES]:
            alerts.append({
                'severity': 'high',
                'type': 'suspicious_process',
                'message': f"Suspicious process detected: {proc['name']} (PID: {proc['pid']}) by {proc.get('user', '?')}",
                'timestamp': datetime.now().isoformat(),
                'pid': proc['pid'],
                'process': proc['name'],
                'user': proc.get('user', ''),
                'reason': 'Known hacking/malware tool',
            })
            continue

        for location in SUSPICIOUS_PROCESS_LOCATIONS:
            if exe_path.startswith(location) and exe_path not in ['']:
                alerts.append({
                    'severity': 'high',
                    'type': 'suspicious_location',
                    'message': f"Process running from suspicious location: {exe_path} (PID: {proc['pid']}, name: {proc['name']})",
                    'timestamp': datetime.now().isoformat(),
                    'pid': proc['pid'],
                    'process': proc['name'],
                    'path': exe_path,
                    'reason': f"Running from {location}",
                })
                break

        hidden_patterns = [r'^\.\w+', r'^\.{3,}']
        for pattern in hidden_patterns:
            if re.match(pattern, proc['name']):
                alerts.append({
                    'severity': 'medium',
                    'type': 'hidden_process',
                    'message': f"Hidden process name: {proc['name']} (PID: {proc['pid']})",
                    'timestamp': datetime.now().isoformat(),
                    'pid': proc['pid'],
                    'process': proc['name'],
                    'reason': 'Process name starts with hidden file pattern',
                })
                break

    return alerts


def _detect_malware_cron(proc, cron_jobs, name):
    alerts = []
    for job in cron_jobs:
        line = job['line'].lower()
        suspicious_cron_patterns = [
            '/tmp/', '/dev/shm/', '/var/tmp/',
            'wget ', 'curl ', 'fetch ',
            'python', 'bash -', 'sh -',
            'base64', 'chmod +x', 'chmod 777',
            '/dev/tcp/', '/dev/udp/',
            '> /dev/tcp/', '> /dev/udp/',
            'nc -e', 'ncat -e',
            'socat ',
            'mkfifo ', 'mknod ',
        ]
        for sp in suspicious_cron_patterns:
            if sp in line:
                alerts.append({
                    'severity': 'high',
                    'type': 'suspicious_cron',
                    'message': f"Suspicious cron job: {job['file']} - {job['line']}",
                    'timestamp': datetime.now().isoformat(),
                    'reason': f'Contains suspicious pattern: {sp}',
                    'file': job['file'],
                    'line': job['line'],
                })
                break
    return alerts


def _detect_suspicious_connections(connections):
    alerts = []
    for conn in connections:
        remote = conn.get('remote', '')
        if remote and not remote.startswith('0.0.0.0'):
            try:
                ip_part = remote.rsplit(':', 1)[0]
                if ip_part in ('127.0.0.1', '::1'):
                    continue
                if _is_private_ip(ip_part):
                    continue

                remote_port = 0
                try:
                    remote_port = int(remote.rsplit(':', 1)[1])
                except (ValueError, IndexError):
                    pass

                if remote_port in SUSPICIOUS_PORTS:
                    alerts.append({
                        'severity': 'high',
                        'type': 'suspicious_outbound',
                        'message': f"Outbound to suspicious port {remote_port} ({SUSPICIOUS_PORTS[remote_port]}) - {remote}",
                        'timestamp': datetime.now().isoformat(),
                        'remote': remote,
                        'port': remote_port,
                        'process': conn.get('process', ''),
                        'pid': conn.get('pid', 0),
                        'reason': f"Connection to suspicious port {remote_port}",
                    })
                    continue

                if conn.get('state') == 'ESTABLISHED' and conn.get('process', '').lower() not in ['', 'systemd', 'ssh', 'sshd', 'dhclient', 'systemd-resolve', 'systemd-timesyn', 'chronyd', 'ntpd', 'dbus-daemon', 'dbus', 'pipewire', 'wireplumber', 'avahi-daemon']:
                    if conn.get('process', '').lower() in SUSPICIOUS_PROCESS_NAMES:
                        alerts.append({
                            'severity': 'critical',
                            'type': 'malware_communication',
                            'message': f"Suspicious process {conn.get('process', '')} (PID: {conn.get('pid', 0)}) has established connection to {remote}",
                            'timestamp': datetime.now().isoformat(),
                            'remote': remote,
                            'process': conn.get('process', ''),
                            'pid': conn.get('pid', 0),
                            'reason': "Process is a known hacking tool",
                        })

            except Exception:
                pass

    return alerts


def _check_anomalous_processes(processes):
    alerts = []
    proc_count_by_name = {}
    for proc in processes:
        name = proc['name']
        proc_count_by_name[name] = proc_count_by_name.get(name, 0) + 1

    for name, count in proc_count_by_name.items():
        if count > 20 and name not in ['systemd', 'kworker', 'kthreadd', 'khelper', 'ksoftirqd', 'migration']:
            alerts.append({
                'severity': 'medium',
                'type': 'process_fork_bomb',
                'message': f"Anomalous process count: {count} instances of '{name}' - possible fork bomb or persistence",
                'timestamp': datetime.now().isoformat(),
                'process': name,
                'count': count,
                'reason': f"More than 20 instances of same process",
            })

    return alerts


def _check_malware_files():
    alerts = []
    suspicious_files = [
        '/tmp/.systemd', '/tmp/.dbus', '/tmp/.X11-unix',
        '/tmp/.ICE-unix', '/tmp/.fonts',
        '/dev/shm/.systemd', '/dev/shm/.dbus',
        '/var/tmp/.systemd', '/var/tmp/.dbus',
    ]
    for path in suspicious_files:
        if os.path.isfile(path):
            try:
                size = os.path.getsize(path)
                alerts.append({
                    'severity': 'high',
                    'type': 'suspicious_file',
                    'message': f"Suspicious file found: {path} ({size} bytes)",
                    'timestamp': datetime.now().isoformat(),
                    'path': path,
                    'size': size,
                    'reason': 'Known malware persistence location',
                })
            except OSError:
                pass
    return alerts


def analyze(data):
    alerts = []
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    alerts.extend(_check_suspicious_ports(data.get('ports', [])))
    alerts.extend(_detect_reverse_shells(data.get('processes', []), data.get('connections', [])))
    alerts.extend(_detect_malware_processes(data.get('processes', [])))
    alerts.extend(_detect_suspicious_connections(data.get('connections', [])))
    alerts.extend(_check_anomalous_processes(data.get('processes', [])))
    alerts.extend(_check_malware_files())
    alerts.extend(_detect_malware_cron(None, data.get('cron_jobs', []), None))

    if data.get('secure_boot') == 'disabled':
        alerts.append({
            'severity': 'high',
            'type': 'secure_boot_disabled',
            'message': 'Secure Boot is DISABLED - system is vulnerable to boot-level attacks',
            'timestamp': datetime.now().isoformat(),
            'reason': 'Secure Boot provides boot-time integrity checking',
        })

    if data.get('secure_boot') == 'unknown':
        alerts.append({
            'severity': 'low',
            'type': 'secure_boot_unknown',
            'message': 'Secure Boot status could not be determined',
            'timestamp': datetime.now().isoformat(),
            'reason': 'mokutil and bootctl not available',
        })

    for alert in alerts:
        sev = alert.get('severity', 'low')
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        'alerts': alerts,
        'severity_counts': severity_counts,
        'total_alerts': len(alerts),
        'scan_time': datetime.now().isoformat(),
    }


def get_risk_score(alerts):
    if not alerts:
        return 0
    weights = {'critical': 10, 'high': 5, 'medium': 2, 'low': 0.5}
    score = sum(weights.get(a.get('severity', 'low'), 0) for a in alerts)
    return min(100, round(score / max(len(alerts), 1) * 10, 1))


def get_summary(alerts):
    types = {}
    for alert in alerts:
        atype = alert.get('type', 'unknown')
        if atype not in types:
            types[atype] = 0
        types[atype] += 1
    return {
        'by_type': types,
        'risk_score': get_risk_score(alerts),
    }
