import os
import pwd
import subprocess
import socket
import struct
import time
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def get_hostname():
    return socket.gethostname()


def get_uptime():
    try:
        with open('/proc/uptime') as f:
            uptime_seconds = float(f.read().split()[0])
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return f"{days}d {hours}h {minutes}m"
    except Exception:
        return "N/A"


def get_os_info():
    try:
        with open('/etc/os-release') as f:
            info = {}
            for line in f:
                if '=' in line:
                    k, v = line.strip().split('=', 1)
                    info[k] = v.strip('"')
        return info.get('PRETTY_NAME', info.get('NAME', 'Linux'))
    except Exception:
        return "Debian GNU/Linux"


def get_cpu_percent():
    if HAS_PSUTIL:
        return psutil.cpu_percent(interval=0.5)
    try:
        with open('/proc/stat') as f:
            line = f.readline().strip().split()
        total = sum(int(x) for x in line[1:])
        idle = int(line[4])
        time.sleep(0.3)
        with open('/proc/stat') as f:
            line = f.readline().strip().split()
        total2 = sum(int(x) for x in line[1:])
        idle2 = int(line[4])
        return round(100 * (1 - (idle2 - idle) / (total2 - total)), 1)
    except Exception:
        return 0.0


def get_memory_info():
    if HAS_PSUTIL:
        mem = psutil.virtual_memory()
        return {
            'total': mem.total,
            'available': mem.available,
            'percent': mem.percent,
            'used': mem.used,
            'free': mem.free
        }
    try:
        with open('/proc/meminfo') as f:
            meminfo = {}
            for line in f:
                if ':' in line:
                    k, v = line.split(':', 1)
                    meminfo[k.strip()] = int(v.strip().split()[0]) * 1024
        total = meminfo.get('MemTotal', 0)
        available = meminfo.get('MemAvailable', 0)
        used = total - available
        percent = round((used / total) * 100, 1) if total else 0
        return {
            'total': total,
            'available': available,
            'percent': percent,
            'used': used,
            'free': meminfo.get('MemFree', 0)
        }
    except Exception:
        return {'total': 0, 'available': 0, 'percent': 0, 'used': 0, 'free': 0}


def get_disk_info():
    if HAS_PSUTIL:
        disk = psutil.disk_usage('/')
        return {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent
        }
    try:
        st = os.statvfs('/')
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bfree
        used = total - free
        percent = round((used / total) * 100, 1) if total else 0
        return {'total': total, 'used': used, 'free': free, 'percent': percent}
    except Exception:
        return {'total': 0, 'used': 0, 'free': 0, 'percent': 0}


def _read_proc_net(proto='tcp'):
    proc_file = f'/proc/net/{proto}'
    connections = []
    try:
        with open(proc_file) as f:
            f.readline()
            for line in f:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                local_addr, local_port = parts[1].split(':')
                rem_addr, rem_port = parts[2].split(':')
                state = int(parts[3], 16)
                uid = int(parts[7])
                inode = int(parts[9])

                local_ip = socket.inet_ntop(
                    socket.AF_INET if proto in ('tcp', 'udp') else socket.AF_INET6,
                    struct.pack('<I', int(local_addr, 16))
                ) if proto in ('tcp', 'udp') else local_addr
                local_port_dec = int(local_port, 16)

                remote_ip = '0.0.0.0'
                remote_port_dec = 0
                if rem_addr != '00000000':
                    remote_ip = socket.inet_ntop(
                        socket.AF_INET if proto in ('tcp', 'udp') else socket.AF_INET6,
                        struct.pack('<I', int(rem_addr, 16))
                    )
                    remote_port_dec = int(rem_port, 16)

                connections.append({
                    'local_ip': local_ip,
                    'local_port': local_port_dec,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port_dec,
                    'state': state,
                    'uid': uid,
                    'inode': inode,
                    'protocol': proto.upper()
                })
    except Exception:
        pass
    return connections


TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV",
    4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
    7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK",
    10: "LISTEN", 11: "CLOSING"
}


def get_connections():
    if HAS_PSUTIL:
        result = []
        for conn in psutil.net_connections(kind='inet'):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                pname = proc.name() if proc else ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = ""
            result.append({
                'local': laddr,
                'remote': raddr,
                'state': conn.status,
                'pid': conn.pid or 0,
                'process': pname,
                'type': conn.type,
                'family': conn.family
            })
        return result

    result = []
    for proto in ('tcp', 'tcp6'):
        for c in _read_proc_net(proto):
            local = f"{c['local_ip']}:{c['local_port']}"
            remote = f"{c['remote_ip']}:{c['remote_port']}"
            state_str = TCP_STATES.get(c['state'], f"UNKNOWN({c['state']})")
            proc_name, pid = '', 0
            try:
                for p in Path('/proc').iterdir():
                    if p.name.isdigit() and (p / 'fd').exists():
                        try:
                            for fd in p.iterdir():
                                try:
                                    link = os.readlink(str(fd))
                                    if f"socket:[{c['inode']}]" in link:
                                        pid = int(p.name)
                                        with open(p / 'comm') as cf:
                                            proc_name = cf.read().strip()
                                        break
                                except (OSError, ValueError):
                                    pass
                        except PermissionError:
                            pass
            except Exception:
                pass
            result.append({
                'local': local,
                'remote': remote,
                'state': state_str,
                'pid': pid,
                'process': proc_name,
                'type': socket.SOCK_STREAM,
                'family': socket.AF_INET6 if proto.endswith('6') else socket.AF_INET
            })
    return result


def get_listening_ports():
    if HAS_PSUTIL:
        ports = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                proc = psutil.Process(conn.pid) if conn.pid else None
                ports.append({
                    'port': conn.laddr.port,
                    'protocol': 'TCP',
                    'process': proc.name() if proc else '',
                    'pid': conn.pid or 0,
                    'user': proc.username() if proc else '',
                })
        return ports

    result = []
    for c in _read_proc_net('tcp'):
        if c['state'] == 10:
            proc_name, pid = '', 0
            try:
                for p in Path('/proc').iterdir():
                    if p.name.isdigit() and (p / 'fd').exists():
                        try:
                            for fd in p.iterdir():
                                try:
                                    link = os.readlink(str(fd))
                                    if f"socket:[{c['inode']}]" in link:
                                        pid = int(p.name)
                                        with open(p / 'comm') as cf:
                                            proc_name = cf.read().strip()
                                        break
                                except (OSError, ValueError):
                                    pass
                        except PermissionError:
                            pass
            except Exception:
                pass
            result.append({
                'port': c['local_port'],
                'protocol': 'TCP',
                'process': proc_name,
                'pid': pid,
                'user': '',
            })
    return result


def get_processes():
    if HAS_PSUTIL:
        procs = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username', 'cmdline', 'create_time']):
            try:
                pinfo = proc.info
                has_net = False
                try:
                    has_net = len(proc.net_connections()) > 0
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                procs.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu': round(pinfo['cpu_percent'] or 0, 1),
                    'memory': round(pinfo['memory_percent'] or 0, 1),
                    'user': pinfo['username'] or '',
                    'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else '',
                    'created': pinfo['create_time'],
                    'has_network': has_net
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs

    procs = []
    try:
        for p in sorted(Path('/proc').iterdir(), key=lambda x: x.name if x.name.isdigit() else '0'):
            if not p.name.isdigit():
                continue
            try:
                with open(p / 'status') as f:
                    status = {}
                    for line in f:
                        if ':' in line:
                            k, v = line.split(':', 1)
                            status[k.strip()] = v.strip()
                with open(p / 'comm') as f:
                    name = f.read().strip()
                pid = int(p.name)
                user = ''
                try:
                    uid = int(status.get('Uid', '0').split('\t')[0])
                    user = pwd.getpwuid(uid).pw_name
                except Exception:
                    user = str(uid) if 'uid' in dir() else '?'

                cmdline = ''
                try:
                    with open(p / 'cmdline') as f:
                        cmdline = f.read().replace('\0', ' ').strip()
                except Exception:
                    pass

                procs.append({
                    'pid': pid,
                    'name': name,
                    'cpu': 0.0,
                    'memory': 0.0,
                    'user': user,
                    'cmdline': cmdline,
                    'created': 0,
                    'has_network': False
                })
            except (PermissionError, FileNotFoundError, ValueError):
                pass
    except Exception:
        pass
    return procs


def get_secure_boot_status():
    try:
        result = subprocess.run(
            ['mokutil', '--sb-state'],
            capture_output=True, text=True, timeout=5
        )
        if 'enabled' in result.stdout.lower():
            return 'enabled'
        elif 'disabled' in result.stdout.lower():
            return 'disabled'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        result = subprocess.run(
            ['bootctl', 'status'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'secure boot' in line.lower():
                return 'enabled' if 'enabled' in line.lower() else 'disabled'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        with open('/sys/kernel/security/secureboot') as f:
            val = f.read().strip()
            return 'enabled' if val == '1' else 'disabled'
    except Exception:
        pass
    return 'unknown'


def get_core_dumps():
    dumps = []
    dump_paths = [
        '/var/crash',
        '/var/lib/systemd/coredump',
        '/var/crash',
    ]
    for path in dump_paths:
        p = Path(path)
        if p.exists():
            for f in p.iterdir():
                if f.is_file() and not f.name.startswith('.'):
                    try:
                        stat_info = f.stat()
                        dumps.append({
                            'path': str(f),
                            'size': stat_info.st_size,
                            'modified': stat_info.st_mtime,
                            'name': f.name
                        })
                    except OSError:
                        pass
    return dumps


def get_cron_jobs():
    jobs = []
    cron_paths = [
        '/var/spool/cron/crontabs',
        '/etc/crontab',
        '/etc/cron.d',
    ]
    for path in cron_paths:
        p = Path(path)
        try:
            if p.exists():
                if p.is_file():
                    try:
                        with open(p) as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#') and not line.startswith('SHELL') and not line.startswith('PATH'):
                                    jobs.append({'file': str(p), 'line': line})
                    except (PermissionError, IOError):
                        pass
                elif p.is_dir():
                    try:
                        for f in p.iterdir():
                            if f.is_file():
                                try:
                                    content = f.read_text().strip()
                                    if content:
                                        jobs.append({'file': str(f), 'line': content.split('\n')[0]})
                                except (PermissionError, IOError):
                                    pass
                    except PermissionError:
                        pass
        except PermissionError:
            pass
    return jobs


def get_kernel_modules():
    modules = []
    try:
        with open('/proc/modules') as f:
            for line in f:
                parts = line.strip().split()
                if parts:
                    modules.append(parts[0])
    except Exception:
        pass
    return modules


def get_system_load():
    try:
        with open('/proc/loadavg') as f:
            parts = f.read().strip().split()
        return {
            '1min': float(parts[0]),
            '5min': float(parts[1]),
            '15min': float(parts[2]),
            'running': int(parts[3].split('/')[0]),
            'total': int(parts[3].split('/')[1])
        }
    except Exception:
        return {'1min': 0, '5min': 0, '15min': 0, 'running': 0, 'total': 0}


def get_network_interfaces():
    ifaces = []
    try:
        with open('/proc/net/dev') as f:
            f.readline()
            f.readline()
            for line in f:
                parts = line.strip().split()
                iface = parts[0].rstrip(':')
                rx_bytes = int(parts[1])
                tx_bytes = int(parts[9])
                ifaces.append({
                    'name': iface,
                    'rx_bytes': rx_bytes,
                    'tx_bytes': tx_bytes
                })
    except Exception:
        pass
    return ifaces


def collect_all(with_psutil=None):
    global HAS_PSUTIL
    if with_psutil is not None:
        HAS_PSUTIL = with_psutil

    return {
        'hostname': get_hostname(),
        'uptime': get_uptime(),
        'os': get_os_info(),
        'cpu_percent': get_cpu_percent(),
        'memory': get_memory_info(),
        'disk': get_disk_info(),
        'load': get_system_load(),
        'interfaces': get_network_interfaces(),
        'secure_boot': get_secure_boot_status(),
        'ports': get_listening_ports(),
        'connections': get_connections(),
        'processes': get_processes(),
        'core_dumps': get_core_dumps(),
        'cron_jobs': get_cron_jobs(),
        'kernel_modules': get_kernel_modules(),
    }
