const SUSPICIOUS_PORTS = {
  21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',135:'MSRPC',137:'NetBIOS',
  139:'NetBIOS',445:'SMB',1433:'MSSQL',1521:'Oracle',3306:'MySQL',3389:'RDP',
  4848:'GlassFish',4899:'Radmin',5000:'UPnP',5432:'PostgreSQL',5900:'VNC',
  5901:'VNC',5985:'WinRM',5986:'WinRM',6379:'Redis',8080:'HTTP Proxy',
  8443:'HTTPS Alt',9100:'Print',9200:'Elasticsearch',9300:'ES Cluster',
  11211:'Memcached',27017:'MongoDB',31337:'BackOrifice',4444:'Metasploit',
  4445:'MSF HTTP',5555:'ADB/Hydra',6666:'IRC C2',6667:'IRC C2',6668:'IRC C2',
  6670:'DeepThroat',6969:'Backdoor',7000:'Backdoor',7001:'NetBus',
  7777:'Trojan',8000:'Alt HTTP',8001:'Alt HTTP',8888:'C2 HTTP',
  9001:'Tor/C2',9050:'Tor SOCKS',9051:'Tor Ctrl',10000:'Webmin',
  12345:'NetBus',12346:'NetBus',16660:'DDoS',20034:'NetBus 2.0',
  27374:'SubSeven',31338:'BackOrifice',45576:'EternalRocks',
  47871:'EternalRocks',49351:'EternalRocks',65535:'Backdoor'
};

const SUSPICIOUS_PROCESSES = [
  'nc','ncat','netcat','nmap','zenmap','masscan','zmap','hydra','medusa',
  'john','hashcat','aircrack','metasploit','msfconsole','msfvenom',
  'sqlmap','beef','wireshark','tshark','tcpdump','ettercap','bettercap',
  'burpsuite','owasp-zap','nikto','socat','xmrig','minerd','cpuminer',
  'ccminer','ethminer','mimikatz','procdump','pwdump','shellter','veil',
  'chisel','frpc','frps','ngrok','crackmapexec','responder','impacket',
  'bloodhound','stunnel','proxychains'
];

let dataCache = null;
let currentFilter = 'all';

function $(id) { return document.getElementById(id); }

function toggleCard(header) {
  const card = header.closest('.card');
  card.classList.toggle('collapsed');
}

function toggleAllCards() {
  const cards = document.querySelectorAll('.card');
  const anyOpen = Array.from(cards).some(c => !c.classList.contains('collapsed'));
  cards.forEach(c => c.classList.toggle('collapsed', anyOpen));
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  let i = 0, val = bytes;
  while (val >= 1024 && i < units.length-1) { val /= 1024; i++; }
  return val.toFixed(1) + ' ' + units[i];
}

function formatTime(ts) {
  if (!ts) return '--';
  try { return new Date(ts).toLocaleTimeString(); } catch(e) { return ts; }
}

function getSeverityClass(sev) {
  return 'severity ' + (sev || 'low');
}

function isSuspiciousPort(port) {
  return SUSPICIOUS_PORTS[port] || null;
}

function isSuspiciousProcess(name) {
  return SUSPICIOUS_PROCESSES.includes((name||'').toLowerCase());
}

function updateStats(data) {
  const s = data.system || {};
  const ac = data.severity_counts || {};
  const total = data.total_alerts || 0;

  const stats = [
    { cls:'alerts', val:total, label:'Total Alerts' },
    { cls:'risk', val:data.risk_score || 0, label:'Risk Score' },
    { cls:'ports', val:(data.ports||[]).length, label:'Listening Ports' },
    { cls:'procs', val:(data.processes||[]).length, label:'Processes' },
    { cls:'connections', val:(data.connections||[]).length, label:'Connections' },
    { cls:'malware', val:(data.core_dumps||[]).length + (ac.critical||0) + (ac.high||0), label:'Threats Detected' },
    { cls:'cpu', val:(s.cpu_percent||0).toFixed(1) + '%', label:'CPU' },
    { cls:'memory', val:(s.memory||{}).percent ? (s.memory.percent.toFixed(1)+'%') : '0%', label:'Memory' },
    { cls:'disk', val:(s.disk||{}).percent ? (s.disk.percent.toFixed(1)+'%') : '0%', label:'Disk' },
  ];

  $('statsRow').innerHTML = stats.map(st =>
    `<div class="stat-card ${st.cls}"><div class="stat-value">${st.val}</div><div class="stat-label">${st.label}</div></div>`
  ).join('');
}

function updateSystemInfo(data) {
  const s = data.system || {};
  const mem = s.memory || {};
  const disk = s.disk || {};
  const load = s.load || {};
  const items = [
    { label:'Hostname', value:s.hostname || '--' },
    { label:'OS', value:s.os || '--' },
    { label:'Uptime', value:s.uptime || '--' },
    { label:'CPU', value:(s.cpu_percent||0).toFixed(1) + '%' },
    { label:'Memory', value:formatBytes(mem.used) + ' / ' + formatBytes(mem.total) + ' (' + (mem.percent||0).toFixed(1) + '%)' },
    { label:'Disk', value:formatBytes(disk.used) + ' / ' + formatBytes(disk.total) + ' (' + (disk.percent||0).toFixed(1) + '%)' },
    { label:'Load', value:(load['1min']||0).toFixed(2) + ' / ' + (load['5min']||0).toFixed(2) + ' / ' + (load['15min']||0).toFixed(2) },
    { label:'Processes', value:(load.running||0) + ' running / ' + (load.total||0) + ' total' },
  ];

  $('systemInfo').innerHTML = items.map(item =>
    `<div class="info-item"><div class="info-label">${item.label}</div><div class="info-value">${item.value}</div></div>`
  ).join('');

  $('hostDisplay').textContent = s.hostname || '--';
  $('osDisplay').textContent = s.os || '--';

  const sb = s.secure_boot || 'unknown';
  const sbEl = $('secureBootBadge');
  sbEl.className = 'secure-boot-badge ' + sb;
  sbEl.textContent = 'Secure Boot: ' + sb.charAt(0).toUpperCase() + sb.slice(1);

  if (data.scan_time) $('scanTimestamp').textContent = 'Last scan: ' + formatTime(data.scan_time);
}

function updateAlerts(data) {
  const alerts = data.alerts || [];
  const filtered = currentFilter === 'all' ? alerts : alerts.filter(a => a.severity === currentFilter);

  $('alertsBadge').textContent = alerts.length;
  $('alertsBadge').className = 'badge ' + (alerts.length > 0 ? (data.risk_score > 50 ? 'critical' : data.risk_score > 25 ? 'danger' : 'warning') : 'success');

  if (filtered.length === 0) {
    $('alertsBody').innerHTML = '';
    $('alertsEmpty').style.display = 'block';
  } else {
    $('alertsEmpty').style.display = 'none';
    $('alertsBody').innerHTML = filtered.map(a =>
      `<tr class="row-${a.severity}">
        <td><span class="${getSeverityClass(a.severity)}">${a.severity}</span></td>
        <td><span class="alert-type">${a.type}</span></td>
        <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis">${escHtml(a.message)}</td>
        <td>${formatTime(a.timestamp)}</td>
      </tr>`
    ).join('');
  }

  if (data.scan_time) $('alertsTimestamp').textContent = 'Updated: ' + formatTime(data.scan_time);
}

function updateRiskCircle(data) {
  const score = data.risk_score || 0;
  const circle = $('riskCircle');
  circle.textContent = score;
  let level = 'low';
  if (score >= 75) level = 'critical';
  else if (score >= 50) level = 'high';
  else if (score >= 25) level = 'medium';
  circle.className = 'risk-circle ' + level;

  const badge = $('riskBadge');
  badge.textContent = score;
  badge.className = 'badge ' + level;

  const ac = data.severity_counts || {};
  $('countCritical').textContent = ac.critical || 0;
  $('countHigh').textContent = ac.high || 0;
  $('countMedium').textContent = ac.medium || 0;
  $('countLow').textContent = ac.low || 0;
}

function updatePorts(data) {
  const ports = data.ports || [];
  $('portsBadge').textContent = ports.length;

  if (ports.length === 0) {
    $('portsBody').innerHTML = '';
    $('portsEmpty').style.display = 'block';
    return;
  }
  $('portsEmpty').style.display = 'none';

  ports.sort((a,b) => a.port - b.port);
  const suspiciousList = Object.keys(SUSPICIOUS_PORTS).map(Number);

  $('portsBody').innerHTML = ports.map(p => {
    const sp = isSuspiciousPort(p.port);
    const isSusp = sp !== null;
    const procSusp = isSuspiciousProcess(p.process);
    return `<tr class="${isSusp||procSusp?'row-high':''}">
      <td style="font-weight:${isSusp?'700':'400'};color:${isSusp?'var(--danger)':'var(--accent)'}">${p.port}</td>
      <td>${p.protocol || 'TCP'}</td>
      <td class="${procSusp?'proc-suspicious':(p.process?'proc-normal':'proc-unknown')}">${escHtml(p.process || '?')}</td>
      <td>${p.pid || '?'}</td>
      <td>${escHtml(p.user || '?')}</td>
      <td>${isSusp ? '<span class="severity high">'+sp+'</span>' : (procSusp ? '<span class="severity medium">Known tool</span>' : '<span class="severity low">OK</span>')}</td>
    </tr>`;
  }).join('');
}

function updateConnections(data) {
  const conns = data.connections || [];
  $('connectionsBadge').textContent = conns.length;

  if (conns.length === 0) {
    $('connectionsBody').innerHTML = '';
    $('connectionsEmpty').style.display = 'block';
    return;
  }
  $('connectionsEmpty').style.display = 'none';

  conns.sort((a,b) => (a.remote || '') > (b.remote || '') ? 1 : -1);

  $('connectionsBody').innerHTML = conns.map(c => {
    const procSusp = isSuspiciousProcess(c.process);
    const country = c.country || 'Unknown';
    const code = (c.country_code || '').toUpperCase();
    let flag = '';
    if (code && code.length === 2) {
      const cp1 = 0x1F1E6 + code.charCodeAt(0) - 65;
      const cp2 = 0x1F1E6 + code.charCodeAt(1) - 65;
      if (cp1 >= 0x1F1E6 && cp1 <= 0x1F1FF && cp2 >= 0x1F1E6 && cp2 <= 0x1F1FF) {
        flag = String.fromCodePoint(cp1) + String.fromCodePoint(cp2) + ' ';
      }
    }
    const isLocal = country === 'Private' || country === 'Loopback' || country === 'Link-local';
    const countryHtml = isLocal
      ? '<span style="color:var(--text-muted)">' + escHtml(country) + '</span>'
      : '<span style="color:var(--accent)">' + flag + escHtml(country) + '</span>';
    return `<tr class="${procSusp?'row-critical':''}">
      <td>${escHtml(c.local || '')}</td>
      <td>${escHtml(c.remote || '')}</td>
      <td>${countryHtml}</td>
      <td>${escHtml(c.state || '')}</td>
      <td class="${procSusp?'proc-suspicious':''}">${escHtml(c.process || '')}</td>
      <td>${c.pid || 0}</td>
    </tr>`;
  }).join('');
}

function updateProcesses(data) {
  const procs = data.processes || [];
  $('processesBadge').textContent = procs.length;

  if (procs.length === 0) {
    $('processesBody').innerHTML = '';
    $('processesEmpty').style.display = 'block';
    return;
  }
  $('processesEmpty').style.display = 'none';

  const sorted = [...procs].sort((a,b) => (b.cpu||0) - (a.cpu||0) || (b.memory||0) - (a.memory||0)).slice(0, 200);

  $('processesBody').innerHTML = sorted.map(p => {
    const susp = isSuspiciousProcess(p.name);
    return `<tr class="${susp?'row-high':''}">
      <td>${p.pid}</td>
      <td class="${susp?'proc-suspicious':''}">${escHtml(p.name)}</td>
      <td>${escHtml(p.user || '')}</td>
      <td>${(p.cpu||0).toFixed(1)}</td>
      <td>${(p.memory||0).toFixed(1)}</td>
      <td>${p.has_network ? '<span style="color:var(--warning)">Yes</span>' : '<span style="color:var(--text-muted)">No</span>'}</td>
      <td>${susp ? '<span class="severity high">Suspicious</span>' : '<span class="severity low">Normal</span>'}</td>
    </tr>`;
  }).join('');
}

function updateDumps(data) {
  const dumps = data.core_dumps || [];
  const alerts = data.alerts || [];
  const suspiciousFiles = alerts.filter(a => a.type === 'suspicious_file').map(a => ({
    path: a.path,
    type: 'Suspicious File',
    size: a.size || 0,
    risk: a.severity
  }));

  const items = [
    ...dumps.map(d => ({ path: d.path, type: 'Core Dump', size: d.size, risk: 'medium' })),
    ...suspiciousFiles
  ];

  $('dumpsBadge').textContent = items.length;

  if (items.length === 0) {
    $('dumpsBody').innerHTML = '';
    $('dumpsEmpty').style.display = 'block';
    return;
  }
  $('dumpsEmpty').style.display = 'none';

  $('dumpsBody').innerHTML = items.map(item =>
    `<tr>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">${escHtml(item.path)}</td>
      <td>${item.type}</td>
      <td>${formatBytes(item.size)}</td>
      <td><span class="severity ${item.risk}">${item.risk}</span></td>
    </tr>`
  ).join('');
}

function updateModules(data) {
  const mods = data.kernel_modules || [];
  $('modulesBadge').textContent = mods.length;

  if (mods.length === 0) {
    $('modulesList').innerHTML = '';
    $('modulesEmpty').style.display = 'block';
    return;
  }
  $('modulesEmpty').style.display = 'none';

  const suspiciousMods = ['hide_proc','rootkit','kbeast','adore','hide_kmem','knark','modhide','suterusu'];
  $('modulesList').innerHTML = mods.map(m => {
    const susp = suspiciousMods.includes(m.toLowerCase());
    return `<span style="display:inline-block;padding:3px 8px;margin:3px;background:${susp?'var(--danger-dim)':'var(--bg-input)'};border:1px solid ${susp?'var(--danger)':'var(--border-color)'};border-radius:3px;font-family:var(--font-mono);font-size:11px;color:${susp?'var(--danger)':'var(--text-primary)'}">${escHtml(m)}${susp?' [ROOTKIT]':''}</span>`;
  }).join('');
}

function updateInterfaces(data) {
  const ifaces = data.interfaces || [];
  $('ifacesBadge').textContent = ifaces.length;

  if (ifaces.length === 0) {
    $('ifacesList').innerHTML = '';
    $('ifacesEmpty').style.display = 'block';
    return;
  }
  $('ifacesEmpty').style.display = 'none';

  $('ifacesList').innerHTML = ifaces.map(iface =>
    `<div class="iface-card">
      <div class="iface-name">${escHtml(iface.name)}</div>
      <div class="iface-traffic">&#8593; ${formatBytes(iface.tx_bytes)} &#8595; ${formatBytes(iface.rx_bytes)}</div>
    </div>`
  ).join('');
}

function updateAlertFilters(data) {
  const sevs = data.severity_counts || {};
  const total = data.total_alerts || 0;
  const filters = [
    { key:'all', label:'All ('+total+')' },
    { key:'critical', label:'Critical ('+(sevs.critical||0)+')' },
    { key:'high', label:'High ('+(sevs.high||0)+')' },
    { key:'medium', label:'Medium ('+(sevs.medium||0)+')' },
    { key:'low', label:'Low ('+(sevs.low||0)+')' },
  ];

  $('alertFilters').innerHTML = filters.map(f =>
    `<button class="filter-chip ${f.key} ${currentFilter===f.key?'active':''}" onclick="setFilter('${f.key}')">${f.label}</button>`
  ).join('');
}

function setFilter(sev) {
  currentFilter = sev;
  if (dataCache) updateAlerts(dataCache);
  updateAlertFilters(dataCache);
}

function escHtml(str) {
  if (!str) return '';
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

function updateDashboard(data) {
  dataCache = data;
  updateSystemInfo(data);
  updateStats(data);
  updateAlerts(data);
  updateRiskCircle(data);
  updatePorts(data);
  updateConnections(data);
  updateProcesses(data);
  updateDumps(data);
  updateModules(data);
  updateInterfaces(data);
  updateAlertFilters(data);
}

async function fetchData() {
  try {
    const resp = await fetch('/api/status');
    const data = await resp.json();

    if (data._error) {
      console.warn('Collector error:', data._error);
    }

    $('loading').style.display = 'none';
    $('dashboard').style.display = 'block';

    updateDashboard(data);
  } catch (err) {
    console.error('Fetch error:', err);
    setTimeout(() => {
      $('loading').innerHTML = `
        <div class="loading-spinner"></div>
        <span>Connection error — retrying...</span>
      `;
    }, 1000);
  }
}

setInterval(fetchData, 5000);
fetchData();
