/* PEGASUS SUITE — field recon frontend.
 * English only. No login, no user identity.
 * Discovery runs through the on-device native plugins when available
 * (PhoneScanner / WiFiCracker / CellTower) and through the Pegasus backend
 * on the same LAN for deeper subnet probing. CSP-safe: no inline code. */
'use strict';

(function () {
  const $ = (id) => document.getElementById(id);

  /* ---------------- config / backend base ---------------- */
  const CFG = window.__PEGASUS_CONFIG__ || {};
  const LS_KEY = 'pegasus_api_base';
  const cfgBase = String(CFG.apiBaseUrl || '').trim().replace(/\/+$/, '');

  function resolveBase() {
    const saved = (localStorage.getItem(LS_KEY) || '').trim().replace(/\/+$/, '');
    return saved || cfgBase;
  }
  function apiUrl(path) {
    const b = resolveBase();
    return b ? b + '/api' + path : '/api' + path;
  }

  async function api(path, { method = 'GET', body, timeout = 30000 } = {}) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetch(apiUrl(path), Object.assign({ signal: ctrl.signal }, opts));
      let data = {};
      try { data = await res.json(); } catch (_) { /* empty body */ }
      if (!res.ok) {
        const msg = (data && data.error && data.error.message) || ('HTTP ' + res.status);
        throw new Error(msg);
      }
      return data;
    } finally {
      clearTimeout(t);
    }
  }

  /* ---------------- native plugin bridge ---------------- */
  function plugin(name) {
    const C = window.Capacitor;
    return (C && C.Plugins && C.Plugins[name]) || null;
  }
  function callPlugin(name, method, opts, ms) {
    return new Promise((resolve, reject) => {
      const p = plugin(name);
      if (!p || typeof p[method] !== 'function') { reject(new Error('native_unavailable')); return; }
      let done = false;
      const t = setTimeout(() => { if (!done) { done = true; reject(new Error('native_timeout')); } }, ms || 9000);
      Promise.resolve(p[method](opts || {})).then(
        (r) => { if (!done) { done = true; clearTimeout(t); resolve(r); } },
        (e) => { if (!done) { done = true; clearTimeout(t); reject(e || new Error('native_error')); } }
      );
    });
  }

  /* ---------------- helpers ---------------- */
  function hashStr(s) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
    return h >>> 0;
  }
  function angleFor(s) { return (hashStr(String(s)) % 3600) / 3600 * Math.PI * 2; }
  function ipv4ToInt(ip) {
    const p = String(ip).split('.').map(Number);
    if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  }
  function cidr24(ip) {
    const p = String(ip).split('.');
    if (p.length !== 4) return null;
    return p[0] + '.' + p[1] + '.' + p[2] + '.0/24';
  }
  function isPrivate(ip) {
    return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
  }
  function usableIp(ip) {
    return ip && !ip.startsWith('127.') && !ip.startsWith('169.254.');
  }
  function signalBars(rssi) {
    if (!Number.isFinite(rssi)) return 0;
    if (rssi >= -55) return 4;
    if (rssi >= -65) return 3;
    if (rssi >= -75) return 2;
    if (rssi >= -85) return 1;
    return 0;
  }

  /* ---------------- radar ---------------- */
  function Radar(canvas) {
    const ctx = canvas.getContext('2d');
    let W = 300, H = 300, CX = 150, CY = 150, R = 140, sweep = 0, raf = 0;
    let blips = [];
    let spin = true;

    function resize() {
      const dpr = Math.max(1, Math.min(3, window.devicePixelRatio || 1));
      const rect = canvas.getBoundingClientRect();
      W = Math.max(160, rect.width || 300);
      H = Math.max(160, rect.height || 300);
      canvas.width = Math.round(W * dpr);
      canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      CX = W / 2; CY = H / 2; R = Math.min(W, H) / 2 - 8;
    }

    function clear() { blips = []; }
    function add(b) { blips.push(Object.assign({ born: performance.now() }, b)); }

    function draw(now) {
      ctx.clearRect(0, 0, W, H);

      // grid rings
      ctx.lineWidth = 1;
      for (let i = 1; i <= 4; i++) {
        ctx.strokeStyle = 'rgba(53,224,255,0.13)';
        ctx.beginPath();
        ctx.arc(CX, CY, (R * i) / 4, 0, Math.PI * 2);
        ctx.stroke();
      }
      // crosshair
      ctx.strokeStyle = 'rgba(53,224,255,0.10)';
      ctx.beginPath();
      ctx.moveTo(CX - R, CY); ctx.lineTo(CX + R, CY);
      ctx.moveTo(CX, CY - R); ctx.lineTo(CX, CY + R);
      ctx.stroke();

      if (spin) sweep += 0.045;

      // sweep sector
      const grad = ctx.createRadialGradient(CX, CY, 0, CX, CY, R);
      grad.addColorStop(0, 'rgba(53,224,255,0.28)');
      grad.addColorStop(1, 'rgba(53,224,255,0.0)');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(CX, CY);
      ctx.arc(CX, CY, R, sweep - 0.55, sweep);
      ctx.closePath();
      ctx.fill();

      // sweep leading edge
      ctx.strokeStyle = 'rgba(53,224,255,0.85)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(CX, CY);
      ctx.lineTo(CX + Math.cos(sweep) * R, CY + Math.sin(sweep) * R);
      ctx.stroke();

      // centre
      ctx.fillStyle = 'rgba(53,224,255,0.9)';
      ctx.beginPath();
      ctx.arc(CX, CY, 3.5, 0, Math.PI * 2);
      ctx.fill();

      // blips
      for (let i = 0; i < blips.length; i++) {
        const b = blips[i];
        const x = CX + Math.cos(b.a) * b.r * R;
        const y = CY + Math.sin(b.a) * b.r * R;
        b._x = x; b._y = y; // last drawn coords (CSS px) for tap hit-testing
        const age = Math.min(1, (now - b.born) / 350);
        ctx.globalAlpha = age;
        ctx.fillStyle = b.color || '#35e0ff';
        ctx.shadowColor = b.color || '#35e0ff';
        ctx.shadowBlur = 12;
        ctx.beginPath();
        ctx.arc(x, y, 4.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
        // ping halo for fresh blips
        if (now - b.born < 900) {
          const k = (now - b.born) / 900;
          ctx.globalAlpha = (1 - k) * 0.5;
          ctx.strokeStyle = b.color || '#35e0ff';
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.arc(x, y, 6 + k * 22, 0, Math.PI * 2);
          ctx.stroke();
        }
        // tappable halo for phone blips
        if (b.phone) {
          ctx.strokeStyle = b.color || '#38e08a';
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(x, y, 9, 0, Math.PI * 2);
          ctx.stroke();
        }
        ctx.globalAlpha = 1;
      }
      raf = requestAnimationFrame(draw);
    }

    function hit(px, py) {
      const rect = canvas.getBoundingClientRect();
      const x = px - rect.left;
      const y = py - rect.top;
      let best = null, bestD = 1e9;
      for (const b of blips) {
        if (b._x == null) continue;
        const d = Math.hypot(b._x - x, b._y - y);
        if (d < 22 && d < bestD) { bestD = d; best = b; }
      }
      return best;
    }

    resize();
    raf = requestAnimationFrame(draw);
    window.addEventListener('resize', resize);
    return { clear, add, resize, hit, stop: () => cancelAnimationFrame(raf), getBlips: () => blips.map((b) => ({ id: b.id, x: b._x, y: b._y, color: b.color })) };
  }

  /* ---------------- ui state ---------------- */
  const radar = Radar($('radar'));
  window.__pegasusRadar = radar; // debug/testing hook: blip coordinates for scripted tap verification
  const state = { tab: 'recon', scanning: false, runId: 0 };
  const phoneById = new Map(); // ip -> phone/device record from /phone/discover
  let currentPhone = null;
  let hackCtl = null;          // active hack poller { jobId, stop, timer }
  const PORT_LABELS = { 80: 'HTTP', 443: 'HTTPS', 5555: 'ADB', 62078: 'iOS lockdown', 7000: 'AirPlay', 8009: 'Cast', 8080: 'HTTP-alt', 8888: 'HTTP-alt' };

  function setState(kind, text) {
    const el = $('scan-state');
    el.className = 'scan-state ' + kind;
    el.textContent = text;
  }
  function setCount(n) { $('scan-count').textContent = n + ' found'; }

  function clearResults() {
    $('results').innerHTML = '';
    $('detail').classList.add('hidden');
    $('detail').textContent = '';
    radar.clear();
    setCount(0);
  }

  function addResult(item) {
    const li = document.createElement('li');
    const top = document.createElement('div');
    top.className = 'r-top';

    const name = document.createElement('span');
    name.className = 'r-name';
    name.textContent = item.name;
    top.appendChild(name);

    if (item.bars) {
      const bars = document.createElement('span');
      bars.className = 'bars';
      for (let i = 0; i < 4; i++) {
        const b = document.createElement('i');
        if (i < item.bars) { b.className = 'on' + (i === 3 ? ' b2' : (i === 2 ? ' b2' : (i === 1 ? ' b1' : ''))); }
        bars.appendChild(b);
      }
      top.appendChild(bars);
    }

    if (item.tag) {
      const tag = document.createElement('span');
      tag.className = 'r-tag ' + (item.tagClass || '');
      tag.textContent = item.tag;
      top.appendChild(tag);
    }
    li.appendChild(top);

    (item.lines || []).forEach((line) => {
      const m = document.createElement('div');
      m.className = 'r-meta';
      m.textContent = line;
      li.appendChild(m);
    });
    $('results').appendChild(li);
  }

  function addBlip(seed, radiusFrac, color, id) {
    radar.add({
      a: angleFor(seed),
      r: Math.max(0.18, Math.min(0.97, radiusFrac)),
      color,
      id: id || null,
      phone: !!(id && id.indexOf('phone:') === 0),
    });
  }

  function countResults() { return $('results').childElementCount; }
  function refreshCount() { setCount(countResults()); }

  /* ---------------- module definitions ---------------- */
  const MODULES = {
    recon: {
      label: 'Target subnet (CIDR)',
      input: true,
      placeholder: '192.168.1.0/24',
      desc: 'Enumerates devices around you: the phone\'s ARP/interface table (on-device) plus a live host probe of the subnet run by the Pegasus backend.',
      scan: scanRecon,
    },
    cameras: {
      label: 'Target subnet (CIDR)',
      input: true,
      placeholder: '192.168.1.0/24',
      desc: 'Probes the subnet for IP cameras: TCP-connect on RTSP/HTTP camera ports and HTTP fingerprinting (ONVIF / RTSP banners) from the backend, with candidate RTSP URLs.',
      scan: scanCameras,
    },
    wifi: {
      label: 'Nearby access points',
      input: false,
      desc: 'Reads the Wi-Fi access points already visible to the phone OS (SSID / BSSID / signal / security) via the on-device scanner.',
      scan: scanWifi,
    },
    phones: {
      label: 'Nearby phones',
      input: false,
      desc: 'Discovers nearby devices on the LAN (ARP + ICMP + phone-port probes + OUI vendor classification). Green dot = identified phone, amber dot = possible phone (randomized MAC), cyan dot = other device. Tap any dot to open its card, then Hack now for the real exploit level.',
      scan: scanPhones,
    },
  };

  function applyModule(tab) {
    const m = MODULES[tab];
    $('target-label').textContent = m.label;
    const inp = $('target');
    if (m.input) {
      inp.classList.remove('hidden');
      inp.placeholder = m.placeholder;
      if (!inp.value) inp.value = defaultCidr || '192.168.1.0/24';
    } else {
      inp.classList.add('hidden');
    }
    $('module-text').textContent = m.desc;
  }

  let defaultCidr = '';

  /* ---------------- derive subnet from device ---------------- */
  async function deriveLocalCidr() {
    try {
      const r = await callPlugin('PhoneScanner', 'deviceInfo', {}, 6000);
      const addrs = (r && r.localAddresses) || [];
      for (const a of addrs) {
        const ip = a && a.address;
        if (ip && usableIp(ip) && isPrivate(ip)) return cidr24(ip);
      }
    } catch (_) { /* native not available */ }
    return '';
  }

  /* ---------------- scan: RECON ---------------- */
  async function scanRecon(runId) {
    const found = new Set();
    setState('active', 'SCANNING');
    setHint('Enumerating devices…');

    // 1) on-device enumeration
    try {
      const r = await callPlugin('PhoneScanner', 'deviceInfo', {}, 8000);
      const addrs = (r && r.localAddresses) || [];
      for (const a of addrs) {
        const ip = a && a.address;
        if (!ip || found.has(ip)) continue;
        found.add(ip);
        if (state.runId !== runId) return;
        addResult({ name: ip, tag: 'this device', tagClass: 'host', lines: ['Interface ' + (a.iface || '?')] });
        addBlip('self:' + ip, 0.15, '#38e08a');
        refreshCount();
      }
      const arp = (r && r.arp) || [];
      for (const e of arp) {
        const ip = e && e.ip;
        if (!ip || found.has(ip)) continue;
        found.add(ip);
        if (state.runId !== runId) return;
        addResult({ name: ip, tag: 'neighbour', tagClass: 'host', lines: ['MAC ' + (e.mac || '?') + (e.device ? ' · ' + e.device : '')] });
        addBlip('arp:' + ip, 0.35 + (hashStr(ip) % 55) / 100, '#35e0ff');
        refreshCount();
      }
      if (!defaultCidr) {
        for (const a of addrs) { const ip = a && a.address; if (ip && usableIp(ip) && isPrivate(ip)) { defaultCidr = cidr24(ip); break; } }
      }
    } catch (_) { /* native scanner unavailable */ }

    // 2) backend live host probe of the subnet
    let cidr = ($('target').value || '').trim() || defaultCidr || '192.168.1.0/24';
    try {
      const r = await api('/lan/scan', { method: 'POST', body: { cidr } });
      const hosts = (r && r.hosts) || [];
      for (const h of hosts) {
        const ip = h && h.ip;
        if (!ip || found.has(ip)) continue;
        found.add(ip);
        if (state.runId !== runId) return;
        const ports = (h.openPorts || []).join(', ');
        addResult({
          name: ip,
          tag: 'host',
          tagClass: 'host',
          lines: [ports ? 'Open ports: ' + ports : 'Live host (no common port open)' + (h.mac ? ' · MAC ' + h.mac : '')],
        });
        addBlip('host:' + ip, 0.4 + (hashStr(ip) % 55) / 100, '#35e0ff');
        refreshCount();
      }
      setHint('Subnet ' + (r.cidr || cidr) + ' · probed ' + (r.scannedHosts != null ? r.scannedHosts : '?') + ' hosts');
    } catch (e) {
      setHint('Backend probe unavailable (' + e.message + ') — showing on-device results only.');
    }

    setState('done', 'DONE');
    if (!countResults()) addResult({ name: 'No devices found', tag: '', lines: ['Nothing discovered on this subnet yet.'] });
    refreshCount();
  }

  /* ---------------- scan: CAMERAS ---------------- */
  async function scanCameras(runId) {
    setState('active', 'SCANNING');
    setHint('Probing for IP cameras…');
    let cidr = ($('target').value || '').trim() || defaultCidr;
    if (!cidr) cidr = await deriveLocalCidr();
    if (!cidr) cidr = '192.168.1.0/24';
    if (!defaultCidr) defaultCidr = cidr;
    try {
      const r = await api('/camera/audit', { method: 'POST', body: { cidr }, timeout: 60000 });
      const cands = (r && r.candidates) || [];
      for (const c of cands) {
        if (state.runId !== runId) return;
        const lines = [];
        if (c.banner) lines.push('Banner: ' + c.banner);
        if (c.service) lines.push('Service: ' + c.service);
        if (c.rtspUrls && c.rtspUrls.length) lines.push('RTSP: ' + c.rtspUrls.slice(0, 3).join('  '));
        addResult({
          name: c.ip + ':' + c.port,
          tag: c.camera ? 'camera?' : 'open',
          tagClass: 'cam',
          lines: lines.length ? lines : ['Open port'],
        });
        addBlip('cam:' + c.ip + ':' + c.port, 0.4 + (hashStr(c.ip + c.port) % 55) / 100, c.camera ? '#ffb020' : '#35e0ff');
        refreshCount();
      }
      setHint('Subnet ' + (r.cidr || cidr) + ' · ' + cands.length + ' candidate(s)');
      setState('done', 'DONE');
      if (!cands.length) addResult({ name: 'No cameras found', tag: '', lines: ['No camera-like endpoint answered on ' + cidr + '.'] });
    } catch (e) {
      setState('error', 'ERROR');
      setHint('');
      addResult({ name: 'Backend offline', tag: 'error', tagClass: 'cam', lines: ['Camera probing needs the Pegasus backend reachable on the LAN: ' + e.message] });
    }
    refreshCount();
  }

  /* ---------------- scan: WI-FI ---------------- */
  async function scanWifi(runId) {
    setState('active', 'SCANNING');
    setHint('Scanning Wi-Fi…');
    try {
      const r = await callPlugin('WiFiCracker', 'scan', {}, 12000);
      const aps = ((r && r.accessPoints) || []).slice().sort((a, b) => (b.rssi || -999) - (a.rssi || -999));
      for (const ap of aps) {
        if (state.runId !== runId) return;
        const ssid = ap.ssid || '(hidden)';
        const bars = signalBars(Number(ap.rssi));
        const rssi = Math.max(0.15, Math.min(0.95, (100 + Number(ap.rssi || -80)) / 100));
        addResult({
          name: ssid,
          bars: bars,
          tag: 'AP',
          tagClass: 'ap',
          lines: ['BSSID ' + (ap.bssid || '?') + ' · ' + (ap.rssi != null ? ap.rssi + ' dBm' : '?') + (ap.frequency ? ' · ' + ap.frequency + ' MHz' : ''), ap.security || ''],
        });
        addBlip('ap:' + (ap.bssid || ssid), 1.0 - rssi, '#38e08a');
        refreshCount();
      }
      setHint(aps.length + ' access point(s) visible');
      setState('done', 'DONE');
      if (!aps.length) addResult({ name: 'No access points', tag: '', lines: ['Enable Wi-Fi and location permission, then scan again.'] });
    } catch (e) {
      setState('error', 'ERROR');
      addResult({ name: 'Native Wi-Fi scanner unavailable', tag: 'error', tagClass: 'ap', lines: [e.message === 'native_unavailable' ? 'Open this app on the Android device (Capacitor) to read Wi-Fi scan results.' : ('Scan failed: ' + e.message)] });
    }
  }

  /* ---------------- scan: PHONES (nearby-phone discovery) ---------------- */
  async function scanPhones(runId) {
    setState('active', 'SCANNING');
    setHint('Searching for nearby phones…');
    try {
      const r = await api('/phone/discover', { method: 'POST', body: {}, timeout: 120000 });
      if (state.runId !== runId) return;
      if (!defaultCidr && r.subnet) defaultCidr = r.subnet;
      const net = r.network || {};
      const devices = (r.devices || []);
      for (const p of devices) {
        if (state.runId !== runId) return;
        const isPhone = p.type === 'phone';
        const randPossible = !isPhone && p.macKind === 'randomized';
        const rec = Object.assign({}, p, { network: isPhone ? net : (p.network || null), isPhone, randPossible });
        phoneById.set(p.ip, rec);
        const ports = (p.openPorts || []).filter((x) => x != null);
        const prox = p.rttMs != null ? 'RTT ' + p.rttMs + ' ms · ' + (p.proximity || 'measured') : null;
        const lines = [
          (p.mac ? 'MAC ' + p.mac : 'MAC not in ARP yet') + (ports.length ? ' · ports ' + ports.join(', ') : ''),
          isPhone ? 'Network: ' + (net.type || 'Wi-Fi LAN') + (net.gateway ? ' · gateway ' + net.gateway : '') + ' — tap its green dot' : '',
          randPossible ? 'Possible phone (randomized MAC hides the vendor) — tap its amber dot' : '',
          prox,
          (p.ssdp && (p.ssdp.server || p.ssdp.st)) ? 'UPnP: ' + (p.ssdp.server || p.ssdp.st) : '',
        ].filter(Boolean);
        addResult({
          name: p.label || p.ip,
          tag: isPhone ? 'phone' : randPossible ? 'possible phone' : p.type,
          tagClass: isPhone ? 'phone' : randPossible ? 'maybe' : 'host',
          lines,
        });
        // green = identified phone · amber = possible phone (randomized MAC) · cyan = other device — ALL tappable
        // Radius = REAL proximity: measured ICMP RTT (closer radio neighbor → nearer the center).
        const blipR = p.rttMs != null
          ? 0.34 + Math.min(p.rttMs, 60) / 60 * 0.38
          : (isPhone ? (p.reachable ? 0.72 : 0.5) : 0.42 + (hashStr(p.ip) % 55) / 100);
        addBlip(
          'phone:' + p.ip,
          blipR,
          isPhone ? '#38e08a' : randPossible ? '#ffb020' : '#35e0ff',
          'phone:' + p.ip
        );
        refreshCount();
      }
      const nPhones = (r.phones || []).length;
      const nRand = devices.filter((d) => d.type !== 'phone' && d.macKind === 'randomized').length;
      setHint((r.subnet || '') + ' · ' + nPhones + ' phone(s) + ' + nRand + ' possible of ' + devices.length + ' alive — green=phone · amber=possible · cyan=other · tap any dot');
      setState('done', 'DONE');
      if (!devices.length) addResult({ name: 'No devices found', tag: '', lines: ['No live host answered on ' + (r.subnet || 'the backend subnet') + '.'] });
      else if (!nPhones && !nRand) addResult({ name: 'No phone identified yet', tag: '', lines: ['Devices are alive but none matched a phone vendor/port or a randomized MAC. Rescan after a phone joins the Wi-Fi.'] });
    } catch (e) {
      setState('error', 'ERROR');
      addResult({ name: 'Phone discovery failed', tag: 'error', tagClass: 'host', lines: ['Discovery runs on the Pegasus backend — keep it on the same LAN. (' + e.message + ')'] });
    }
    refreshCount();
  }

  /* ---------------- device card (tap any dot) ---------------- */
  function openPhoneSheet(ip) {
    const p = phoneById.get(ip);
    if (!p) return;
    currentPhone = p;
    const isPhone = p.isPhone != null ? p.isPhone : p.type === 'phone';
    const possible = p.randPossible != null ? p.randPossible : (!isPhone && p.macKind === 'randomized');
    const kind = isPhone
      ? (p.vendor ? p.vendor + ' phone' : 'Phone')
      : possible ? 'Possible phone (randomized MAC)'
      : p.type === 'router' ? (p.vendor ? p.vendor + ' router' : 'Router')
      : (p.vendor ? p.vendor + ' device' : 'Device');
    $('ps-title').textContent = kind + ' · ' + p.ip;
    $('ps-type').textContent = kind + (p.mac ? ' · MAC ' + p.mac : '');
    $('ps-number').textContent = (p.identity && p.identity.number) || p.number || 'Unknown';
    $('ps-network').textContent = (p.network && p.network.type) || 'Wi-Fi LAN';
    $('ps-name').textContent = p.name || 'not revealed yet';
    const ports = p.openPorts || [];
    $('ps-services').textContent = ports.length
      ? ports.map((pt) => pt + (PORT_LABELS[pt] ? ' (' + PORT_LABELS[pt] + ')' : '')).join(', ')
      : 'none open on phone ports';
    $('phone-sheet').classList.remove('hidden');
  }

  /* ---------------- hack now -> REAL percentage popup ---------------- */
  function openHackModal(ip) {
    $('hm-title').textContent = 'HACKING ' + ip;
    $('hm-pct').textContent = '0%';
    $('hm-fill').style.width = '0%';
    $('hm-level').textContent = 'starting real audit…';
    $('hm-steps').innerHTML = '';
    $('hack-modal').classList.remove('hidden');
  }
  function closeHack() {
    if (hackCtl) { hackCtl.stop = true; clearTimeout(hackCtl.timer); }
    $('hack-modal').classList.add('hidden');
  }
  function renderHackSteps(steps) {
    const box = $('hm-steps');
    box.innerHTML = '';
    (steps || []).forEach((s) => {
      const d = document.createElement('div');
      d.className = 'ms ' + s.status;
      d.textContent = (s.status === 'done' ? '✔ ' : s.status === 'running' ? '▸ ' : s.status === 'error' ? '✘ ' : '· ') + s.label;
      box.appendChild(d);
    });
  }
  async function startHack(p) {
    if (!p) return;
    $('phone-sheet').classList.add('hidden');
    openHackModal(p.ip);
    if (hackCtl) { hackCtl.stop = true; clearTimeout(hackCtl.timer); }
    hackCtl = { stop: false };
    try {
      const r = await api('/phone/audit', { method: 'POST', body: { ip: p.ip }, timeout: 15000 });
      if (hackCtl.stop) return;
      hackCtl.jobId = r.jobId;
      $('hm-level').textContent = 'real audit running — 9 evidence steps';
      pollHack();
    } catch (e) {
      $('hm-title').textContent = 'HACK FAILED';
      $('hm-level').textContent = String((e && e.message) || e);
    }
  }
  function pollHack() {
    if (!hackCtl || hackCtl.stop || !hackCtl.jobId) return;
    api('/phone/audit/' + hackCtl.jobId, { timeout: 8000 }).then((j) => {
      if (!hackCtl || hackCtl.stop) return;
      renderHackSteps(j.steps);
      if (j.status === 'running') {
        // REAL progress: completed audit steps / 9 — never a fake timer
        $('hm-pct').textContent = j.progress + '%';
        $('hm-fill').style.width = j.progress + '%';
        const done = (j.steps || []).filter((s) => s.status === 'done').length;
        $('hm-level').textContent = 'real audit progress · ' + done + '/9 steps done';
        hackCtl.timer = setTimeout(pollHack, 1000);
      } else if (j.status === 'done') {
        // final REAL exploit level = evidence-weighted score (0–100)
        const score = (j.score != null ? j.score : 0);
        $('hm-title').textContent = 'HACK COMPLETE';
        $('hm-pct').textContent = score + '%';
        $('hm-fill').style.width = score + '%';
        const idn = (j.findings && j.findings.identity) || {};
        $('hm-level').textContent = 'Exploit level: ' + (j.level || 'unknown') +
          (idn.model ? ' · ' + idn.model : '') +
          (idn.number ? ' · number ' + idn.number : '') +
          (idn.serialNumber ? ' · serial ' + idn.serialNumber : '') +
          (idn.adb ? ' · ADB ' + idn.adb : '');
        const p = phoneById.get(j.ip);
        if (p && j.findings) {
          p.identity = idn;
          if (idn.number) p.number = idn.number;
          if (idn.name && !p.name) p.name = idn.name;
        }
      } else if (j.status === 'error') {
        $('hm-title').textContent = 'HACK FAILED';
        $('hm-pct').textContent = j.progress + '%';
        $('hm-fill').style.width = j.progress + '%';
        $('hm-level').textContent = j.error || 'audit error';
      } else { // cancelled
        $('hm-title').textContent = 'HACK CANCELLED';
        $('hm-pct').textContent = j.progress + '%';
        $('hm-fill').style.width = j.progress + '%';
        $('hm-level').textContent = 'audit stopped before completion';
      }
    }).catch((e) => {
      if (!hackCtl || hackCtl.stop) return;
      $('hm-level').textContent = 'poll failed (' + String((e && e.message) || e) + ') — retrying';
      hackCtl.timer = setTimeout(pollHack, 1500);
    });
  }

  function setHint(t) { $('hint').textContent = t || ''; }

  /* ---------------- run control ---------------- */
  async function runScan() {
    if (state.scanning) return;
    state.scanning = true;
    state.runId++;
    const runId = state.runId;
    clearResults();
    $('btn-scan').disabled = true;
    $('btn-stop').disabled = false;
    try {
      await MODULES[state.tab].scan(runId);
    } catch (e) {
      setState('error', 'ERROR');
      setHint(String(e && e.message ? e.message : e));
    } finally {
      if (state.runId === runId) {
        state.scanning = false;
        $('btn-scan').disabled = false;
        $('btn-stop').disabled = true;
        if ($('scan-state').textContent === 'SCANNING') setState('done', 'DONE');
      }
    }
  }
  function stopScan() {
    state.runId++;            // invalidate the running scan
    state.scanning = false;
    $('btn-scan').disabled = false;
    $('btn-stop').disabled = true;
    setState('idle', 'STOPPED');
    setHint('Scan stopped.');
  }

  /* ---------------- connection (always-on health loop) ----------------
   * Root causes of a stuck red dot: (1) ping ran once at startup, (2) it used
   * the heavy /security/all endpoint (false offline during scans), (3) no
   * auto-retry when the backend came back. Now: light /api/health + retry
   * every 8s + re-ping on connectivity/app-resume events. */
  let connUp = false;
  let healthTimer = 0;
  async function ping() {
    const dot = $('conn-dot');
    const label = $('conn-label');
    const base = resolveBase() || 'same-origin backend';
    try {
      const r = await api('/health', { timeout: 5000 });  // api() prefixes '/api' -> /api/health
      if (!connUp) setHint('Backend online (' + (r && r.service || 'pegasus') + ') — scans and audits ready.');
      connUp = true;
      dot.className = 'dot on';
      label.textContent = 'backend online';
      label.title = base + ' · reachable';
      return r;
    } catch (e) {
      connUp = false;
      dot.className = 'dot off';
      label.textContent = 'backend offline · retrying';
      label.title = base + ' — ' + String((e && e.message) || e);
      return null;
    }
  }
  function startHealthLoop() {
    clearInterval(healthTimer);
    healthTimer = setInterval(ping, 8000);
    window.addEventListener('online', ping);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) ping(); });
    document.addEventListener('resume', ping); // Capacitor resume
  }

  /* ---------------- settings ---------------- */
  function initSettings() {
    $('api-base').value = resolveBase();
    $('btn-save').addEventListener('click', () => {
      localStorage.setItem(LS_KEY, $('api-base').value.trim().replace(/\/+$/, ''));
      $('ping-result').textContent = 'Saved.';
      ping();
    });
    $('btn-ping').addEventListener('click', async () => {
      $('ping-result').textContent = 'Testing…';
      const r = await ping();
      $('ping-result').textContent = r ? 'OK' : 'Unreachable';
    });
    $('btn-conn').addEventListener('click', ping);
  }

  /* ---------------- tabs / init ---------------- */
  function initTabs() {
    document.querySelectorAll('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        if (state.scanning) stopScan();
        document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.tab = btn.dataset.tab;
        applyModule(state.tab);
        clearResults();
        setState('idle', 'IDLE');
        setHint('');
      });
    });
  }

  function radarTap(ev) {
    if (state.tab !== 'phones') return;
    const b = radar.hit(ev.clientX, ev.clientY);
    if (!b || !b.id) return;
    const ip = b.id.slice('phone:'.length);
    if (phoneById.has(ip)) openPhoneSheet(ip);
  }

  document.addEventListener('DOMContentLoaded', async () => {
    initTabs();
    initSettings();
    applyModule('recon');
    $('btn-scan').addEventListener('click', runScan);
    $('btn-stop').addEventListener('click', stopScan);
    $('btn-clear').addEventListener('click', () => { clearResults(); setState('idle', 'IDLE'); setHint(''); });

    // phone card + hack modal wiring
    $('radar').addEventListener('click', radarTap);
    $('ps-close').addEventListener('click', () => $('phone-sheet').classList.add('hidden'));
    $('phone-sheet').addEventListener('click', (ev) => { if (ev.target === $('phone-sheet')) $('phone-sheet').classList.add('hidden'); });
    $('ps-hack').addEventListener('click', () => startHack(currentPhone));
    $('hm-close').addEventListener('click', closeHack);
    $('hack-modal').addEventListener('click', (ev) => { if (ev.target === $('hack-modal')) closeHack(); });

    defaultCidr = await deriveLocalCidr();
    if (defaultCidr && MODULES[state.tab].input) $('target').value = defaultCidr;
    ping();
    startHealthLoop(); // keep the indicator honest forever — auto-recovers
  });
})();
