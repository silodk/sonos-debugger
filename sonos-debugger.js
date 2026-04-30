'use strict';

const http = require('http');
const dgram = require('dgram');
const net = require('net');
const os = require('os');
const { exec } = require('child_process');
const { URL } = require('url');

const PORT = 8888;
const SONOS_PORT = 1400;

// ── SSDP Discovery ────────────────────────────────────────────────────────────
function ssdpDiscover(timeoutMs = 5000) {
  return new Promise(resolve => {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const found = new Map();
    const msg = Buffer.from(
      'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n' +
      'MAN: "ssdp:discover"\r\nMX: 3\r\n' +
      'ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\r\n'
    );
    socket.on('message', (buf, rinfo) => {
      const text = buf.toString();
      if (!found.has(rinfo.address)) {
        const m = text.match(/location:\s*(.+)/i);
        found.set(rinfo.address, m ? m[1].trim() : '');
      }
    });
    socket.on('error', () => {});
    socket.bind(0, () => {
      try { socket.setBroadcast(true); } catch {}
      socket.send(msg, 1900, '239.255.255.250', () => {});
    });
    setTimeout(() => {
      try { socket.close(); } catch {}
      resolve([...found.entries()].map(([ip]) => ({ ip })));
    }, timeoutMs);
  });
}

// ── IP Range Scanner ──────────────────────────────────────────────────────────
function expandSubnet(cidr) {
  const [base, bits] = cidr.trim().split('/');
  const prefixLen = parseInt(bits, 10);
  if (isNaN(prefixLen) || prefixLen < 16 || prefixLen > 30)
    throw new Error(`Ugyldigt subnet (tilladt /16–/30): ${cidr}`);
  const parts = base.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255))
    throw new Error(`Ugyldig IP: ${base}`);
  const baseInt = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = prefixLen === 32 ? 0xffffffff : (~((1 << (32 - prefixLen)) - 1)) >>> 0;
  const network = (baseInt & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const ips = [];
  for (let i = network + 1; i < broadcast; i++) {
    ips.push(`${(i>>>24)&255}.${(i>>>16)&255}.${(i>>>8)&255}.${i&255}`);
  }
  return ips;
}

function tcpProbe(ip, port, ms) {
  return new Promise(resolve => {
    const sock = new net.Socket();
    let done = false;
    const fin = v => { if (!done) { done = true; resolve(v); } };
    sock.setTimeout(ms);
    sock.on('connect', () => { sock.destroy(); fin(true); });
    sock.on('error', () => { sock.destroy(); fin(false); });
    sock.on('timeout', () => { sock.destroy(); fin(false); });
    sock.connect(port, ip);
  });
}

async function scanSubnet(cidr, onProgress) {
  const ips = expandSubnet(cidr);
  const found = [];
  const chunk = 60;
  for (let i = 0; i < ips.length; i += chunk) {
    const batch = ips.slice(i, i + chunk);
    const results = await Promise.all(batch.map(ip => tcpProbe(ip, SONOS_PORT, 500)));
    results.forEach((open, j) => { if (open) found.push(batch[j]); });
    if (onProgress) onProgress(Math.min(i + chunk, ips.length), ips.length);
  }
  return found;
}

// ── Sonos HTTP helpers ────────────────────────────────────────────────────────
function sonosGet(ip, path, ms = 5000) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: ip, port: SONOS_PORT, path, method: 'GET', timeout: ms },
      res => {
        let body = '';
        res.on('data', c => (body += c));
        res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
      }
    );
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

function sonosPost(ip, path, body = '', extraHeaders = {}, ms = 6000) {
  return new Promise((resolve, reject) => {
    const buf = Buffer.from(body);
    const req = http.request(
      {
        hostname: ip, port: SONOS_PORT, path, method: 'POST', timeout: ms,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': buf.length,
          ...extraHeaders,
        },
      },
      res => {
        let d = '';
        res.on('data', c => (d += c));
        res.on('end', () => resolve({ status: res.statusCode, body: d }));
      }
    );
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end(buf);
  });
}

// ── XML Parsers ───────────────────────────────────────────────────────────────
function xmlField(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([^<]*)</${tag}>`, 'i'));
  return m ? m[1].trim() : '';
}

function parseDeviceDescription(xml, ip) {
  return {
    ip,
    name: xmlField(xml, 'friendlyName') || ip,
    roomName: xmlField(xml, 'roomName') || xmlField(xml, 'displayName') || xmlField(xml, 'friendlyName') || ip,
    model: xmlField(xml, 'modelName'),
    modelNumber: xmlField(xml, 'modelNumber'),
    description: xmlField(xml, 'modelDescription'),
    serialNumber: xmlField(xml, 'serialNum') || xmlField(xml, 'serialNumber'),
    softwareVersion: xmlField(xml, 'softwareVersion'),
    hardwareVersion: xmlField(xml, 'hardwareVersion'),
    uuid: (xml.match(/uuid:([A-Z0-9_-]+)/i) || ['', ''])[1],
  };
}

function parseTopologyXML(xml) {
  const groups = [];
  for (const gm of (xml.matchAll(/<ZoneGroup\s+([^>]+)>([\s\S]*?)<\/ZoneGroup>/g) || [])) {
    const gAttrs = gm[1];
    const coordinatorUUID = (gAttrs.match(/Coordinator="([^"]+)"/) || ['', ''])[1];
    const members = [];
    for (const mm of (gm[2].matchAll(/<ZoneGroupMember\s+([^/]*)\/?>/g) || [])) {
      const a = mm[1];
      const ga = n => (a.match(new RegExp(`${n}="([^"]*)"`)) || ['', ''])[1];
      const loc = ga('Location');
      const memberIp = (loc.match(/\/\/([^:/]+)/) || ['', ''])[1];
      members.push({
        uuid: ga('UUID'),
        name: ga('ZoneName'),
        ip: memberIp,
        wirelessMode: ga('WirelessMode'),
        wifiEnabled: ga('WifiEnabled'),
        channelFreq: ga('ChannelFreq'),
        behindExtender: ga('BehindWifiExtender') === '1',
        softwareVersion: ga('SoftwareVersion'),
        isCoordinator: ga('UUID') === coordinatorUUID,
        invisible: ga('Invisible') === '1',
      });
    }
    if (members.length) groups.push({ coordinatorUUID, members });
  }
  return groups;
}

// ── Local subnet detection ────────────────────────────────────────────────────
function getLocalSubnets() {
  const subnets = new Set();
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const addr of addrs) {
      if (addr.family !== 'IPv4' || addr.internal) continue;
      const maskBits = addr.netmask.split('.').reduce(
        (n, o) => n + parseInt(o, 10).toString(2).replace(/0/g, '').length, 0
      );
      if (maskBits < 16 || maskBits > 30) continue;
      const p = addr.address.split('.').map(Number);
      const m = addr.netmask.split('.').map(Number);
      const net = p.map((x, i) => x & m[i]).join('.');
      subnets.add(`${net}/${maskBits}`);
    }
  }
  return [...subnets];
}

// ── HTTP Server ───────────────────────────────────────────────────────────────
function jsonResp(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://localhost:${PORT}`);
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // Frontend
  if (u.pathname === '/' || u.pathname === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(HTML);
    return;
  }

  // GET /api/defaults
  if (u.pathname === '/api/defaults' && req.method === 'GET') {
    jsonResp(res, { subnets: getLocalSubnets() });
    return;
  }

  // GET /api/scan — SSE stream
  if (u.pathname === '/api/scan' && req.method === 'GET') {
    const subnetParam = u.searchParams.get('subnets') || '';
    const subnets = subnetParam
      ? subnetParam.split(',').map(s => s.trim()).filter(Boolean)
      : getLocalSubnets();

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    const sse = (event, data) => {
      if (!res.destroyed) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    sse('start', { subnets });

    const seenIPs = new Set();

    const enrichDevice = async ip => {
      if (seenIPs.has(ip)) return;
      seenIPs.add(ip);
      try {
        const { body } = await sonosGet(ip, '/xml/device_description.xml', 4000);
        if (body.includes('ZonePlayer') || body.includes('Sonos') || body.toLowerCase().includes('rincon')) {
          sse('device', parseDeviceDescription(body, ip));
        }
      } catch {}
    };

    // SSDP + IP scan in parallel
    const ssdpDone = ssdpDiscover(5000)
      .then(list => Promise.all(list.map(({ ip }) => enrichDevice(ip))))
      .catch(() => {});

    for (const subnet of subnets) {
      let total = 0;
      try { total = expandSubnet(subnet).length; } catch (e) {
        sse('subnet_error', { subnet, message: e.message });
        continue;
      }
      sse('subnet_start', { subnet, total });
      try {
        const openIPs = await scanSubnet(subnet, (scanned, t) =>
          sse('progress', { subnet, scanned, total: t })
        );
        await Promise.all(openIPs.map(ip => enrichDevice(ip)));
      } catch (e) {
        sse('subnet_error', { subnet, message: e.message });
      }
      sse('subnet_done', { subnet });
    }

    await ssdpDone;
    sse('done', { count: seenIPs.size });
    res.end();
    return;
  }

  // /api/device/:ip/:action
  const dm = u.pathname.match(/^\/api\/device\/([^/]+)\/([^/]+)$/);
  if (dm) {
    const [, ip, action] = dm;
    try {
      if (action === 'info' && req.method === 'GET') {
        const { body } = await sonosGet(ip, '/xml/device_description.xml');
        jsonResp(res, parseDeviceDescription(body, ip));
        return;
      }
      if (action === 'topology' && req.method === 'GET') {
        const { body } = await sonosGet(ip, '/status/topology');
        jsonResp(res, { groups: parseTopologyXML(body), raw: body });
        return;
      }
      if (action === 'status' && req.method === 'GET') {
        const { body } = await sonosGet(ip, '/status/zp');
        jsonResp(res, { raw: body });
        return;
      }
      if (action === 'reboot' && req.method === 'POST') {
        let csrfToken = '';
        try {
          const { body: page } = await sonosGet(ip, '/reboot');
          const m = page.match(/name="csrf[_-]?token"\s+value="([^"]+)"/i)
                 || page.match(/value="([^"]+)"\s+name="csrf[_-]?token"/i);
          if (m) csrfToken = m[1];
        } catch {}
        try {
          const postBody = csrfToken ? `csrf_token=${encodeURIComponent(csrfToken)}` : '';
          const { status } = await sonosPost(ip, '/reboot', postBody);
          jsonResp(res, { success: true, statusCode: status, usedCsrf: !!csrfToken });
        } catch (e) {
          jsonResp(res, { success: false, error: e.message }, 500);
        }
        return;
      }
    } catch (e) {
      jsonResp(res, { error: e.message }, 500);
      return;
    }
    jsonResp(res, { error: 'unknown action' }, 404);
    return;
  }

  res.writeHead(404); res.end('Not found');
});

function openBrowser(url) {
  const cmd = process.platform === 'darwin' ? `open "${url}"`
    : process.platform === 'win32' ? `start "" "${url}"` : `xdg-open "${url}"`;
  exec(cmd, () => {});
}

server.listen(PORT, '127.0.0.1', () => {
  const url = `http://localhost:${PORT}`;
  console.log(`\n  ╔══════════════════════════════════════╗`);
  console.log(`  ║  Sonos Debugger                      ║`);
  console.log(`  ║  ${url}          ║`);
  console.log(`  ║  Ctrl+C for at stoppe                ║`);
  console.log(`  ╚══════════════════════════════════════╝\n`);
  setTimeout(() => openBrowser(url), 600);
});

// ── HTML Frontend ─────────────────────────────────────────────────────────────
const HTML = `<!DOCTYPE html>
<html lang="da">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sonos Debugger</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg0:#05050b;--bg1:#0a0a14;--bg2:#0f0f1c;
  --glass:rgba(255,255,255,.04);--glass2:rgba(255,255,255,.07);
  --border:rgba(255,255,255,.08);--border2:rgba(255,255,255,.14);
  --accent:#4f8ef7;--glow:rgba(79,142,247,.28);
  --green:#34d399;--yellow:#fbbf24;--red:#f87171;--purple:#a78bfa;
  --t1:#e2e8f0;--t2:#94a3b8;--t3:#475569;
  --r:14px;--rs:8px;
}
html{height:100%}
body{
  min-height:100%;background:var(--bg0);
  background-image:
    radial-gradient(ellipse 60% 40% at 10% 0%,rgba(79,142,247,.07) 0%,transparent 70%),
    radial-gradient(ellipse 50% 30% at 90% 10%,rgba(167,139,250,.05) 0%,transparent 60%);
  color:var(--t1);font-family:-apple-system,'SF Pro Display','Inter',system-ui,sans-serif;
  font-size:14px;line-height:1.5;
}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:3px}
.wrap{max-width:1300px;margin:0 auto;padding:28px 24px 100px}

/* Header */
header{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:14px}
.brand-icon{
  width:40px;height:40px;border-radius:12px;
  background:linear-gradient(135deg,var(--accent),#7c3aed);
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 0 20px var(--glow);flex-shrink:0
}
.brand-icon svg{width:22px;height:22px}
.brand h1{font-size:19px;font-weight:800;letter-spacing:-.04em}
.brand p{font-size:11px;color:var(--t3);letter-spacing:.08em;text-transform:uppercase;margin-top:1px}
#hdr-status{font-size:12px;color:var(--t2);display:flex;align-items:center;gap:8px}

/* Card */
.card{background:var(--glass);border:1px solid var(--border);border-radius:var(--r);backdrop-filter:blur(16px)}

/* Scan panel */
.scan-panel{padding:20px 24px;margin-bottom:28px;display:flex;flex-direction:column;gap:16px}
.row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.row-label{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
  color:var(--t3);min-width:72px}
.tags{display:flex;flex-wrap:wrap;gap:6px;flex:1}
.tag{
  display:flex;align-items:center;gap:6px;padding:4px 8px 4px 12px;
  background:var(--bg2);border:1px solid var(--border);border-radius:99px;
  font-size:12px;font-family:'SF Mono','Fira Code',monospace;color:var(--t1)
}
.tag button{background:none;border:none;cursor:pointer;color:var(--t3);font-size:13px;
  line-height:1;padding:0;display:flex;align-items:center;transition:color .15s}
.tag button:hover{color:var(--red)}
.add-sub{display:flex;gap:6px;align-items:center}
.add-sub input{
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--rs);
  color:var(--t1);font-family:'SF Mono','Fira Code',monospace;font-size:12px;
  padding:6px 10px;width:168px;outline:none;transition:border-color .15s
}
.add-sub input:focus{border-color:var(--accent)}
.add-sub input::placeholder{color:var(--t3)}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:var(--rs);
  border:none;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s;
  white-space:nowrap;text-decoration:none;font-family:inherit}
.btn-primary{background:var(--accent);color:#fff;box-shadow:0 0 18px var(--glow)}
.btn-primary:hover{background:#6ba3f9;transform:translateY(-1px);box-shadow:0 0 28px var(--glow)}
.btn-ghost{background:var(--glass);color:var(--t2);border:1px solid var(--border)}
.btn-ghost:hover{background:var(--glass2);color:var(--t1);border-color:var(--border2)}
.btn-sm{padding:5px 11px;font-size:12px;border-radius:6px}
.btn-danger{background:rgba(248,113,113,.1);color:var(--red);border:1px solid rgba(248,113,113,.2)}
.btn-danger:hover{background:rgba(248,113,113,.2)}
.btn:disabled{opacity:.45;cursor:not-allowed;transform:none!important;box-shadow:none!important}

/* Progress */
.prog-area{display:none;flex-direction:column;gap:8px}
.prog-area.on{display:flex}
.prog-info{display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--t2)}
.prog-track{height:3px;background:rgba(255,255,255,.06);border-radius:99px;overflow:hidden}
.prog-fill{height:100%;background:linear-gradient(90deg,var(--accent),#7c3aed);
  border-radius:99px;transition:width .25s ease;min-width:4px;position:relative}
.prog-fill::after{content:'';position:absolute;right:0;top:0;bottom:0;width:60px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.35));animation:shim 1.4s infinite}
@keyframes shim{from{transform:translateX(-60px);opacity:0}50%{opacity:1}to{transform:translateX(10px);opacity:0}}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;
  background:var(--accent);box-shadow:0 0 7px var(--accent);animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.75)}}

/* Section */
.sec{margin-bottom:36px}
.sec-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.sec-title{font-size:12px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:var(--t3);display:flex;align-items:center;gap:8px}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:99px;
  font-size:11px;font-weight:600}
.b-count{background:var(--glass2);color:var(--t2);border:1px solid var(--border)}
.b-green{background:rgba(52,211,153,.1);color:var(--green);border:1px solid rgba(52,211,153,.2)}
.b-yellow{background:rgba(251,191,36,.1);color:var(--yellow);border:1px solid rgba(251,191,36,.2)}
.b-red{background:rgba(248,113,113,.1);color:var(--red);border:1px solid rgba(248,113,113,.2)}
.b-blue{background:rgba(79,142,247,.1);color:var(--accent);border:1px solid rgba(79,142,247,.2)}
.b-purple{background:rgba(167,139,250,.1);color:var(--purple);border:1px solid rgba(167,139,250,.2)}

/* Device grid */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:16px}

/* Device card */
.dcard{padding:20px;border-radius:var(--r);display:flex;flex-direction:column;gap:14px;
  animation:cin .3s ease both;position:relative;overflow:hidden;
  transition:border-color .2s,transform .2s,box-shadow .2s}
.dcard::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:0;transition:opacity .2s}
.dcard:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:0 8px 32px rgba(0,0,0,.3)}
.dcard:hover::before{opacity:1}
@keyframes cin{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.dcard-hdr{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}
.dicon{width:42px;height:42px;background:var(--glass2);border:1px solid var(--border);
  border-radius:11px;display:flex;align-items:center;justify-content:center;
  font-size:20px;flex-shrink:0}
.dname{flex:1}
.dname h3{font-size:15px;font-weight:700;letter-spacing:-.025em;line-height:1.2}
.dname p{font-size:12px;color:var(--t2);margin-top:2px}
.sdot{width:8px;height:8px;border-radius:50%;background:var(--green);
  box-shadow:0 0 7px var(--green);flex-shrink:0;margin-top:4px}
.sdot.off{background:var(--t3);box-shadow:none}
.dmeta{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.mitem{display:flex;flex-direction:column;gap:2px}
.mlabel{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--t3)}
.mval{font-size:12px;color:var(--t1)}
.mval.mono{font-family:'SF Mono','Fira Code',monospace;font-size:11px}
.dtags{display:flex;flex-wrap:wrap;gap:5px;min-height:20px}
.dact{display:flex;gap:7px;flex-wrap:wrap}

/* Empty state */
.empty{text-align:center;padding:64px 24px;grid-column:1/-1}
.empty-ico{font-size:52px;margin-bottom:16px;opacity:.4}
.empty h3{font-size:16px;font-weight:700;margin-bottom:8px}
.empty p{font-size:13px;color:var(--t2);max-width:380px;margin:0 auto}

/* Topology */
.topo-sec{display:none}
.topo-sec.on{display:block}
.zone-wrap{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:24px}
.zone-card{padding:16px;border-radius:var(--r);flex:1;min-width:190px}
.zone-hdr{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
  color:var(--t3);margin-bottom:12px;display:flex;align-items:center;gap:6px}
.zmem{display:flex;align-items:center;gap:10px;padding:9px;border-radius:var(--rs);
  background:var(--glass);margin-bottom:5px}
.zmem:last-child{margin-bottom:0}
.zmem-ico{font-size:17px}
.zmem-info h4{font-size:13px;font-weight:600}
.zmem-info p{font-size:11px;color:var(--t2)}
.crown{margin-left:auto;font-size:14px}

/* Matrix */
.mat-wrap{overflow-x:auto}
.mat{border-collapse:collapse;width:100%;min-width:300px}
.mat th,.mat td{padding:6px 10px;text-align:center;font-size:12px;white-space:nowrap}
.mat th{color:var(--t2);font-weight:600;border-bottom:1px solid var(--border)}
.mat th.rh{text-align:left;padding-left:14px;color:var(--t1)}
.mat tbody tr{border-top:1px solid rgba(255,255,255,.04)}
.mcell{border-radius:7px;width:34px;height:34px;display:inline-flex;
  align-items:center;justify-content:center;font-size:15px;cursor:help;transition:transform .15s}
.mcell:hover{transform:scale(1.12)}
.c-self{background:rgba(255,255,255,.06);color:var(--t3)}
.c-wired{background:rgba(52,211,153,.15);color:var(--green)}
.c-wifi{background:rgba(79,142,247,.15);color:var(--accent)}
.c-coord{background:rgba(251,191,36,.15);color:var(--yellow)}
.c-none{background:rgba(255,255,255,.03);color:rgba(255,255,255,.15)}
.legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:14px}
.li{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t2)}

/* Detail table */
.dtbl{border-collapse:collapse;width:100%}
.dtbl th,.dtbl td{padding:10px 14px;text-align:left;font-size:12px;white-space:nowrap}
.dtbl th{color:var(--t2);font-weight:600;border-bottom:1px solid var(--border);background:var(--bg2)}
.dtbl tbody tr{border-top:1px solid rgba(255,255,255,.04);transition:background .12s}
.dtbl tbody tr:hover{background:var(--glass)}
.mono{font-family:'SF Mono','Fira Code',monospace}

/* Toast */
.toasts{position:fixed;bottom:24px;right:24px;display:flex;flex-direction:column;gap:8px;z-index:900}
.toast{padding:11px 16px;border-radius:var(--rs);font-size:13px;display:flex;
  align-items:center;gap:8px;max-width:320px;box-shadow:0 8px 32px rgba(0,0,0,.4);animation:tin .25s ease}
@keyframes tin{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:translateX(0)}}
.t-ok{background:rgba(52,211,153,.12);border:1px solid rgba(52,211,153,.25);color:var(--green)}
.t-err{background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.25);color:var(--red)}
.t-info{background:rgba(79,142,247,.12);border:1px solid rgba(79,142,247,.25);color:var(--accent)}

/* Modal */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px);
  display:flex;align-items:center;justify-content:center;z-index:800;
  opacity:0;pointer-events:none;transition:opacity .2s}
.overlay.on{opacity:1;pointer-events:auto}
.modal{background:var(--bg1);border:1px solid var(--border2);border-radius:var(--r);
  padding:28px;max-width:400px;width:90%;box-shadow:0 24px 64px rgba(0,0,0,.5);
  transform:scale(.96);transition:transform .2s}
.overlay.on .modal{transform:scale(1)}
.modal h2{font-size:17px;font-weight:700;margin-bottom:8px}
.modal p{font-size:13px;color:var(--t2);margin-bottom:24px;line-height:1.6}
.modal-act{display:flex;gap:8px;justify-content:flex-end}

/* Responsive */
@media(max-width:640px){
  .wrap{padding:16px 14px 80px}
  header{flex-direction:column;align-items:flex-start;gap:12px}
  .dmeta{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="brand">
    <div class="brand-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round">
        <circle cx="12" cy="12" r="3"/>
        <path d="M6.3 6.3a8 8 0 0 0 0 11.4M17.7 6.3a8 8 0 0 1 0 11.4M3.5 3.5a13 13 0 0 0 0 17M20.5 3.5a13 13 0 0 1 0 17"/>
      </svg>
    </div>
    <div>
      <h1>Sonos Debugger</h1>
      <p>Network Diagnostics</p>
    </div>
  </div>
  <div id="hdr-status"></div>
</header>

<div class="card scan-panel">
  <div class="row">
    <span class="row-label">Subnets</span>
    <div class="tags" id="tags"></div>
    <div class="add-sub">
      <input type="text" id="sub-inp" placeholder="10.0.0.0/24" />
      <button class="btn btn-ghost btn-sm" onclick="addSubnet()">+ Tilføj</button>
    </div>
  </div>
  <div class="row">
    <span class="row-label"></span>
    <button class="btn btn-primary" id="scan-btn" onclick="startScan()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
      Scan netværk
    </button>
    <button class="btn btn-ghost btn-sm" onclick="clearAll()">Ryd</button>
  </div>
  <div class="prog-area" id="prog">
    <div class="prog-info">
      <div style="display:flex;align-items:center;gap:8px">
        <span class="dot"></span>
        <span id="prog-txt">Scanner...</span>
      </div>
      <span id="prog-cnt" style="font-family:monospace;font-size:11px"></span>
    </div>
    <div class="prog-track"><div class="prog-fill" id="prog-fill" style="width:0%"></div></div>
  </div>
</div>

<div class="sec" id="dev-sec">
  <div class="sec-hdr">
    <div class="sec-title">
      Enheder
      <span class="badge b-count" id="dev-count">0</span>
    </div>
    <button class="btn btn-ghost btn-sm" id="topo-btn" onclick="loadTopo()" style="display:none">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="5" cy="12" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="M7 12h10M17 7l-8 4M17 17l-8-4"/></svg>
      Vis topologi
    </button>
  </div>
  <div class="grid" id="grid">
    <div class="empty">
      <div class="empty-ico">🔊</div>
      <h3>Ingen enheder fundet endnu</h3>
      <p>Klik "Scan netværk" for at søge efter Sonos-enheder. Tilføj ekstra subnets hvis enheder er på andre VLAN.</p>
    </div>
  </div>
</div>

<div class="sec topo-sec" id="topo-sec">
  <div class="sec-hdr">
    <div class="sec-title">Netværkstopologi</div>
    <a class="btn btn-ghost btn-sm" id="matrix-link" href="#" target="_blank">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
      Signalmatrix
    </a>
  </div>
  <div id="topo-body"></div>
</div>

</div>

<div class="toasts" id="toasts"></div>

<div class="overlay" id="modal-overlay" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <h2>Genstart enhed</h2>
    <p id="modal-txt"></p>
    <div class="modal-act">
      <button class="btn btn-ghost" onclick="closeModal()">Annuller</button>
      <button class="btn btn-danger" id="modal-ok">Genstart</button>
    </div>
  </div>
</div>

<script>
const devices = new Map();
let subnets = [];
let evtSrc = null;
let firstDeviceIp = null;

// ── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  try {
    const d = await fetch('/api/defaults').then(r => r.json());
    subnets = d.subnets.length ? d.subnets : ['192.168.1.0/24'];
  } catch { subnets = ['192.168.1.0/24']; }
  renderTags();
  document.getElementById('sub-inp').addEventListener('keydown', e => { if(e.key==='Enter') addSubnet(); });
}

// ── Subnets ───────────────────────────────────────────────────────────────────
function renderTags() {
  document.getElementById('tags').innerHTML = subnets.map((s, i) =>
    '<div class="tag">' + esc(s) +
    '<button onclick="removeSubnet(' + i + ')" title="Fjern">&#x2715;</button></div>'
  ).join('');
}

function addSubnet() {
  const inp = document.getElementById('sub-inp');
  const v = inp.value.trim();
  if (!v) return;
  if (!/^\\d+\\.\\d+\\.\\d+\\.\\d+\\/\\d+$/.test(v)) { toast('Ugyldigt format — brug fx 192.168.1.0/24', 'err'); return; }
  if (!subnets.includes(v)) { subnets.push(v); renderTags(); }
  inp.value = '';
}

function removeSubnet(i) { subnets.splice(i, 1); renderTags(); }

// ── Scan ──────────────────────────────────────────────────────────────────────
function startScan() {
  if (!subnets.length) { toast('Tilføj mindst ét subnet', 'err'); return; }
  if (evtSrc) { evtSrc.close(); evtSrc = null; }

  document.getElementById('scan-btn').disabled = true;
  document.getElementById('prog').classList.add('on');
  document.getElementById('prog-fill').style.width = '0%';
  setTxt('Starter scan...');

  const url = '/api/scan?subnets=' + encodeURIComponent(subnets.join(','));
  evtSrc = new EventSource(url);

  evtSrc.addEventListener('subnet_start', e => {
    const d = JSON.parse(e.data);
    setTxt('Scanner ' + d.subnet + ' (' + d.total + ' IP\'er)...');
  });
  evtSrc.addEventListener('progress', e => {
    const d = JSON.parse(e.data);
    const pct = d.total > 0 ? Math.round(d.scanned / d.total * 100) : 50;
    document.getElementById('prog-fill').style.width = pct + '%';
    document.getElementById('prog-cnt').textContent = d.scanned + '/' + d.total;
  });
  evtSrc.addEventListener('device', e => {
    const dev = JSON.parse(e.data);
    if (!firstDeviceIp) firstDeviceIp = dev.ip;
    devices.set(dev.ip, dev);
    renderCard(dev);
    updateCount();
    toast('Fandt: ' + (dev.roomName || dev.name || dev.ip), 'ok');
  });
  evtSrc.addEventListener('subnet_error', e => {
    const d = JSON.parse(e.data);
    toast('Subnet fejl ' + d.subnet + ': ' + d.message, 'err');
  });
  evtSrc.addEventListener('done', e => {
    const d = JSON.parse(e.data);
    scanDone(d.count);
  });
  evtSrc.onerror = () => scanDone(-1);
}

function scanDone(count) {
  document.getElementById('scan-btn').disabled = false;
  document.getElementById('prog').classList.remove('on');
  if (evtSrc) { evtSrc.close(); evtSrc = null; }
  if (count === 0) toast('Ingen Sonos-enheder fundet', 'info');
  else if (count > 0) {
    toast('Scan færdig — ' + count + ' enhed(er) fundet', 'ok');
    document.getElementById('topo-btn').style.display = '';
  }
}

function setTxt(t) { document.getElementById('prog-txt').textContent = t; }

function clearAll() {
  devices.clear(); firstDeviceIp = null;
  document.getElementById('grid').innerHTML =
    '<div class="empty"><div class="empty-ico">🔊</div>' +
    '<h3>Ingen enheder fundet endnu</h3>' +
    '<p>Klik "Scan netværk" for at søge efter Sonos-enheder.</p></div>';
  document.getElementById('dev-count').textContent = '0';
  document.getElementById('topo-btn').style.display = 'none';
  document.getElementById('topo-sec').classList.remove('on');
}

// ── Device cards ──────────────────────────────────────────────────────────────
const ICONS = { arc:'🔊',beam:'🔊',ray:'🔊',playbar:'🔊',
  move:'📱',roam:'📱','era 100':'🎵','era 300':'🎵',
  one:'🎵','play:1':'🎵','play:3':'🎵','play:5':'🎵',five:'🎵',
  sub:'💿',amp:'🎛',port:'🎛',connect:'🎛' };

function devIcon(model) {
  if (!model) return '🔈';
  const m = model.toLowerCase();
  for (const [k,v] of Object.entries(ICONS)) if (m.includes(k)) return v;
  return '🔈';
}

function renderCard(dev) {
  const grid = document.getElementById('grid');
  const empty = grid.querySelector('.empty');
  if (empty) empty.remove();
  const old = grid.querySelector('[data-ip="' + dev.ip + '"]');
  if (old) old.remove();

  const modelStr = [dev.model, dev.modelNumber].filter(Boolean).join(' ');
  const card = document.createElement('div');
  card.className = 'dcard card';
  card.dataset.ip = dev.ip;
  card.innerHTML =
    '<div class="dcard-hdr">' +
      '<div class="dicon">' + devIcon(dev.model) + '</div>' +
      '<div class="dname">' +
        '<h3>' + esc(dev.name || dev.ip) + '</h3>' +
        '<p>' + esc(dev.roomName !== dev.name ? dev.roomName : (dev.description || modelStr || '')) + '</p>' +
      '</div>' +
      '<div class="sdot" id="dot-' + dev.ip.replace(/\\./g,'_') + '" title="Online"></div>' +
    '</div>' +
    '<div class="dmeta">' +
      '<div class="mitem"><div class="mlabel">IP-adresse</div><div class="mval mono">' + esc(dev.ip) + '</div></div>' +
      '<div class="mitem"><div class="mlabel">Model</div><div class="mval">' + esc(modelStr || '—') + '</div></div>' +
      (dev.softwareVersion ? '<div class="mitem"><div class="mlabel">Software</div><div class="mval mono">' + esc(dev.softwareVersion) + '</div></div>' : '') +
      (dev.serialNumber ? '<div class="mitem"><div class="mlabel">Serienr.</div><div class="mval mono" style="font-size:10px">' + esc(dev.serialNumber) + '</div></div>' : '') +
    '</div>' +
    '<div class="dtags" id="dtags-' + dev.ip.replace(/\\./g,'_') + '"></div>' +
    '<div class="dact">' +
      '<a class="btn btn-ghost btn-sm" href="http://' + dev.ip + ':1400" target="_blank">' +
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>' +
        'Web UI' +
      '</a>' +
      '<button class="btn btn-ghost btn-sm" onclick="loadTopoFrom(\'' + dev.ip + '\')">' +
        'Topologi' +
      '</button>' +
      '<button class="btn btn-danger btn-sm" onclick="confirmReboot(\'' + dev.ip + '\',' + JSON.stringify(esc(dev.name||dev.ip)) + ')">' +
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.5"/></svg>' +
        'Reboot' +
      '</button>' +
    '</div>';

  grid.appendChild(card);
  loadDeviceTags(dev.ip);
}

async function loadDeviceTags(ip) {
  try {
    const { groups } = await fetch('/api/device/' + ip + '/topology').then(r => r.json());
    if (!groups) return;
    const key = ip.replace(/\\./g,'_');
    const el = document.getElementById('dtags-' + key);
    if (!el) return;
    for (const g of groups) {
      for (const m of g.members) {
        if (m.ip !== ip) continue;
        const tags = [];
        const wm = parseInt(m.wirelessMode || '0');
        if (m.wifiEnabled === '0' || wm === 0) tags.push('<span class="badge b-green">⬡ Kablet</span>');
        else if (wm === 2) tags.push('<span class="badge b-purple">⬡ SonosNet</span>');
        else tags.push('<span class="badge b-blue">⬡ WiFi</span>');
        if (m.isCoordinator) tags.push('<span class="badge b-yellow">★ Koordinator</span>');
        if (m.behindExtender) tags.push('<span class="badge b-yellow">↑ Extender</span>');
        if (m.channelFreq) {
          const ghz = parseInt(m.channelFreq) > 5000 ? '5 GHz' : '2.4 GHz';
          tags.push('<span class="badge b-count">' + ghz + '</span>');
        }
        el.innerHTML = tags.join('');
        return;
      }
    }
  } catch {}
}

function updateCount() {
  document.getElementById('dev-count').textContent = devices.size;
}

// ── Topology ──────────────────────────────────────────────────────────────────
async function loadTopo() {
  if (!firstDeviceIp) { toast('Ingen enheder at hente topologi fra', 'err'); return; }
  await loadTopoFrom(firstDeviceIp);
}

async function loadTopoFrom(ip) {
  try {
    toast('Henter topologi fra ' + ip + '...', 'info');
    const { groups } = await fetch('/api/device/' + ip + '/topology').then(r => r.json());
    if (!groups || !groups.length) throw new Error('Ingen topologidata returneret');
    renderTopo(groups, ip);
    document.getElementById('topo-sec').classList.add('on');
    document.getElementById('matrix-link').href = 'http://' + ip + ':1400/support/review';
    document.getElementById('topo-sec').scrollIntoView({ behavior:'smooth', block:'start' });
    toast('Topologi opdateret', 'ok');
  } catch(e) {
    toast('Topologi fejl: ' + e.message, 'err');
  }
}

function connLabel(m) {
  const wm = parseInt(m.wirelessMode || '0');
  if (m.wifiEnabled === '0' || wm === 0) return '🟢 Kablet';
  if (wm === 2) return '🟣 SonosNet';
  return '🔵 WiFi';
}

function renderTopo(groups, sourceIp) {
  const members = groups.flatMap(g => g.members.filter(m => !m.invisible));
  let html = '';

  // Zone groups
  html += '<h3 style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--t3);margin-bottom:14px">Zonegrupper</h3>';
  html += '<div class="zone-wrap">';
  for (const g of groups) {
    const vis = g.members.filter(m => !m.invisible);
    if (!vis.length) continue;
    const coord = vis.find(m => m.isCoordinator);
    html += '<div class="zone-card card"><div class="zone-hdr">🎵 ' + esc(coord ? coord.name : 'Gruppe') + '</div>';
    for (const m of vis) {
      const wm = parseInt(m.wirelessMode || '0');
      const ico = (m.wifiEnabled === '0' || wm === 0) ? '🟢' : wm === 2 ? '🟣' : '🔵';
      const freq = m.channelFreq ? ' · ' + (parseInt(m.channelFreq) > 5000 ? '5 GHz' : '2.4 GHz') : '';
      html += '<div class="zmem"><div class="zmem-ico">' + ico + '</div>' +
        '<div class="zmem-info"><h4>' + esc(m.name || '—') + '</h4>' +
        '<p>' + esc(m.ip || '—') + freq + '</p></div>' +
        (m.isCoordinator ? '<span class="crown" title="Koordinator">👑</span>' : '') +
        '</div>';
    }
    html += '</div>';
  }
  html += '</div>';

  // Matrix
  if (members.length > 1) {
    html += '<h3 style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--t3);margin:28px 0 14px">Forbindelsesmatrix</h3>';
    html += '<div class="card" style="padding:20px">';
    html += '<div class="mat-wrap"><table class="mat"><thead><tr><th class="rh"></th>';
    for (const m of members) html += '<th title="' + esc(m.ip||'') + '">' + esc(m.name||m.ip||'?') + '</th>';
    html += '</tr></thead><tbody>';
    for (const row of members) {
      html += '<tr><th class="rh">' + esc(row.name||row.ip||'?') + '</th>';
      for (const col of members) {
        if (row.uuid === col.uuid) {
          html += '<td><div class="mcell c-self" title="' + esc(row.name) + '">•</div></td>';
        } else {
          const sameGroup = groups.some(g =>
            g.members.some(m => m.uuid === row.uuid) &&
            g.members.some(m => m.uuid === col.uuid)
          );
          const rowWired = parseInt(row.wirelessMode||'0') === 0 || row.wifiEnabled === '0';
          let cls, ico, tip;
          if (!sameGroup) { cls = 'c-none'; ico = '·'; tip = 'Forskellig gruppe'; }
          else if (rowWired) { cls = 'c-wired'; ico = '⬡'; tip = 'Kablet · Samme gruppe'; }
          else if (row.isCoordinator || col.isCoordinator) { cls = 'c-coord'; ico = '★'; tip = 'Koordinator · Samme gruppe'; }
          else { cls = 'c-wifi'; ico = '⬡'; tip = connLabel(row) + ' · Samme gruppe'; }
          html += '<td><div class="mcell ' + cls + '" title="' + esc(tip) + '">' + ico + '</div></td>';
        }
      }
      html += '</tr>';
    }
    html += '</tbody></table></div>';
    html += '<div class="legend">' +
      '<div class="li"><div class="mcell c-wired" style="width:24px;height:24px;font-size:12px">⬡</div> Kablet + samme gruppe</div>' +
      '<div class="li"><div class="mcell c-wifi" style="width:24px;height:24px;font-size:12px">⬡</div> Trådløs + samme gruppe</div>' +
      '<div class="li"><div class="mcell c-coord" style="width:24px;height:24px;font-size:12px">★</div> Koordinator-relation</div>' +
      '<div class="li"><div class="mcell c-none" style="width:24px;height:24px;font-size:12px">·</div> Ingen direkte relation</div>' +
      '</div>';
    html += '</div>';
  }

  // Detail table
  html += '<h3 style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--t3);margin:28px 0 14px">Enhedsdetaljer</h3>';
  html += '<div class="card" style="overflow:hidden"><table class="dtbl">';
  html += '<thead><tr><th>Enhed</th><th>IP</th><th>Forbindelse</th><th>Kanal</th><th>Software</th><th>Gruppe</th></tr></thead><tbody>';
  for (const m of members) {
    const gIdx = groups.findIndex(g => g.members.some(mm => mm.uuid === m.uuid));
    const freq = m.channelFreq ? (parseInt(m.channelFreq) > 5000 ? '5 GHz' : '2.4 GHz') : '—';
    html += '<tr>' +
      '<td style="font-weight:600">' + (m.isCoordinator ? '👑 ' : '') + esc(m.name||'—') + '</td>' +
      '<td class="mono">' + esc(m.ip||'—') + '</td>' +
      '<td>' + connLabel(m) + '</td>' +
      '<td>' + freq + '</td>' +
      '<td class="mono" style="font-size:11px">' + esc((m.softwareVersion||'').substring(0,20)) + '</td>' +
      '<td style="color:var(--t2)">' + (gIdx >= 0 ? 'Gruppe ' + (gIdx+1) : '—') + '</td>' +
      '</tr>';
  }
  html += '</tbody></table></div>';

  document.getElementById('topo-body').innerHTML = html;
}

// ── Reboot ────────────────────────────────────────────────────────────────────
function confirmReboot(ip, name) {
  document.getElementById('modal-txt').textContent =
    'Er du sikker på, at du vil genstarte "' + name + '" (' + ip + ')? Enheden vil midlertidigt gå offline.';
  document.getElementById('modal-ok').onclick = () => { closeModal(); doReboot(ip, name); };
  document.getElementById('modal-overlay').classList.add('on');
}

function closeModal() { document.getElementById('modal-overlay').classList.remove('on'); }

async function doReboot(ip, name) {
  toast('Sender reboot-kommando til ' + name + '...', 'info');
  try {
    const r = await fetch('/api/device/' + ip + '/reboot', { method:'POST' });
    const d = await r.json();
    if (d.success) {
      toast('✓ Reboot sendt til ' + name, 'ok');
      const key = ip.replace(/\\./g,'_');
      const dot = document.getElementById('dot-' + key);
      if (dot) { dot.classList.add('off'); dot.title = 'Genstarter...'; }
    } else {
      toast('Reboot fejlede: ' + (d.error||'Ukendt fejl'), 'err');
    }
  } catch(e) { toast('Netværksfejl: ' + e.message, 'err'); }
}

// ── Toasts ────────────────────────────────────────────────────────────────────
function toast(msg, type) {
  const c = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = 'toast t-' + (type||'info');
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity .3s,transform .3s';
    el.style.opacity = '0'; el.style.transform = 'translateX(16px)';
    setTimeout(() => el.remove(), 320);
  }, 4200);
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

init();
</script>
</body>
</html>`;
