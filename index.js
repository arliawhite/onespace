'use strict';

/**
 * Safe / audited rewrite of the original script.
 *
 * Security defaults:
 *  - AUTO_ACCESS default: false
 *  - No automatic download+execution of remote binaries unless ALLOW_RUN_REMOTE_BINARY=true and a checksum is provided
 *  - Use dns.resolve4 (with optionally configured DNS servers). DoH used only as fallback if configured.
 *  - Safer parsing with bounds checks for VLESS/TROJAN.
 */

const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios').default;
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { spawn, execFile } = require('child_process');
const { WebSocketServer, WebSocket } = require('ws');
const { createWebSocketStream } = require('ws');
const dns = require('dns').promises;

// ---- Environment and safe defaults ----
const UUID = (process.env.UUID || 'xiaojie666').trim();
const NEZHA_SERVER = (process.env.NEZHA_SERVER || '').trim(); // e.g. nz.example.com:8008
const NEZHA_PORT = (process.env.NEZHA_PORT || '').trim();
const NEZHA_KEY = (process.env.NEZHA_KEY || '').trim();
const DOMAIN = (process.env.DOMAIN || '').trim(); // recommended: validated, no scheme
const AUTO_ACCESS = (process.env.AUTO_ACCESS === 'true'); // default false - explicit opt-in
const WSPATH = (process.env.WSPATH || UUID.slice(0, 8)).replace(/^\//, '');
const SUB_PATH = (process.env.SUB_PATH || 'sub').replace(/^\//, '');
const NAME = (process.env.NAME || 'Hug').replace(/[#\n\r]/g, '');
const PORT = Number(process.env.PORT || 7860);
const ALLOW_RUN_REMOTE_BINARY = (process.env.ALLOW_RUN_REMOTE_BINARY === 'true'); // must be explicitly true
const EXPECTED_BINARY_SHA256 = (process.env.EXPECTED_BINARY_SHA256 || '').trim().toLowerCase(); // hex string
const DOWNLOAD_BASE = (process.env.DOWNLOAD_BASE || 'https://arm64.ssss.nyc.mn'); // override if needed
const DNS_SERVERS = (process.env.DNS_SERVERS || '8.8.4.4,1.1.1.1').split(',').map(s => s.trim()).filter(Boolean);

// Validate basic env
if (!UUID) {
  console.error('ERROR: UUID is required.');
  process.exit(1);
}
if (!DOMAIN) {
  console.warn('WARN: DOMAIN not set — some features (subscription generation, AUTO_ACCESS) will be disabled.');
}

// ---- ISP metadata (best-effort) ----
let ISP = 'Unknown';
(async function getISP() {
  try {
    const resp = await axios.get('https://speed.cloudflare.com/meta', { timeout: 3000 });
    const data = resp.data || {};
    ISP = `${data.country || 'XX'}-${(data.asOrganization || data.asn || 'Unknown')}`.replace(/\s+/g, '_');
    // keep ISP short
    ISP = ISP.slice(0, 120);
  } catch (e) {
    ISP = 'Unknown';
  }
})();

// ---- HTTP server (routes: / and /SUB_PATH) ----
const httpServer = http.createServer(async (req, res) => {
  try {
    if (!req.url) req.url = '/';
    if (req.url === '/') {
      const filePath = path.join(__dirname, 'index.html');
      if (fs.existsSync(filePath)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        fs.createReadStream(filePath).pipe(res);
      } else {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('OK\n');
      }
      return;
    }

    // subscription endpoint
    if (req.url === `/${SUB_PATH}`) {
      if (!DOMAIN) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('DOMAIN is not configured\n');
        return;
      }
      // build vless/trojan subscription strings
      const vlessURL = `vless://${encodeURIComponent(UUID)}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${encodeURIComponent(WSPATH)}#${encodeURIComponent(NAME + '-' + ISP)}`;
      const trojanURL = `trojan://${encodeURIComponent(UUID)}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${encodeURIComponent(WSPATH)}#${encodeURIComponent(NAME + '-' + ISP)}`;
      const subscription = `${vlessURL}\n${trojanURL}\n`;
      const base64Content = Buffer.from(subscription, 'utf8').toString('base64');
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(base64Content + '\n');
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found\n');
  } catch (err) {
    console.error('HTTP handler error:', err && err.message);
    try {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Internal Server Error\n');
    } catch (e) {}
  }
});

// ---- WebSocket server ----
const wss = new WebSocketServer({ server: httpServer });

// helper: safe ipv4 check
function isIPv4String(s) {
  return /^(25[0-5]|2[0-4]\d|1?\d{1,2})(\.(25[0-5]|2[0-4]\d|1?\d{1,2})){3}$/.test(s);
}

// Resolve host with local DNS first, optional custom DNS servers, fallback to DoH if configured
async function resolveHost(host) {
  if (!host) throw new Error('empty host');
  if (isIPv4String(host)) return host;

  // configure dns servers if provided
  try {
    if (DNS_SERVERS && DNS_SERVERS.length) {
      dns.setServers(DNS_SERVERS);
    }
  } catch (e) {
    // ignore
  }

  try {
    const addrs = await dns.resolve4(host, { ttl: false });
    if (addrs && addrs.length) return addrs[0];
  } catch (err) {
    // fallback to DoH (optional)
    if (process.env.ENABLE_DOH === 'true') {
      try {
        const dohUrl = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
        const resp = await axios.get(dohUrl, {
          timeout: 5000,
          headers: { Accept: 'application/dns-json' }
        });
        const data = resp.data;
        if (data && data.Status === 0 && Array.isArray(data.Answer)) {
          const ipRec = data.Answer.find(r => r.type === 1);
          if (ipRec) return ipRec.data;
        }
      } catch (e) {
        // ignore fallback failure
      }
    }
    throw new Error(`Failed to resolve ${host}`);
  }

  throw new Error(`No A record for ${host}`);
}

// Safe buffer reader: checks lengths before reading
class BufferReader {
  constructor(buf) {
    this.buf = buf;
    this.offset = 0;
  }
  remaining() { return this.buf.length - this.offset; }
  ensure(n) {
    if (this.remaining() < n) throw new Error('Insufficient buffer length');
  }
  readUInt8() { this.ensure(1); return this.buf[this.offset++]; }
  readUInt16BE() { this.ensure(2); const v = this.buf.readUInt16BE(this.offset); this.offset += 2; return v; }
  readBytes(n) { this.ensure(n); const b = this.buf.slice(this.offset, this.offset + n); this.offset += n; return b; }
  readString(n) { return this.readBytes(n).toString('utf8'); }
}

// VLESS connection handling (robust, with bounds checks)
async function handleVlessConnection(ws, firstBuf) {
  try {
    const br = new BufferReader(firstBuf);
    const version = br.readUInt8(); // 0x00
    const id = br.readBytes(16); // uuid
    // check id matches configured uuid
    const cleanedUuidHex = UUID.replace(/-/g, '');
    for (let i = 0; i < 16; i++) {
      const expected = parseInt(cleanedUuidHex.substr(i * 2, 2), 16);
      if (id[i] !== expected) {
        return false;
      }
    }
    // next byte is cmd/addrlen encoded in original code: replicate safely
    const cmdByte = br.readUInt8();
    // original says: let i = msg.slice(17,18).readUInt8() + 19;
    // to be safe, continue reading port/ATYP with bounds checks
    // read port (2 bytes)
    const port = br.readUInt16BE();
    const atyp = br.readUInt8();
    let host = '';
    if (atyp === 1) {
      // IPv4
      const b = br.readBytes(4);
      host = Array.from(b).join('.');
    } else if (atyp === 3) {
      const len = br.readUInt8();
      host = br.readString(len);
    } else if (atyp === 4) {
      // IPv6 (16 bytes), convert to standard representation
      const ipv6 = br.readBytes(16);
      const parts = [];
      for (let i = 0; i < 16; i += 2) {
        parts.push(ipv6.readUInt16BE(i).toString(16));
      }
      host = parts.join(':');
    } else {
      return false;
    }

    // send response ACK
    ws.send(Buffer.from([version, 0]));

    // pipe duplex
    const duplex = createWebSocketStream(ws, { encoding: 'binary' });
    let resolvedIP;
    try {
      resolvedIP = await resolveHost(host);
    } catch (e) {
      resolvedIP = host; // last resort: try host as given
    }

    const remote = net.connect({ host: resolvedIP, port }, function () {
      // write remaining buffer (if any)
      try {
        const remaining = firstBuf.slice(br.offset);
        if (remaining && remaining.length) remote.write(remaining);
      } catch (e) {}
      duplex.pipe(remote).on('error', () => {}).pipe(duplex).on('error', () => {});
    });
    remote.on('error', () => { try { remote.destroy(); } catch (e) {} });

    return true;
  } catch (err) {
    // parse error or protocol mismatch
    return false;
  }
}

// Trojan handling (robust)
async function handleTrojanConnection(ws, msg) {
  try {
    if (!msg || msg.length < 58) return false;
    // first 56 bytes expected sha224 hex (56 chars)
    const received = msg.slice(0, 56).toString('utf8');
    const possiblePasswords = [ UUID ];
    let matched = false;
    for (const pwd of possiblePasswords) {
      const h = crypto.createHash('sha224').update(pwd).digest('hex');
      if (h === received) { matched = true; break; }
    }
    if (!matched) return false;

    let offset = 56;
    // skip CRLF if present
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    if (offset >= msg.length) return false;

    const cmd = msg[offset];
    if (cmd !== 0x01) return false; // we only handle CONNECT

    offset += 1;
    const atyp = msg[offset++];
    let host = '';
    if (atyp === 0x01) {
      if (offset + 4 > msg.length) return false;
      host = Array.from(msg.slice(offset, offset + 4)).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset++];
      if (offset + hostLen > msg.length) return false;
      host = msg.slice(offset, offset + hostLen).toString('utf8');
      offset += hostLen;
    } else if (atyp === 0x04) {
      if (offset + 16 > msg.length) return false;
      const ipv6 = msg.slice(offset, offset + 16);
      const parts = [];
      for (let i = 0; i < 16; i += 2) parts.push(ipv6.readUInt16BE(i).toString(16));
      host = parts.join(':');
      offset += 16;
    } else {
      return false;
    }
    if (offset + 2 > msg.length) return false;
    const port = msg.readUInt16BE(offset);
    offset += 2;
    // skip optional CRLF
    if (offset + 1 < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;

    const duplex = createWebSocketStream(ws, { encoding: 'binary' });
    let resolvedIP;
    try {
      resolvedIP = await resolveHost(host);
    } catch (e) {
      resolvedIP = host;
    }

    const remote = net.connect({ host: resolvedIP, port }, function () {
      // send remaining bytes if any
      if (offset < msg.length) {
        remote.write(msg.slice(offset));
      }
      duplex.pipe(remote).on('error', () => {}).pipe(duplex).on('error', () => {});
    });

    remote.on('error', () => { try { remote.destroy(); } catch (e) {} });

    return true;
  } catch (err) {
    return false;
  }
}

// WebSocket connection handler
wss.on('connection', (ws, req) => {
  ws.once('message', async (msg) => {
    try {
      // ensure Buffer
      const buf = Buffer.isBuffer(msg) ? msg : Buffer.from(msg);
      if (buf.length > 17 && buf[0] === 0x00) {
        // possible VLESS: check uuid
        const id = buf.slice(1, 17);
        const cleanedUuidHex = UUID.replace(/-/g, '');
        let isVless = true;
        for (let i = 0; i < 16; i++) {
          if (id[i] !== parseInt(cleanedUuidHex.substr(i * 2, 2), 16)) { isVless = false; break; }
        }
        if (isVless) {
          const ok = await handleVlessConnection(ws, buf);
          if (!ok) ws.close();
          return;
        }
      }
      // otherwise try trojan
      const okTro = await handleTrojanConnection(ws, buf);
      if (!okTro) ws.close();
    } catch (e) {
      try { ws.close(); } catch (e) {}
    }
  });

  ws.on('error', () => {});
});

// ---- Safe download + run (opt-in, must provide checksum) ----
function getDownloadUrl() {
  // simple selection by arch (can be overridden via DOWNLOAD_BASE)
  const arch = os.arch();
  if (arch.startsWith('arm')) {
    return `${DOWNLOAD_BASE}/v1`; // example
  } else {
    return `${DOWNLOAD_BASE}/v1`;
  }
}

async function downloadAndVerifyBinary() {
  if (!NEZHA_SERVER || !NEZHA_KEY) {
    console.log('NEZHA vars not provided - skipping download');
    return;
  }

  if (!ALLOW_RUN_REMOTE_BINARY) {
    console.log('ALLOW_RUN_REMOTE_BINARY not enabled - skipping remote binary execution.');
    return;
  }

  if (!EXPECTED_BINARY_SHA256) {
    console.error('EXPECTED_BINARY_SHA256 is required when ALLOW_RUN_REMOTE_BINARY=true. Aborting.');
    return;
  }

  const url = getDownloadUrl();
  const outPath = path.join(__dirname, 'npm.bin');

  try {
    const resp = await axios.get(url, { responseType: 'stream', timeout: 20000 });
    const writer = fs.createWriteStream(outPath, { mode: 0o700 });
    const hash = crypto.createHash('sha256');
    resp.data.on('data', chunk => hash.update(chunk));
    resp.data.pipe(writer);

    await new Promise((resolve, reject) => {
      writer.on('finish', resolve);
      writer.on('error', reject);
      resp.data.on('error', reject);
    });

    const computed = hash.digest('hex').toLowerCase();
    if (computed !== EXPECTED_BINARY_SHA256.toLowerCase()) {
      console.error('Binary checksum mismatch! expected:', EXPECTED_BINARY_SHA256, 'got:', computed);
      try { fs.unlinkSync(outPath); } catch (e) {}
      return;
    }

    // run binary with safe args (use spawn without shell)
    // NOTE: we still avoid running arbitrary shell: prefer execFile/spawn with args.
    const args = [];
    if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
      const tlsPorts = new Set(['443','8443','2096','2087','2083','2053']);
      const useTls = tlsPorts.has(NEZHA_PORT) ? '--tls' : '';
      // example: ./npm.bin -s server:port -p key --disable-auto-update
      args.push('-s', `${NEZHA_SERVER}:${NEZHA_PORT}`, '-p', `${NEZHA_KEY}`);
      if (useTls) args.push(useTls);
      args.push('--disable-auto-update', '--report-delay', '4', '--skip-conn', '--skip-procs');
    } else {
      // config.yaml mode: we create config file (careful: contains secrets)
      const configYaml = [
        `client_secret: ${NEZHA_KEY}`,
        `server: ${NEZHA_SERVER}`,
        `uuid: ${UUID}`,
        `debug: false`,
        `disable_auto_update: true`
      ].join('\n');
      fs.writeFileSync(path.join(__dirname, 'config.yaml'), configYaml, { mode: 0o600 });
      args.push('-c', 'config.yaml');
    }

    // launch detached background process
    const child = spawn(outPath, args, {
      detached: true,
      stdio: 'ignore'
    });
    child.unref();
    console.log('Launched remote binary (detached).');
  } catch (err) {
    console.error('Download/run error:', err && err.message);
    try { fs.unlinkSync(outPath); } catch (e) {}
  }
}

// ---- Automatic add access task (opt-in only) ----
async function addAccessTask() {
  if (!AUTO_ACCESS) return;
  if (!DOMAIN) return;
  try {
    const fullURL = `https://${DOMAIN}/${SUB_PATH}`;
    await axios.post('https://oooo.serv00.net/add-url', { url: fullURL }, { timeout: 6000, headers: { 'Content-Type': 'application/json' }});
    console.log('Automatic Access Task added (remote).');
  } catch (err) {
    console.warn('Failed to add access task:', err && err.message);
  }
}

// ---- Cleanup sensitive files after some time (optional) ----
function delFiles() {
  try { fs.unlinkSync(path.join(__dirname, 'npm.bin')); } catch (e) {}
  try { fs.unlinkSync(path.join(__dirname, 'config.yaml')); } catch (e) {}
}

// ---- server start ----
httpServer.listen(PORT, async () => {
  console.log(`Server listening on ${PORT} (PID ${process.pid})`);
  // spawn only if explicit opt-in and checksum provided
  if (ALLOW_RUN_REMOTE_BINARY) {
    await downloadAndVerifyBinary();
    // schedule cleanup if wanted
    setTimeout(() => { delFiles(); }, 180000); // 3 minutes
  } else {
    // still keep config cleanup delayed in case files exist
    setTimeout(() => { delFiles(); }, 180000);
  }

  // try to add access task if allowed
  await addAccessTask();
});
