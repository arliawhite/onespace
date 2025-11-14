'use strict';
/**
 * server_hf_safe.js
 * 最简安全版本（适用于一般 Node 环境）
 *
 * 本版本修改点：
 *  - 代理功能默认启用（ENABLE_PROXY = true）
 *  - 全文中文注释，便于阅读
 *
 * ⚠ 注意：Cloudflare Pages **不支持 Node.js 后端运行时**，因此此脚本无法在 Pages 部署。
 *    如果你希望在 Cloudflare 生态运行代理服务：
 *        → 只能使用 Cloudflare Workers（但 Workers 禁止创建 TCP 连接，因此也无法作为真实代理）
 *        → 或使用 Cloudflare Tunnel 配合自托管服务器
 *    结论：此代理脚本 **不能** 在 Cloudflare Pages / Workers 运行。
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');
const dns = require('dns').promises;
const { createWebSocketStream } = require('ws');
const WebSocket = require('ws');
const { Buffer } = require('buffer');

// ---- 环境变量（请通过环境注入） ----
const UUID = (process.env.UUID || '').trim();         // 不要在代码里写死
const DOMAIN = (process.env.DOMAIN || '').trim();     // 可选：用于订阅生成
const SUB_PATH = (process.env.SUB_PATH || 'sub').replace(/^\//, '');
const WSPATH = (process.env.WSPATH || (UUID ? UUID.slice(0, 8) : 'path')).replace(/^\//, '');
const NAME = (process.env.NAME || 'Hug').replace(/[\n\r#]/g, '');
const PORT = Number(process.env.PORT || 7860);
const ENABLE_PROXY = true // 默认启用代理功能; // 默认 false —— 必须显式开启
const ALLOWED_OUTBOUND = (process.env.ALLOWED_OUTBOUND || '127.0.0.1,localhost').split(',').map(s => s.trim()).filter(Boolean);
const DNS_SERVERS = (process.env.DNS_SERVERS || '8.8.8.8,1.1.1.1').split(',').map(s => s.trim()).filter(Boolean);

// helper: mask sensitive values for logs
function mask(s) {
  if (!s) return '—';
  if (s.length <= 8) return s.replace(/./g, '*');
  return s.slice(0, 4) + '...' + s.slice(-4);
}

console.log('Starting server (safe-mode)');
console.log('PORT=', PORT, 'ENABLE_PROXY=', ENABLE_PROXY);
if (UUID) console.log('UUID=', mask(UUID));
if (DOMAIN) console.log('DOMAIN=', DOMAIN);

// configure dns servers (best-effort)
try { if (DNS_SERVERS.length) dns.setServers(DNS_SERVERS); } catch (e) { }

// ---- Minimal HTTP server: root and subscription ----
const httpServer = http.createServer((req, res) => {
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

  if (req.url === `/${SUB_PATH}`) {
    if (!UUID || !DOMAIN) {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('UUID or DOMAIN missing in environment\n');
      return;
    }
    const vless = `vless://${encodeURIComponent(UUID)}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=%2F${encodeURIComponent(WSPATH)}#${encodeURIComponent(NAME)}`;
    const trojan = `trojan://${encodeURIComponent(UUID)}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=%2F${encodeURIComponent(WSPATH)}#${encodeURIComponent(NAME)}`;
    const subscription = `${vless}\n${trojan}\n`;
    const b64 = Buffer.from(subscription, 'utf8').toString('base64');
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(b64 + '\n');
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found\n');
});

// ---- WebSocket server (will accept connections but only forward if ENABLE_PROXY=true) ----
const wss = new WebSocket.Server({ server: httpServer });

function isIPv4String(s) {
  return /^(25[0-5]|2[0-4]\d|1?\d{1,2})(\.(25[0-5]|2[0-4]\d|1?\d{1,2})){3}$/.test(s);
}

async function resolveHost(host) {
  if (!host) throw new Error('empty host');
  if (isIPv4String(host)) return host;
  // prefer system resolver
  try {
    const arr = await dns.resolve4(host);
    if (arr && arr.length) return arr[0];
  } catch (e) { /* ignore */ }
  // last resort: return host as-is (may fail when connecting)
  return host;
}

class BufferReader {
  constructor(buf) { this.buf = buf; this.offset = 0; }
  remaining() { return this.buf.length - this.offset; }
  ensure(n) { if (this.remaining() < n) throw new Error('short buffer'); }
  readUInt8() { this.ensure(1); return this.buf[this.offset++]; }
  readUInt16BE() { this.ensure(2); const v = this.buf.readUInt16BE(this.offset); this.offset += 2; return v; }
  readBytes(n) { this.ensure(n); const b = this.buf.slice(this.offset, this.offset + n); this.offset += n; return b; }
  readString(n) { return this.readBytes(n).toString('utf8'); }
}

// check outbound allowed (simple hostname/ip whitelist)
function outboundAllowed(destHost) {
  if (!ALLOWED_OUTBOUND || ALLOWED_OUTBOUND.length === 0) return false;
  // compare by host or ip string
  const hostLower = (destHost || '').toLowerCase();
  return ALLOWED_OUTBOUND.some(a => a.toLowerCase() === hostLower);
}

async function handleVless(ws, buf) {
  // minimal robust parser with checks
  try {
    const br = new BufferReader(buf);
    const version = br.readUInt8();
    const id = br.readBytes(16);
    // optional: validate id against UUID if configured
    if (UUID) {
      const cleaned = UUID.replace(/-/g, '');
      for (let i = 0; i < 16; i++) {
        if (id[i] !== parseInt(cleaned.substr(i * 2, 2), 16)) return false;
      }
    }
    // read port/atyp similarly to original
    const port = br.readUInt16BE();
    const atyp = br.readUInt8();
    let host = '';
    if (atyp === 1) {
      const b = br.readBytes(4); host = Array.from(b).join('.');
    } else if (atyp === 3) {
      const len = br.readUInt8(); host = br.readString(len);
    } else if (atyp === 4) {
      const ipv6 = br.readBytes(16); const parts = []; for (let i=0;i<16;i+=2) parts.push(ipv6.readUInt16BE(i).toString(16)); host = parts.join(':');
    } else return false;

    // respond ack
    ws.send(Buffer.from([version, 0]));

    if (!ENABLE_PROXY) {
      // reject forwarding in safe-mode
      ws.send(Buffer.from('PROXY_DISABLED')); // harmless text message
      ws.close();
      return true;
    }

    // check outbound whitelist
    if (!outboundAllowed(host)) {
      console.warn('Outbound to', host, 'not allowed by ALLOWED_OUTBOUND');
      ws.close();
      return false;
    }

    const duplex = createWebSocketStream(ws, { encoding: 'binary' });
    let resolved;
    try { resolved = await resolveHost(host); } catch (e) { resolved = host; }

    const remote = net.connect({ host: resolved, port }, function () {
      const remaining = buf.slice(br.offset);
      if (remaining && remaining.length) remote.write(remaining);
      duplex.pipe(remote).on('error', ()=>{}).pipe(duplex).on('error', ()=>{});
    });
    remote.on('error', () => { try{ remote.destroy(); }catch(e){} });
    return true;
  } catch (e) {
    return false;
  }
}

async function handleTrojan(ws, buf) {
  try {
    if (!buf || buf.length < 58) return false;
    const receivedHash = buf.slice(0,56).toString('utf8');
    // we do not verify password here strictly; if UUID set, try to match
    if (UUID) {
      const expected = require('crypto').createHash('sha224').update(UUID).digest('hex');
      if (expected !== receivedHash) return false;
    }

    let offset = 56;
    if (buf[offset] === 0x0d && buf[offset+1] === 0x0a) offset += 2;
    const cmd = buf[offset++];
    if (cmd !== 0x01) return false; // only CONNECT
    const atyp = buf[offset++];
    let host='';
    if (atyp === 0x01) { host = Array.from(buf.slice(offset, offset+4)).join('.'); offset+=4; }
    else if (atyp === 0x03) { const l = buf[offset++]; host = buf.slice(offset, offset+l).toString('utf8'); offset += l; }
    else if (atyp === 0x04) { const ipv6 = buf.slice(offset, offset+16); const parts=[]; for (let i=0;i<16;i+=2) parts.push(ipv6.readUInt16BE(i).toString(16)); host = parts.join(':'); offset+=16; }
    else return false;
    if (offset+2>buf.length) return false;
    const port = buf.readUInt16BE(offset); offset+=2;

    if (!ENABLE_PROXY) { ws.send(Buffer.from('PROXY_DISABLED')); ws.close(); return true; }
    if (!outboundAllowed(host)) { ws.close(); return false; }

    const duplex = createWebSocketStream(ws, { encoding: 'binary' });
    let resolved;
    try { resolved = await resolveHost(host); } catch(e) { resolved = host; }

    const remote = net.connect({ host: resolved, port }, function(){
      if (offset < buf.length) remote.write(buf.slice(offset));
      duplex.pipe(remote).on('error', ()=>{}).pipe(duplex).on('error', ()=>{});
    });
    remote.on('error', ()=>{ try{ remote.destroy(); }catch(e){} });
    return true;
  } catch (e) { return false; }
}

wss.on('connection', (ws, req) => {
  ws.once('message', async (msg) => {
    const buf = Buffer.isBuffer(msg) ? msg : Buffer.from(msg);

    // detect VLESS (first byte 0x00 and id matching)
    if (buf.length > 17 && buf[0] === 0x00) {
      const id = buf.slice(1,17);
      if (UUID) {
        const cleaned = UUID.replace(/-/g, '');
        let ok = true;
        for (let i=0;i<16;i++) if (id[i] !== parseInt(cleaned.substr(i*2,2),16)) { ok=false; break; }
        if (ok) {
          const handled = await handleVless(ws, buf);
          if (!handled) ws.close();
          return;
        }
      } else {
        // if no UUID configured, try to parse anyway but be conservative
        const handled = await handleVless(ws, buf);
        if (!handled) ws.close();
        return;
      }
    }

    // otherwise try trojan
    const troOk = await handleTrojan(ws, buf);
    if (!troOk) ws.close();
  });

  ws.on('error', ()=>{});
});

httpServer.listen(PORT, () => {
  console.log(`Safe server listening on :${PORT}`);
  if (!ENABLE_PROXY) console.log('Proxy functionality is DISABLED. Set ENABLE_PROXY=true to enable (not recommended on HF).');
  else console.log('Proxy functionality ENABLED (make sure this host is allowed to make outbound connections).');
});

// export for testing
module.exports = { httpServer, wss };
