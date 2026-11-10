// terminal-ws.js: gateway WebSocket <-> Telnet ke OLT untuk halaman "Terminal OLT".
// Install: npm i ws   (tidak perlu ssh2)
//
// Pasang di server.js (server harus berupa http.Server):
//   const server = http.createServer(app);   // atau: const server = app.listen(PORT)
//   require('./terminal-ws')(server, {
//     verifyToken: async (token) => /* verifikasi sama seperti /api/auth/verify */ { username, role },
//     getOlt: async (name) => /* dari config OLT yang sama dengan push Telnet */ { name, host, port: 23, username, password },
//   });
//   server.listen(PORT);
// Nginx: untuk location /ws/terminal tambahkan proxy_http_version 1.1; Upgrade/Connection header; proxy_read_timeout 3600s;
const { WebSocketServer } = require('ws');
const net = require('net');
const { StringDecoder } = require('string_decoder');

const IAC = 255, DONT = 254, DO = 253, WONT = 252, WILL = 251, SB = 250, SE = 240, NAWS = 31, ECHO = 1, SGA = 3;

module.exports = function attachOltTerminal(server, o) {
  const { path = '/ws/terminal', verifyToken, getOlt, allowedRoles = ['admin', 'operator'],
          idleMs = 15 * 60 * 1000, maxPerUser = 3, audit = console.log } = o;
  const wss = new WebSocketServer({ server, path, maxPayload: 64 * 1024 });
  const sessions = new Map(); // username -> jumlah sesi aktif

  wss.on('connection', (ws, req) => {
    const origin = req.headers.origin;
    if (origin) { try { if (new URL(origin).host !== req.headers.host) return ws.close(1008, 'origin'); } catch { return ws.close(1008); } }

    const send = m => ws.readyState === 1 && ws.send(JSON.stringify(m));
    const fail = msg => { send({ type: 'status', state: 'err', message: msg }); ws.close(); };
    let user = null, sock = null, idle = null, counted = false, oltName = '';
    let size = { cols: 80, rows: 24 }, nawsOn = false;
    const touch = () => { clearTimeout(idle); idle = setTimeout(() => fail('Idle timeout'), idleMs); };
    const authTimer = setTimeout(() => ws.close(1008, 'auth timeout'), 5000);
    const sendSize = () => nawsOn && sock && sock.write(Buffer.from([IAC, SB, NAWS, size.cols >> 8, size.cols & 255, size.rows >> 8, size.rows & 255, IAC, SE]));

    // Buang urutan IAC dari server, jawab negosiasi seperlunya, kembalikan teks bersih.
    let carry = Buffer.alloc(0);
    const filter = chunk => {
      const b = Buffer.concat([carry, chunk]); carry = Buffer.alloc(0);
      const out = [];
      for (let i = 0; i < b.length;) {
        if (b[i] !== IAC) { out.push(b[i++]); continue; }
        if (i + 1 >= b.length) { carry = b.subarray(i); break; }
        const c = b[i + 1];
        if (c === IAC) { out.push(255); i += 2; }
        else if (c >= WILL && c <= DONT) {
          if (i + 2 >= b.length) { carry = b.subarray(i); break; }
          const opt = b[i + 2], reply = x => sock.write(Buffer.from([IAC, x, opt]));
          if (c === DO && opt === NAWS) { nawsOn = true; reply(WILL); sendSize(); }
          else if (c === DO && opt === SGA) reply(WILL);
          else if (c === WILL && (opt === ECHO || opt === SGA)) reply(DO);
          else if (c === DO) reply(WONT);
          else if (c === WILL) reply(DONT);
          i += 3;
        } else if (c === SB) {
          const e = b.indexOf(Buffer.from([IAC, SE]), i + 2);
          if (e < 0) { carry = b.subarray(i); break; }
          i = e + 2;
        } else i += 2;
      }
      return Buffer.from(out);
    };

    ws.on('message', async raw => {
      let m; try { m = JSON.parse(raw); } catch { return; }
      if (!user) {
        if (m.type !== 'auth') return;
        try { user = await verifyToken(m.token); } catch { user = null; }
        if (!user || !allowedRoles.includes(user.role)) { user = null; return fail('Akses ditolak'); }
        clearTimeout(authTimer); touch();
        return send({ type: 'ready' });
      }
      touch();
      if (m.type === 'connect' && !sock) {
        const olt = await getOlt(String(m.olt));
        if (!olt) return fail('OLT tidak ditemukan');
        const n = sessions.get(user.username) || 0;
        if (n >= maxPerUser) return fail('Terlalu banyak sesi terbuka');
        sessions.set(user.username, n + 1); counted = true; oltName = olt.name;
        size = { cols: m.cols | 0 || 80, rows: m.rows | 0 || 24 };

        sock = net.connect({ host: olt.host, port: olt.port || olt.telnetPort || 23 });
        sock.setTimeout(15000, () => fail('Telnet: timeout'));
        const dec = new StringDecoder('utf8');
        let seen = '', sentUser = false, sentPass = false;
        sock.on('connect', () => {
          sock.setTimeout(0);
          send({ type: 'status', state: 'on', message: 'Terhubung: ' + oltName });
          audit(`[olt-terminal] OPEN user=${user.username} olt=${oltName} ip=${req.socket.remoteAddress}`);
        });
        sock.on('data', d => {
          const text = dec.write(filter(d));
          if (!text) return;
          send({ type: 'data', d: text });
          // auto-login: hanya di awal sesi, sekali untuk username dan sekali untuk password
          if (!sentPass) {
            seen = (seen + text).slice(-120);
            if (!sentUser && /(user ?name|login)\s*:\s*$/i.test(seen)) { sentUser = true; seen = ''; sock.write(olt.username + '\r\n'); }
            else if (sentUser && /password\s*:\s*$/i.test(seen)) { sentPass = true; seen = ''; sock.write(olt.password + '\r\n'); }
          }
        });
        sock.on('error', e => fail('Telnet: ' + e.message));
        sock.on('close', () => ws.close());
      } else if (m.type === 'data' && sock) sock.write(String(m.d).replace(/\r/g, '\r\0'));
      else if (m.type === 'resize') { size = { cols: m.cols | 0 || 80, rows: m.rows | 0 || 24 }; sendSize(); }
      else if (m.type === 'close') ws.close();
    });

    ws.on('close', () => {
      clearTimeout(idle); clearTimeout(authTimer);
      if (sock) sock.destroy();
      if (counted) { const n = (sessions.get(user.username) || 1) - 1; n ? sessions.set(user.username, n) : sessions.delete(user.username); }
      if (user && oltName) audit(`[olt-terminal] CLOSE user=${user.username} olt=${oltName}`);
    });
  });
};
