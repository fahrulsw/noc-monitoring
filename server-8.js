const express = require('express');
const { Telnet } = require('telnet-client');
const cors = require('cors');
const path = require('path');
const Database = require('better-sqlite3');
const snmp = require('net-snmp');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'nocs-secret-key-ganti-di-production';

const app = express();
app.use(cors());
app.use(express.json());

// ─── AUTH MIDDLEWARE ───
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Token tidak ditemukan' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: 'Token tidak valid atau kadaluarsa' });
  }
}

// ─── STATIC FILES (public bebas akses) ───
app.use(express.static(path.join(__dirname, 'public')));

// ─── SQLITE SETUP ───
const db = new Database(path.join(__dirname, 'history.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS history (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    oltName TEXT,
    slot TEXT,
    port TEXT,
    onuId TEXT,
    sn TEXT,
    lokasi TEXT,
    namaPelanggan TEXT,
    idPppoe TEXT,
    success INTEGER,
    pushed INTEGER,
    elapsed TEXT,
    rxPower TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )
`);

// ─── TABEL CACHE ONU ───
db.exec(`
  CREATE TABLE IF NOT EXISTS onu_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    olt_name    TEXT NOT NULL,
    suffix      TEXT NOT NULL,
    slot        INTEGER,
    port        INTEGER,
    onu_id      INTEGER,
    name        TEXT,
    serial_number TEXT,
    status_code INTEGER,
    status_label TEXT,
    status_color TEXT,
    rx_power    TEXT,
    online      INTEGER,
    last_online  TEXT,
    last_offline TEXT,
    updated_at  TEXT DEFAULT (datetime('now', 'localtime')),
    UNIQUE(olt_name, suffix)
  );
  CREATE TABLE IF NOT EXISTS poll_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    olt_name    TEXT NOT NULL,
    polled_at   TEXT DEFAULT (datetime('now', 'localtime')),
    duration_ms INTEGER,
    onu_count   INTEGER,
    online_count INTEGER,
    success     INTEGER DEFAULT 1,
    error_msg   TEXT
  );
`);

// Migration: tambah kolom rxPower jika belum ada (untuk database lama)
try {
  db.exec(`ALTER TABLE history ADD COLUMN rxPower TEXT`);
} catch(e) { /* kolom sudah ada, abaikan */ }

// ─── TABEL USERS ───
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role    TEXT NOT NULL DEFAULT 'operator',
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )
`);

// ─── TABEL MIKROTIK CONFIG (persisten) ───
db.exec(`
  CREATE TABLE IF NOT EXISTS mikrotik_config (
    name     TEXT PRIMARY KEY,
    host     TEXT NOT NULL,
    port     INTEGER DEFAULT 8728,
    username TEXT NOT NULL,
    password TEXT NOT NULL
  )
`);

// Hash password dengan fixed salt (tidak tergantung JWT_SECRET)
const PW_SALT = 'nocs-pw-salt-2024';
function hashPassword(password) {
  return crypto.createHash('sha256').update(PW_SALT + password + PW_SALT).digest('hex');
}

// Buat akun admin default jika belum ada
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
    .run('admin', hashPassword('admin123'), 'admin');
  console.log('[AUTH] Akun admin default dibuat: admin / admin123');
} else {
  // Jika akun admin ada tapi dibuat dengan salt lama (JWT_SECRET), update hashnya
  // Caranya: coba login dengan hash baru, jika berbeda dari yang tersimpan, reset ke admin123
  const currentHash = adminExists.password_hash;
  const newHash = hashPassword('admin123');
  if (currentHash !== newHash) {
    // Hash lama (pakai JWT_SECRET sebagai salt) - reset ke password default dengan hash baru
    const oldHash = require('crypto').createHash('sha256')
      .update('admin123' + (process.env.JWT_SECRET || 'nocs-secret-key-ganti-di-production'))
      .digest('hex');
    if (currentHash === oldHash) {
      db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(newHash, 'admin');
      console.log('[AUTH] Hash admin dimigrasikan ke format baru (password tetap admin123)');
    }
  }
}

// ─── RESET ADMIN via ENV (darurat) ───
if (process.env.RESET_ADMIN_PASSWORD) {
  db.prepare('UPDATE users SET password_hash = ? WHERE username = ?')
    .run(hashPassword(process.env.RESET_ADMIN_PASSWORD), 'admin');
  console.log('[AUTH] Password admin berhasil direset via RESET_ADMIN_PASSWORD env var');
}

// ─── API: LOGIN ───
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username dan password wajib diisi' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || user.password_hash !== hashPassword(password)) {
    return res.status(401).json({ success: false, message: 'Username atau password salah' });
  }
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
  res.json({ success: true, token, username: user.username, role: user.role });
});

// ─── API: VERIFY TOKEN ───
app.get('/api/auth/verify', requireAuth, (req, res) => {
  res.json({ success: true, user: req.user });
});

// ─── API: LOGOUT ───
app.post('/api/auth/logout', requireAuth, (req, res) => {
  res.json({ success: true, message: 'Logout berhasil' });
});

// ─── API: DAFTAR USER (admin only) ───
app.get('/api/users', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Akses ditolak' });
  const users = db.prepare('SELECT id, username, role, created_at FROM users').all();
  res.json({ success: true, users });
});

// ─── API: TAMBAH USER (admin only) ───
app.post('/api/users', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Akses ditolak' });
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Username dan password wajib' });
  try {
    db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
      .run(username, hashPassword(password), role || 'operator');
    res.json({ success: true, message: 'User ' + username + ' berhasil ditambahkan' });
  } catch(e) {
    res.status(400).json({ success: false, message: 'Username sudah digunakan' });
  }
});

// ─── API: HAPUS USER (admin only) ───
app.delete('/api/users/:id', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Akses ditolak' });
  if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ success: false, message: 'Tidak bisa menghapus akun sendiri' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── API: GANTI PASSWORD ───
app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (user.password_hash !== hashPassword(oldPassword)) {
    return res.status(400).json({ success: false, message: 'Password lama salah' });
  }
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), req.user.id);
  res.json({ success: true, message: 'Password berhasil diubah' });
});


const MAX_HISTORY = 1000;

// ─── TELEGRAM CONFIG ───
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '8472144825:AAHiPFn45XInWpMOJaCiUnYOFl5kPbvsnhQ';
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID   || '-4871262336';
const TELEGRAM_ENABLED   = !!TELEGRAM_BOT_TOKEN && !!TELEGRAM_CHAT_ID;

const OLT_CONFIG = {
  'OLT-C320-DEMPET': {
    host: '10.136.1.1',
    username: 'zte',
    password: 'zte',
    port: 23,
    vendor: 'OLT1',
  },
  'OLT-C300-DEMPET': {
    host: '10.136.3.1',
    username: 'zte',
    password: 'zte',
    port: 233,
    vendor: 'OLT2',
  },
  'OLT-C320-MINTRENG': {
    host: '10.136.20.1',
    username: 'zte',
    password: 'zte',
    port: 233,
    vendor: 'OLT3',
  },
  'OLT-C320-KARANGAWEN': {
    host: '10.136.4.1',
    username: 'zte',
    password: 'zte',
    port: 23,
    vendor: 'OLT4',
  },
};

function generateScript(vendor, params) {
  const { slot, port, onuId, sn, lokasi, namaPelanggan, idPppoe } = params;

  if (vendor === 'OLT1') {
    return [
      `conf t`,
      `interface gpon-olt_1/${slot}/${port}`,
      `onu ${onuId} type ZTE-F609 sn ${sn}`,
      `exit`,
      `interface gpon-onu_1/${slot}/${port}:${onuId}`,
      `name ${lokasi} - ${namaPelanggan}`,
      `description 1$$ ${namaPelanggan} - ${lokasi} $$`,
      `tcont 1 name MTC profile 100M`,
      `gemport 1 name MTC tcont 1`,
      `gemport 1 traffic-limit upstream UP100M downstream DW100M`,
      `service-port 1 vport 1 user-vlan 601 vlan 601`,
      `port-identification format DSL-FORUM-PON sport 1`,
      `pppoe-intermediate-agent enable sport 1`,
      `exit`,
      `pon-onu-mng gpon-onu_1/${slot}/${port}:${onuId}`,
      `service MTC gemport 1 vlan 601`,
      `wan-ip 1 mode pppoe username ${idPppoe}@MERDEKA.NET.ID  password ${idPppoe} vlan-profile PPPoE host 1`,
      `wan-ip 1 ping-response enable traceroute-response enable`,
      `security-mgmt 1 state enable mode forward protocol web`,
      `end`,
      `write`,
      '',
    ].join('\n');
  }

  if (vendor === 'OLT2') {
    return [
      `conf t`,
      `interface gpon-olt_1/${slot}/${port}`,
      `onu ${onuId} type ZTE-F609 sn ${sn}`,
      `exit`,
      `interface gpon-onu_1/${slot}/${port}:${onuId}`,
      `name ${lokasi} - ${namaPelanggan}`,
      `description 1$$ ${namaPelanggan} - ${lokasi} $$`,
      `tcont 1 name MTC profile 100M`,
      `gemport 1 name MTC tcont 1`,
      `gemport 1 traffic-limit upstream UP100M downstream DW100M`,
      `service-port 1 vport 1 user-vlan 602 vlan 602`,
      `port-identification format DSL-FORUM-PON sport 1`,
      `pppoe-intermediate-agent enable sport 1`,
      `exit`,
      `pon-onu-mng gpon-onu_1/${slot}/${port}:${onuId}`,
      `service MTC gemport 1 vlan 602`,
      `wan-ip 1 mode pppoe username ${idPppoe}@MERDEKA.NET.ID  password ${idPppoe} vlan-profile PPPoE host 1`,
      `wan-ip 1 ping-response enable traceroute-response enable`,
      `security-mgmt 1 state enable mode forward protocol web`,
      `end`,
      `write`,
      '',
    ].join('\n');
  }

  if (vendor === 'OLT3') {
    return [
      `conf t`,
      `interface gpon-olt_1/${slot}/${port}`,
      `onu ${onuId} type ZTE-F609 sn ${sn}`,
      `exit`,
      `interface gpon-onu_1/${slot}/${port}:${onuId}`,
      `name ${lokasi} - ${namaPelanggan}`,
      `description 1$$ ${namaPelanggan} - ${lokasi} $$`,
      `tcont 1 name MTC profile 100M`,
      `gemport 1 name MTC tcont 1`,
      `gemport 1 traffic-limit upstream UP100M downstream DW100M`,
      `service-port 1 vport 1 user-vlan 600 vlan 600`,
      `port-identification format DSL-FORUM-PON sport 1`,
      `pppoe-intermediate-agent enable sport 1`,
      `exit`,
      `pon-onu-mng gpon-onu_1/${slot}/${port}:${onuId}`,
      `service MTC gemport 1 vlan 600`,
      `wan-ip 1 mode pppoe username ${idPppoe}@MERDEKA.NET.ID  password ${idPppoe} vlan-profile PPPoE host 1`,
      `wan-ip 1 ping-response enable traceroute-response enable`,
      `security-mgmt 1 state enable mode forward protocol web`,
      `end`,
      `write`,
      '',
    ].join('\n');
  }

  if (vendor === 'OLT4') {
    return [
      `conf t`,
      `interface gpon-olt_1/${slot}/${port}`,
      `onu ${onuId} type ZTE-F609 sn ${sn}`,
      `exit`,
      `interface gpon-onu_1/${slot}/${port}:${onuId}`,
      `name ${lokasi} - ${namaPelanggan}`,
      `description 1$$ ${namaPelanggan} - ${lokasi} $$`,
      `tcont 1 name MTC profile 500M`,
      `gemport 1 name MTC tcont 1`,
      `gemport 1 traffic-limit upstream UP500M downstream DW500M`,
      `service-port 1 vport 1 user-vlan 603 vlan 603`,
      `port-identification format DSL-FORUM-PON sport 1`,
      `pppoe-intermediate-agent enable sport 1`,
      `exit`,
      `pon-onu-mng gpon-onu_1/${slot}/${port}:${onuId}`,
      `service MTC gemport 1 vlan 603`,
      `wan-ip 1 mode pppoe username ${idPppoe}@MERDEKA.NET.ID  password ${idPppoe} vlan-profile PPPoE host 1`,
      `wan-ip 1 ping-response enable traceroute-response enable`,
      `security-mgmt 1 state enable mode forward protocol web`,
      `end`,
      `write`,
      '',
    ].join('\n');
  }

  

  return `! Unknown vendor: ${vendor}`;
}

// ─── API: GET OLTs ───
app.get('/api/olts', requireAuth, (req, res) => {
  const list = Object.entries(OLT_CONFIG).map(([name, cfg]) => ({
    name,
    host: cfg.host,
    port: cfg.port,
    username: cfg.username,
    vendor: cfg.vendor,
  }));
  res.json(list);
});

// ─── API: GET HISTORY ───
app.get('/api/history', requireAuth, (req, res) => {
  try {
    const rows = db.prepare(
      'SELECT * FROM history ORDER BY created_at DESC LIMIT ?'
    ).all(MAX_HISTORY);
    // convert integer booleans back to JS booleans
    const list = rows.map(r => ({
      ...r,
      success: !!r.success,
      pushed: !!r.pushed,
    }));
    res.json({ success: true, history: list });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── API: ADD HISTORY ───
app.post('/api/history', requireAuth, (req, res) => {
  try {
    const {
      id, ts, oltName, slot, port, onuId, sn,
      lokasi, namaPelanggan, idPppoe, success, pushed, elapsed, rxPower
    } = req.body;

    db.prepare(`
      INSERT OR REPLACE INTO history
        (id, ts, oltName, slot, port, onuId, sn, lokasi, namaPelanggan, idPppoe, success, pushed, elapsed, rxPower)
      VALUES
        (@id, @ts, @oltName, @slot, @port, @onuId, @sn, @lokasi, @namaPelanggan, @idPppoe, @success, @pushed, @elapsed, @rxPower)
    `).run({
      id, ts, oltName, slot, port, onuId, sn,
      lokasi, namaPelanggan, idPppoe,
      success: success ? 1 : 0,
      pushed: pushed ? 1 : 0,
      elapsed,
      rxPower: rxPower || null,
    });

    // Trim jika melebihi MAX_HISTORY (hapus yang paling lama)
    const count = db.prepare('SELECT COUNT(*) as c FROM history').get().c;
    if (count > MAX_HISTORY) {
      db.prepare(`
        DELETE FROM history WHERE id IN (
          SELECT id FROM history ORDER BY created_at ASC LIMIT ?
        )
      `).run(count - MAX_HISTORY);
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── API: DELETE ONE HISTORY ───
app.delete('/api/history/:id', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM history WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── API: CLEAR ALL HISTORY ───
app.delete('/api/history', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM history').run();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── TELNET HELPER ───
async function telnetExec(oltCfg, commands, log) {
  const telnet = new Telnet();

  await telnet.connect({
    host: oltCfg.host,
    port: oltCfg.port || 23,
    shellPrompt: /#\s*$/,
    loginPrompt: /Username:/i,
    passwordPrompt: /Password:/i,
    username: oltCfg.username,
    password: oltCfg.password,
    timeout: 15000,
    execTimeout: 8000,
    irs: '\r\n',
    ors: '\r\n',
  });

  log.push(`[OK]   Connected to ${oltCfg.host} via Telnet`);

  for (const cmd of commands) {
    if (!cmd.trim() || cmd.trim().startsWith('!')) continue;
    try {
      const result = await telnet.exec(cmd.trim());
      log.push(`[CMD]  ${cmd.trim()}`);
      if (result && result.trim()) log.push(`[OUT]  ${result.trim()}`);
    } catch (e) {
      log.push(`[WARN] ${cmd.trim()} -> ${e.message}`);
    }
  }

  await telnet.end();
}

// ─── API: ACTIVATE ───
app.post('/api/activate', requireAuth, async (req, res) => {
  const { oltName, slot, port, onuId, sn, lokasi, namaPelanggan, idPppoe, pushToOlt } = req.body;

  if (!oltName || !slot || !port || !onuId || !sn) {
    return res.status(400).json({ success: false, message: 'Field wajib: OLT, Slot, Port, ONU ID, SN' });
  }

  const oltCfg = OLT_CONFIG[oltName];
  if (!oltCfg) {
    return res.status(404).json({ success: false, message: `OLT "${oltName}" tidak ditemukan` });
  }

  const script = generateScript(oltCfg.vendor, { slot, port, onuId, sn, lokasi, namaPelanggan, idPppoe });
  const log = [];

  if (!pushToOlt) {
    return res.json({ success: true, script, pushed: false });
  }

  try {
    log.push(`[INFO] Connecting to ${oltCfg.host}:${oltCfg.port || 23} via Telnet...`);
    const commands = script.split('\n');
    await telnetExec(oltCfg, commands, log);
    log.push(`[OK]   ONU ${sn} berhasil diaktivasi!`);

    // ─── QUERY RX OPTICAL POWER ───
    let rxPower = null;
    try {
      // Tunggu ONT selesai sinkronisasi ke OLT
      log.push(`[INFO] Menunggu ONT sinkronisasi (15 detik)...`);
      await new Promise(resolve => setTimeout(resolve, 15000));

      const MAX_RETRY = 3;
      const RETRY_DELAY = 10000; // 10 detik antar retry

      for (let attempt = 1; attempt <= MAX_RETRY; attempt++) {
        log.push(`[INFO] Mengambil RX Optical Power... (percobaan ${attempt}/${MAX_RETRY})`);
        try {
          const telnetRx = new Telnet();
          await telnetRx.connect({
            host: oltCfg.host,
            port: oltCfg.port || 23,
            shellPrompt: /#\s*$/,
            loginPrompt: /Username:/i,
            passwordPrompt: /Password:/i,
            username: oltCfg.username,
            password: oltCfg.password,
            timeout: 15000,
            execTimeout: 8000,
            irs: '\r\n',
            ors: '\r\n',
          });

          const rxCmd = `show pon power attenuation gpon-onu_1/${slot}/${port}:${onuId}`;
          log.push(`[CMD]  ${rxCmd}`);
          const rxOutput = await telnetRx.exec(rxCmd);
          await telnetRx.end();

          if (rxOutput) {
            log.push(`[OUT]  ${rxOutput.trim()}`);

            // Ambil dari baris "down ... Rx:-13.904(dbm)"
            const rxMatch = rxOutput.match(/down\s+.*?Rx\s*:\s*(-?\d+\.\d+)/i);
            if (rxMatch) {
              rxPower = rxMatch[1];
              log.push(`[OK]   RX Optical Power: ${rxPower} dBm`);
              break; // berhasil, keluar dari loop retry
            } else {
              log.push(`[WARN] RX Power belum tersedia (ONT mungkin masih sinkronisasi)`);
              if (attempt < MAX_RETRY) {
                log.push(`[INFO] Menunggu ${RETRY_DELAY / 1000} detik sebelum retry...`);
                await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
              }
            }
          }
        } catch (retryErr) {
          log.push(`[WARN] Percobaan ${attempt} gagal: ${retryErr.message}`);
          if (attempt < MAX_RETRY) {
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
          }
        }
      }

      if (!rxPower) {
        log.push(`[WARN] RX Power tidak tersedia setelah ${MAX_RETRY} percobaan`);
      }

    } catch (rxErr) {
      log.push(`[WARN] Gagal ambil RX Power: ${rxErr.message}`);
    }

    res.json({ success: true, script, pushed: true, log: log.join('\n'), rxPower });
  } catch (err) {
    log.push(`[FAIL] Telnet Error: ${err.message}`);
    res.status(500).json({ success: false, script, pushed: false, log: log.join('\n'), message: err.message });
  }
});

// ─── API: TEST TELNET ───
app.post('/api/test-ssh', requireAuth, async (req, res) => {
  const { oltName } = req.body;
  const oltCfg = OLT_CONFIG[oltName];
  if (!oltCfg) return res.status(404).json({ success: false, message: 'OLT tidak ditemukan' });

  const telnet = new Telnet();
  try {
    await telnet.connect({
      host: oltCfg.host,
      port: oltCfg.port || 23,
      shellPrompt: /#\s*$/,
      loginPrompt: /Username:/i,
      passwordPrompt: /Password:/i,
      username: oltCfg.username,
      password: oltCfg.password,
      timeout: 10000,
    });
    await telnet.end();
    res.json({ success: true, message: `Koneksi Telnet ke ${oltName} (${oltCfg.host}) berhasil!` });
  } catch (err) {
    res.status(500).json({ success: false, message: `Gagal: ${err.message}` });
  }
});

// ─── API: SCAN UNCONFIGURED ONU ───
app.post('/api/scan-uncfg', requireAuth, async (req, res) => {
  const { oltName, slot, port } = req.body;

  if (!oltName) {
    return res.status(400).json({ success: false, message: 'Field wajib: OLT' });
  }

  const oltCfg = OLT_CONFIG[oltName];
  if (!oltCfg) {
    return res.status(404).json({ success: false, message: `OLT "${oltName}" tidak ditemukan` });
  }

  const log = [];
  const onus = [];

  try {
    const telnet = new Telnet();
    await telnet.connect({
      host: oltCfg.host,
      port: oltCfg.port || 23,
      shellPrompt: /#\s*$/,
      loginPrompt: /Username:/i,
      passwordPrompt: /Password:/i,
      username: oltCfg.username,
      password: oltCfg.password,
      timeout: 15000,
      execTimeout: 10000,
      irs: '\r\n',
      ors: '\r\n',
    });

    log.push(`[OK]   Terhubung ke ${oltCfg.host}`);

    let cmd = 'show gpon onu uncfg';
    if (slot && port) {
      cmd = `show gpon onu uncfg gpon-olt_1/${slot}/${port}`;
    }

    log.push(`[CMD]  ${cmd}`);
    const output = await telnet.exec(cmd);
    await telnet.end();

    if (output) {
      log.push(`[OUT]  Output diterima (${output.length} chars)`);

      const lines = output.split('\n');
      lines.forEach(line => {
        const trimmed = line.trim();
        const snMatch = trimmed.match(/([A-Z]{4}[0-9A-Fa-f]{8})/);
        const ifMatch = trimmed.match(/(\d+\/\d+\/\d+)/);
        if (snMatch) {
          const sn = snMatch[1];
          const iface = ifMatch ? ifMatch[1] : null;
          const parts = iface ? iface.split('/') : [];
          onus.push({
            sn,
            slot: parts[1] || null,
            port: parts[2] || null,
            rawLine: trimmed,
          });
        }
      });

      log.push(`[OK]   Ditemukan ${onus.length} ONU unconfigured`);
    } else {
      log.push(`[INFO] Tidak ada output atau tidak ada ONU unconfigured`);
    }

    res.json({ success: true, onus, log: log.join('\n'), rawOutput: output });
  } catch (err) {
    log.push(`[FAIL] ${err.message}`);
    res.status(500).json({ success: false, onus: [], log: log.join('\n'), message: err.message });
  }
});

// ─── API: ADMIN — TAMBAH OLT ───
app.post('/api/admin/olt', requireAuth, (req, res) => {
  const { name, host, port, username, password, vendor } = req.body;
  if (!name || !host || !vendor) {
    return res.status(400).json({ success: false, message: 'name, host, dan vendor wajib diisi' });
  }
  if (OLT_CONFIG[name]) {
    return res.status(409).json({ success: false, message: `OLT "${name}" sudah ada` });
  }
  OLT_CONFIG[name] = { host, port: parseInt(port) || 23, username: username || 'zte', password: password || 'zte', vendor };
  res.json({ success: true, message: `OLT "${name}" berhasil ditambahkan` });
});

// ─── API: ADMIN — EDIT OLT ───
app.put('/api/admin/olt', requireAuth, (req, res) => {
  const { name, host, port, username, password, vendor } = req.body;
  if (!name || !OLT_CONFIG[name]) {
    return res.status(404).json({ success: false, message: `OLT "${name}" tidak ditemukan` });
  }
  OLT_CONFIG[name] = { host, port: parseInt(port) || 23, username: username || 'zte', password: password || 'zte', vendor };
  res.json({ success: true, message: `OLT "${name}" berhasil diperbarui` });
});

// ─── API: ADMIN — HAPUS OLT ───
app.delete('/api/admin/olt/:name', requireAuth, (req, res) => {
  const name = decodeURIComponent(req.params.name);
  if (!OLT_CONFIG[name]) {
    return res.status(404).json({ success: false, message: `OLT "${name}" tidak ditemukan` });
  }
  delete OLT_CONFIG[name];
  res.json({ success: true, message: `OLT "${name}" berhasil dihapus` });
});

// ─── API: ADMIN — GET OLT DETAIL (dengan credential) ───
app.get('/api/admin/olts', requireAuth, (req, res) => {
  const list = Object.entries(OLT_CONFIG).map(([name, cfg]) => ({
    name,
    host: cfg.host,
    port: cfg.port,
    username: cfg.username,
    password: cfg.password,
    vendor: cfg.vendor,
  }));
  res.json(list);
});

// ─── SNMP HELPERS ───
const SNMP_COMMUNITY = 'public';
const SNMP_PORT = 161;
const SNMP_VERSION = snmp.Version2c;
const SNMP_TIMEOUT = 5000;
const SNMP_RETRIES = 1;

// OID ZTE GPON C320/C300 (verified via snmpwalk)
const OID = {
  // ONU name/display name — suffix: <portIndex>.<onuId>
  onuName:          '1.3.6.1.4.1.3902.1012.3.28.1.1.2',
  // ONU serial number (Hex-STRING 8 bytes, e.g. ZTEG + 4 bytes)
  onuSerial:        '1.3.6.1.4.1.3902.1012.3.28.1.1.5',
  // ONU description (format: "1$$lokasi - nama$$")
  onuDesc:          '1.3.6.1.4.1.3902.1012.3.28.1.1.3',
  // ONU phase state: 1=LOS, 3=Online, 4=DyingGasp, 6=Offline
  onuOperStatus:    '1.3.6.1.4.1.3902.1012.3.28.2.1.4',
  // ONU last online time (STRING "YYYY-MM-DD HH:MM:SS")
  onuLastOnline:    '1.3.6.1.4.1.3902.1012.3.28.2.1.5',
  // ONU last offline time (STRING "YYYY-MM-DD HH:MM:SS")
  onuLastOffline:   '1.3.6.1.4.1.3902.1012.3.28.2.1.6',
  // ONU RX power (unit: raw integer, dBm = (value - 15000) * 0.002)
  // suffix: <portIndex>.<onuId>.1
  onuRxPower:       '1.3.6.1.4.1.3902.1012.3.50.12.1.1.10',
  // OLT RX power (receive from ONU side) — unit: 0.001 dBm signed
  oltRxPower:       '1.3.6.1.4.1.3902.1015.1010.11.2.1.2',
  // Upstream octets
  upOctets:         '1.3.6.1.2.1.31.1.1.1.6',
  // Downstream octets
  downOctets:       '1.3.6.1.2.1.31.1.1.1.10',
  // sysUpTime
  sysUpTime:        '1.3.6.1.2.1.1.3.0',
};

function snmpSession(host) {
  return snmp.createSession(host, SNMP_COMMUNITY, {
    port: SNMP_PORT,
    retries: SNMP_RETRIES,
    timeout: SNMP_TIMEOUT,
    version: SNMP_VERSION,
  });
}

function snmpGetSubtree(host, rootOid) {
  return new Promise((resolve, reject) => {
    const session = snmpSession(host);
    const results = [];
    session.subtree(rootOid, 20, (varbinds) => {
      for (const vb of varbinds) {
        if (snmp.isVarbindError(vb)) continue;
        results.push({ oid: vb.oid, value: vb.value });
      }
    }, (err) => {
      session.close();
      if (err) return reject(err);
      resolve(results);
    });
  });
}

function snmpGet(host, oids) {
  return new Promise((resolve, reject) => {
    const session = snmpSession(host);
    session.get(oids, (err, varbinds) => {
      session.close();
      if (err) return reject(err);
      resolve(varbinds);
    });
  });
}

// Konversi ONU portIndex ZTE C320 → slot/port
// Format index integer: 0x10 aabb cc 00
//   byte3 (bits 31-24) = 0x10 (fixed prefix)
//   byte2 (bits 23-16) = slot (1-based)
//   byte1 (bits 15-8)  = port (0-based, displayed as 0-based)
//   byte0 (bits 7-0)   = sub (usually 0 or 2)
// OID suffix for onuName/onuOperStatus: <portIndex>.<onuId>
function parseOnuIndex(portIndex, onuId) {
  const idx = parseInt(portIndex);
  const slot = (idx >> 16) & 0xFF;
  const port = (idx >> 8) & 0xFF;
  return { slot, port, onuId: parseInt(onuId) };
}

// ZTE C320 RX power formula: dBm = (raw - 15000) * 0.002
// Valid range: -30 dBm (raw=0) to 0 dBm (raw=15000)
function rxPowerToDbm(raw) {
  if (raw === null || raw === undefined) return null;
  const val = parseInt(raw);
  if (isNaN(val)) return null;
  const dbm = (val - 15000) * 0.002;
  if (dbm < -35 || dbm > 5) return null; // sanity check
  return dbm.toFixed(3);
}

function uptime100thToStr(hundredths) {
  const totalSec = Math.floor(hundredths / 100);
  const d = Math.floor(totalSec / 86400);
  const h = Math.floor((totalSec % 86400) / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  return `${m}m ${s}s`;
}

// ─── API: SNMP — MONITOR ONU LIST ───
app.get('/api/snmp/onu-monitor', requireAuth, async (req, res) => {
  const { oltName } = req.query;
  if (!oltName) return res.status(400).json({ success: false, message: 'Query param oltName wajib' });

  const oltCfg = OLT_CONFIG[oltName];
  if (!oltCfg) return res.status(404).json({ success: false, message: `OLT "${oltName}" tidak ditemukan` });

  const host = oltCfg.host;
  const result = { oltName, host, ts: new Date().toISOString(), onus: [], sysUptime: null, error: null };

  try {
    // 1. Ambil sysUpTime
    try {
      const uptimeVbs = await snmpGet(host, [OID.sysUpTime]);
      if (uptimeVbs[0] && !snmp.isVarbindError(uptimeVbs[0])) {
        result.sysUptime = uptime100thToStr(uptimeVbs[0].value);
      }
    } catch(e) { /* optional */ }

    // 2. Walk ONU name table — suffix: <portIndex>.<onuId>
    const nameRows = await snmpGetSubtree(host, OID.onuName);
    if (!nameRows.length) {
      return res.json({ ...result, onus: [], error: 'Tidak ada data ONU dari SNMP. Pastikan SNMP v2c diaktifkan di OLT dan community "public" benar.' });
    }

    // 3. Walk ONU oper status — suffix: <portIndex>.<onuId>
    let statusMap = {};
    try {
      const statusRows = await snmpGetSubtree(host, OID.onuOperStatus);
      statusRows.forEach(r => {
        const suffix = r.oid.replace(OID.onuOperStatus + '.', '');
        statusMap[suffix] = Number(r.value);
      });
    } catch(e) {}

    // 4. Walk ONU RX power — suffix: <portIndex>.<onuId>.1
    let rxMap = {};
    try {
      const rxRows = await snmpGetSubtree(host, OID.onuRxPower);
      rxRows.forEach(r => {
        // strip trailing .1 from suffix
        const full = r.oid.replace(OID.onuRxPower + '.', '');
        const key = full.replace(/\.1$/, '');
        rxMap[key] = r.value;
      });
    } catch(e) {}

    // 5. Walk ONU serial number — suffix: <portIndex>.<onuId>
    let snMap = {};
    try {
      const snRows = await snmpGetSubtree(host, OID.onuSerial);
      snRows.forEach(r => {
        const suffix = r.oid.replace(OID.onuSerial + '.', '');
        let sn = '';
        if (Buffer.isBuffer(r.value)) {
          const vendor = r.value.slice(0, 4).toString('ascii').replace(/[^\x20-\x7E]/g, '');
          const hex = r.value.slice(4).toString('hex').toUpperCase();
          sn = vendor + hex;
        } else if (typeof r.value === 'string') {
          sn = r.value;
        }
        snMap[suffix] = sn;
      });
    } catch(e) {}

    // 6. Walk ONU last online time — suffix: <portIndex>.<onuId>
    let lastOnlineMap = {};
    try {
      const loRows = await snmpGetSubtree(host, OID.onuLastOnline);
      loRows.forEach(r => {
        const suffix = r.oid.replace(OID.onuLastOnline + '.', '');
        lastOnlineMap[suffix] = r.value ? r.value.toString() : null;
      });
    } catch(e) {}

    // 7. Walk ONU last offline time — suffix: <portIndex>.<onuId>
    let lastOfflineMap = {};
    try {
      const lofRows = await snmpGetSubtree(host, OID.onuLastOffline);
      lofRows.forEach(r => {
        const suffix = r.oid.replace(OID.onuLastOffline + '.', '');
        lastOfflineMap[suffix] = r.value ? r.value.toString() : null;
      });
    } catch(e) {}

    // 7. Rakit hasil
    nameRows.forEach(row => {
      const suffix = row.oid.replace(OID.onuName + '.', '');
      const parts = suffix.split('.');
      if (parts.length < 2) return;
      const portIndex = parts[0];
      const onuId = parts[1];
      const idx = parseOnuIndex(portIndex, onuId);

      const statusCode = statusMap[suffix] !== undefined ? statusMap[suffix] : -1;
      // ZTE phase state: 1=LOS, 3=Online, 4=DyingGasp, 6=Offline
      const phaseMap = {
        1: { label: 'LOS',        color: 'err',  online: false },
        3: { label: 'ONLINE',     color: 'ok',   online: true  },
        4: { label: 'DYING GASP', color: 'err',  online: false },
        6: { label: 'OFFLINE',    color: 'err',  online: false },
      };
      const st = phaseMap[statusCode] || { label: `CODE ${statusCode}`, color: 'muted', online: false };
      const online = st.online;

      const rxRaw = rxMap[suffix] !== undefined ? rxMap[suffix] : null;

      result.onus.push({
        suffix,
        slot: idx.slot,
        port: idx.port,
        onuId: idx.onuId,
        name: row.value ? row.value.toString() : '',
        serialNumber: snMap[suffix] || '—',
        lastOnline: lastOnlineMap[suffix] || null,
        lastOffline: lastOfflineMap[suffix] || null,
        statusCode,
        statusLabel: st.label,
        statusColor: st.color,
        rxPower: rxPowerToDbm(rxRaw),
        online,
      });
    });

    // Sort by slot, port, onuId
    result.onus.sort((a, b) => (a.slot - b.slot) || (a.port - b.port) || (a.onuId - b.onuId));
    result.total   = result.onus.length;
    result.online  = result.onus.filter(o => o.online).length;
    result.offline = result.total - result.online;

    res.json({ success: true, ...result });
  } catch (err) {
    const msg = err.message || String(err);
    let hint = '';
    if (msg.includes('Timeout')) hint = 'Timeout — pastikan SNMP diaktifkan di OLT, port 161 UDP tidak diblokir firewall.';
    else if (msg.includes('ECONNREFUSED')) hint = 'Koneksi ditolak — periksa host/IP OLT.';
    res.json({ success: false, ...result, onus: [], error: hint || msg });
  }
});

// ─── API: SNMP — TRAFFIC COUNTER (single ONU) ───
app.get('/api/snmp/onu-traffic', requireAuth, async (req, res) => {
  const { oltName, ifIndex } = req.query;
  if (!oltName || !ifIndex) return res.status(400).json({ success: false, message: 'Param oltName dan ifIndex wajib' });

  const oltCfg = OLT_CONFIG[oltName];
  if (!oltCfg) return res.status(404).json({ success: false, message: 'OLT tidak ditemukan' });

  try {
    const oids = [
      `${OID.upOctets}.${ifIndex}`,
      `${OID.downOctets}.${ifIndex}`,
    ];
    const vbs = await snmpGet(oltCfg.host, oids);
    const upOct   = (!snmp.isVarbindError(vbs[0])) ? Number(vbs[0].value) : null;
    const downOct = (!snmp.isVarbindError(vbs[1])) ? Number(vbs[1].value) : null;

    function fmtBytes(b) {
      if (b === null) return null;
      if (b > 1e12) return (b/1e12).toFixed(2) + ' TB';
      if (b > 1e9)  return (b/1e9).toFixed(2) + ' GB';
      if (b > 1e6)  return (b/1e6).toFixed(2) + ' MB';
      return (b/1e3).toFixed(1) + ' KB';
    }

    res.json({ success: true, upOctets: upOct, downOctets: downOct, upFmt: fmtBytes(upOct), downFmt: fmtBytes(downOct) });
  } catch(err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── API: BACA CACHE ONU (cepat, dari DB) ───
app.get('/api/onu-cache', requireAuth, (req, res) => {
  const { oltName } = req.query;
  if (!oltName) return res.status(400).json({ success: false, message: 'oltName wajib' });

  try {
    const rows = db.prepare(
      'SELECT * FROM onu_cache WHERE olt_name = ? ORDER BY slot, port, onu_id'
    ).all(oltName);

    if (!rows.length) {
      return res.json({ success: false, cached: false, message: 'Belum ada cache. Sedang polling...' });
    }

    const log = db.prepare(
      'SELECT * FROM poll_log WHERE olt_name = ? ORDER BY id DESC LIMIT 1'
    ).get(oltName);

    const onus = rows.map(r => ({
      suffix:       r.suffix,
      slot:         r.slot,
      port:         r.port,
      onuId:        r.onu_id,
      name:         r.name,
      serialNumber: r.serial_number,
      statusCode:   r.status_code,
      statusLabel:  r.status_label,
      statusColor:  r.status_color,
      rxPower:      r.rx_power,
      online:       !!r.online,
      lastOnline:   r.last_online,
      lastOffline:  r.last_offline,
    }));

    res.json({
      success:    true,
      cached:     true,
      oltName,
      onus,
      total:      onus.length,
      online:     onus.filter(o => o.online).length,
      offline:    onus.filter(o => !o.online).length,
      updatedAt:  log ? log.polled_at : rows[0].updated_at,
      durationMs: log ? log.duration_ms : null,
      ts:         new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── API: STATUS POLLER ───
app.get('/api/poll-status', requireAuth, (req, res) => {
  try {
    const logs = db.prepare(
      'SELECT olt_name, polled_at, duration_ms, onu_count, online_count, success, error_msg FROM poll_log GROUP BY olt_name HAVING MAX(id)'
    ).all();
    res.json({ success: true, status: logs, nextPollIn: Math.round((nextPollTime - Date.now()) / 1000) });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── API: TRIGGER POLL MANUAL ───
app.post('/api/poll-now', requireAuth, async (req, res) => {
  const { oltName } = req.body;
  res.json({ success: true, message: 'Polling dimulai di background' });
  if (oltName && OLT_CONFIG[oltName]) {
    pollOlt(oltName, OLT_CONFIG[oltName]).catch(e => console.error('[POLLER]', oltName, e.message));
  } else {
    pollAllOlts();
  }
});

// ═══════════════════════════════════════════════════════
// ─── BACKGROUND POLLER ───
// ═══════════════════════════════════════════════════════

const POLL_INTERVAL_MS = 2 * 60 * 1000; // 2 menit
let nextPollTime = Date.now() + POLL_INTERVAL_MS;

// ─── TELEGRAM NOTIFIKASI ───
const https = require('https');

// Track ONU yang sudah dinotifikasi (key: "oltName|suffix")
// supaya tidak spam notifikasi tiap 2 menit
const _losNotified = new Set();

// Track ONU yang sebelumnya LOS, untuk deteksi kembali UP
const _losWasDown = new Map(); // key -> ONU object saat LOS

async function sendTelegram(message) {
  if (!TELEGRAM_ENABLED) return;
  return new Promise((resolve) => {
    const body = JSON.stringify({
      chat_id:    TELEGRAM_CHAT_ID,
      text:       message,
      parse_mode: 'HTML',
    });
    const req = https.request({
      hostname: 'api.telegram.org',
      path:     `/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      res.resume();
      resolve();
    });
    req.on('error', (e) => {
      console.error('[TELEGRAM] Gagal kirim:', e.message);
      resolve();
    });
    req.write(body);
    req.end();
  });
}

function checkAndNotifyLos(oltName, onus) {
  if (!TELEGRAM_ENABLED) return;

  const losOnus    = onus.filter(o => o.statusCode === 1); // LOS saja
  const onlineOnus = onus.filter(o => o.online);           // ONU online

  const now = new Date().toLocaleString('id-ID', {
    timeZone: 'Asia/Jakarta',
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  });

  // ── Deteksi ONU LOS baru (belum pernah dinotifikasi) ──
  const newLos = losOnus.filter(o => {
    const key = `${oltName}|${o.suffix}`;
    return !_losNotified.has(key);
  });

  // Tandai semua ONU LOS saat ini sebagai sudah dinotifikasi
  const currentLosKeys = new Set(losOnus.map(o => `${oltName}|${o.suffix}`));

  // ── Deteksi ONU yang kembali UP (sebelumnya LOS, sekarang online) ──
  const recoveredOnus = onlineOnus.filter(o => {
    const key = `${oltName}|${o.suffix}`;
    return _losWasDown.has(key);
  });

  // Hapus dari set ONU yang sudah kembali normal
  for (const key of _losNotified) {
    if (key.startsWith(oltName + '|') && !currentLosKeys.has(key)) {
      _losNotified.delete(key);
    }
  }

  // Update _losWasDown: hapus yang sudah UP, tambah yang baru LOS
  for (const key of _losWasDown.keys()) {
    if (key.startsWith(oltName + '|') && !currentLosKeys.has(key)) {
      _losWasDown.delete(key);
    }
  }
  losOnus.forEach(o => {
    const key = `${oltName}|${o.suffix}`;
    if (!_losWasDown.has(key)) _losWasDown.set(key, o);
  });

  // Tambah yang baru LOS ke set notified
  currentLosKeys.forEach(k => _losNotified.add(k));

  // ── Kirim notifikasi ONU LOS baru ──
  newLos.forEach(o => {
    const iface  = `1/${o.slot}/${o.port}:${o.onuId}`;
    const nama   = o.name || '—';
    const sn     = o.serialNumber || '—';
    const rx     = (o.rxPower !== null && o.rxPower !== undefined) ? `${o.rxPower} dBm` : '—';

    const msg = [
      `🔴 <b>ONU LOS TERDETEKSI</b>`,
      ``,
      `<b>OLT:</b> ${oltName}`,
      `<b>Interface:</b> ${iface}`,
      `<b>Pelanggan:</b> ${nama}`,
      `<b>Serial:</b> ${sn}`,
      `<b>RX Power:</b> ${rx}`,
      `<b>Waktu:</b> ${now}`,
    ].join('\n');

    sendTelegram(msg).catch(e => console.error('[TELEGRAM]', e.message));
  });

  if (newLos.length > 1) {
    console.log(`[TELEGRAM] Mengirim ${newLos.length} notifikasi LOS untuk ${oltName}`);
  }

  // ── Kirim notifikasi ONU kembali UP ──
  recoveredOnus.forEach(o => {
    const iface  = `1/${o.slot}/${o.port}:${o.onuId}`;
    const nama   = o.name || '—';
    const sn     = o.serialNumber || '—';
    const rx     = (o.rxPower !== null && o.rxPower !== undefined) ? `${o.rxPower} dBm` : '—';

    const msg = [
      `🟢 <b>ONU KEMBALI ONLINE</b>`,
      ``,
      `<b>OLT:</b> ${oltName}`,
      `<b>Interface:</b> ${iface}`,
      `<b>Pelanggan:</b> ${nama}`,
      `<b>Serial:</b> ${sn}`,
      `<b>RX Power:</b> ${rx}`,
      `<b>Waktu:</b> ${now}`,
    ].join('\n');

    sendTelegram(msg).catch(e => console.error('[TELEGRAM]', e.message));
    // Hapus dari map setelah notif UP dikirim
    _losWasDown.delete(`${oltName}|${o.suffix}`);
  });

  if (recoveredOnus.length > 0) {
    console.log(`[TELEGRAM] Mengirim ${recoveredOnus.length} notifikasi UP untuk ${oltName}`);
  }
}

// ─── API: TEST TELEGRAM ───
app.post('/api/telegram/test', requireAuth, async (req, res) => {
  if (!TELEGRAM_ENABLED) {
    return res.json({ success: false, message: 'TELEGRAM_BOT_TOKEN atau TELEGRAM_CHAT_ID belum diset di environment variable' });
  }
  try {
    await sendTelegram('✅ <b>Test Notifikasi</b>\n\nKoneksi Telegram berhasil! Notifikasi ONU LOS aktif.');
    res.json({ success: true, message: 'Pesan test berhasil dikirim ke group Telegram' });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Simpan hasil SNMP ke DB
function saveOnuCache(oltName, onus) {
  const upsert = db.prepare(`
    INSERT INTO onu_cache
      (olt_name, suffix, slot, port, onu_id, name, serial_number,
       status_code, status_label, status_color, rx_power, online,
       last_online, last_offline, updated_at)
    VALUES
      (@olt_name, @suffix, @slot, @port, @onu_id, @name, @serial_number,
       @status_code, @status_label, @status_color, @rx_power, @online,
       @last_online, @last_offline, @updated_at)
    ON CONFLICT(olt_name, suffix) DO UPDATE SET
      slot         = excluded.slot,
      port         = excluded.port,
      onu_id       = excluded.onu_id,
      name         = excluded.name,
      serial_number= excluded.serial_number,
      status_code  = excluded.status_code,
      status_label = excluded.status_label,
      status_color = excluded.status_color,
      rx_power     = excluded.rx_power,
      online       = excluded.online,
      last_online  = excluded.last_online,
      last_offline = excluded.last_offline,
      updated_at   = excluded.updated_at
  `);

  const insertMany = db.transaction((items) => {
    for (const o of items) upsert.run(o);
  });

  // Waktu lokal dari JS (bukan SQLite) agar timezone sesuai server
  const nowLocal = new Date().toLocaleString('sv-SE', { timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone }).replace('T', ' ');

  insertMany(onus.map(o => ({
    olt_name:     oltName,
    suffix:       o.suffix,
    slot:         o.slot,
    port:         o.port,
    onu_id:       o.onuId,
    name:         o.name || '',
    serial_number: o.serialNumber || '',
    status_code:  o.statusCode,
    status_label: o.statusLabel,
    status_color: o.statusColor,
    rx_power:     o.rxPower,
    online:       o.online ? 1 : 0,
    last_online:  o.lastOnline || null,
    last_offline: o.lastOffline || null,
    updated_at:   nowLocal,
  })));
}

// Fungsi SNMP fetch (extracted dari endpoint, tanpa res)
async function snmpFetchOnus(oltName, oltCfg) {
  const host = oltCfg.host;
  const result = { onus: [], sysUptime: null };

  // sysUptime (optional)
  try {
    const uptimeVbs = await snmpGet(host, [OID.sysUpTime]);
    if (uptimeVbs[0] && !snmp.isVarbindError(uptimeVbs[0])) {
      result.sysUptime = uptime100thToStr(uptimeVbs[0].value);
    }
  } catch(e) {}

  // ONU name (required)
  const nameRows = await snmpGetSubtree(host, OID.onuName);
  if (!nameRows.length) throw new Error('Tidak ada data ONU dari SNMP');

  // Status, RX, SN, lastOnline, lastOffline (parallel)
  const [statusRows, rxRows, snRows, loRows, lofRows] = await Promise.allSettled([
    snmpGetSubtree(host, OID.onuOperStatus),
    snmpGetSubtree(host, OID.onuRxPower),
    snmpGetSubtree(host, OID.onuSerial),
    snmpGetSubtree(host, OID.onuLastOnline),
    snmpGetSubtree(host, OID.onuLastOffline),
  ]).then(rs => rs.map(r => r.status === 'fulfilled' ? r.value : []));

  const statusMap = {};
  statusRows.forEach(r => {
    const suffix = r.oid.replace(OID.onuOperStatus + '.', '');
    statusMap[suffix] = Number(r.value);
  });

  const rxMap = {};
  rxRows.forEach(r => {
    const full = r.oid.replace(OID.onuRxPower + '.', '');
    rxMap[full.replace(/\.1$/, '')] = r.value;
  });

  const snMapLocal = {};
  snRows.forEach(r => {
    const suffix = r.oid.replace(OID.onuSerial + '.', '');
    let sn = '';
    if (Buffer.isBuffer(r.value)) {
      const vendor = r.value.slice(0, 4).toString('ascii').replace(/[^\x20-\x7E]/g, '');
      const hex = r.value.slice(4).toString('hex').toUpperCase();
      sn = vendor + hex;
    } else if (typeof r.value === 'string') { sn = r.value; }
    snMapLocal[suffix] = sn;
  });

  const lastOnlineMap = {};
  loRows.forEach(r => {
    const suffix = r.oid.replace(OID.onuLastOnline + '.', '');
    lastOnlineMap[suffix] = r.value ? r.value.toString() : null;
  });

  const lastOfflineMap = {};
  lofRows.forEach(r => {
    const suffix = r.oid.replace(OID.onuLastOffline + '.', '');
    lastOfflineMap[suffix] = r.value ? r.value.toString() : null;
  });

  const phaseMap = {
    1: { label: 'LOS',        color: 'err',  online: false },
    3: { label: 'ONLINE',     color: 'ok',   online: true  },
    4: { label: 'DYING GASP', color: 'err',  online: false },
    6: { label: 'OFFLINE',    color: 'err',  online: false },
  };

  nameRows.forEach(row => {
    const suffix = row.oid.replace(OID.onuName + '.', '');
    const parts = suffix.split('.');
    if (parts.length < 2) return;
    const { slot, port, onuId } = parseOnuIndex(parts[0], parts[1]);
    const statusCode = statusMap[suffix] !== undefined ? statusMap[suffix] : -1;
    const st = phaseMap[statusCode] || { label: `CODE ${statusCode}`, color: 'muted', online: false };

    result.onus.push({
      suffix,
      slot, port, onuId,
      name:         row.value ? row.value.toString() : '',
      serialNumber: snMapLocal[suffix] || '—',
      lastOnline:   lastOnlineMap[suffix] || null,
      lastOffline:  lastOfflineMap[suffix] || null,
      statusCode,
      statusLabel:  st.label,
      statusColor:  st.color,
      rxPower:      rxPowerToDbm(rxMap[suffix] !== undefined ? rxMap[suffix] : null),
      online:       st.online,
    });
  });

  result.onus.sort((a, b) => (a.slot - b.slot) || (a.port - b.port) || (a.onuId - b.onuId));
  return result;
}

// Poll satu OLT → simpan ke DB
async function pollOlt(oltName, oltCfg) {
  const t0 = Date.now();
  console.log(`[POLLER] Polling ${oltName} (${oltCfg.host})...`);
  try {
    const data = await snmpFetchOnus(oltName, oltCfg);
    saveOnuCache(oltName, data.onus);
    checkAndNotifyLos(oltName, data.onus);

    const duration = Date.now() - t0;
    const onlineCount = data.onus.filter(o => o.online).length;
    const nowJs = new Date().toLocaleString('sv-SE', { timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone }).replace('T', ' ');
    db.prepare(`
      INSERT INTO poll_log (olt_name, polled_at, duration_ms, onu_count, online_count, success)
      VALUES (?, ?, ?, ?, ?, 1)
    `).run(oltName, nowJs, duration, data.onus.length, onlineCount);

    console.log(`[POLLER] ${oltName} selesai: ${data.onus.length} ONU, ${onlineCount} online, ${duration}ms`);
  } catch (err) {
    const duration = Date.now() - t0;
    const nowJsErr = new Date().toLocaleString('sv-SE', { timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone }).replace('T', ' ');
    db.prepare(`
      INSERT INTO poll_log (olt_name, polled_at, duration_ms, onu_count, online_count, success, error_msg)
      VALUES (?, ?, ?, 0, 0, 0, ?)
    `).run(oltName, nowJsErr, duration, err.message);
    console.error(`[POLLER] ${oltName} error: ${err.message}`);
  }
}

// Poll semua OLT secara paralel
async function pollAllOlts() {
  const entries = Object.entries(OLT_CONFIG);
  console.log(`[POLLER] Mulai polling ${entries.length} OLT...`);
  await Promise.allSettled(entries.map(([name, cfg]) => pollOlt(name, cfg)));
  nextPollTime = Date.now() + POLL_INTERVAL_MS;
  console.log(`[POLLER] Selesai. Poll berikutnya: ${new Date(nextPollTime).toLocaleTimeString('id-ID')}`);
}

// Jalankan poller pertama kali saat server start (delay 3 detik)
setTimeout(pollAllOlts, 3000);

// Ulangi tiap POLL_INTERVAL_MS
setInterval(pollAllOlts, POLL_INTERVAL_MS);

// ══════════════════════════════════════════════════════════════
// ─── MIKROTIK INTEGRATION (port 8728 binary API) ───
// ══════════════════════════════════════════════════════════════

const { RouterOSAPI } = require('node-routeros');

// Helper: ambil config Mikrotik dari DB
function getMikrotikCfg(name) {
  return db.prepare('SELECT * FROM mikrotik_config WHERE name = ?').get(name);
}

// Helper: koneksi ke Mikrotik via port 8728, jalankan perintah, lalu disconnect
async function mikrotikExec(cfg, commands) {
  const conn = new RouterOSAPI({
    host:     cfg.host,
    port:     cfg.port || 8728,
    user:     cfg.username,
    password: cfg.password,
    timeout:  10,
  });

  await conn.connect();
  try {
    const results = [];
    for (const cmd of (Array.isArray(commands) ? commands : [commands])) {
      const path   = typeof cmd === 'string' ? cmd : cmd.command;
      const params = typeof cmd === 'string' ? [] : (cmd.query || []);
      const res = await conn.write(path, params);
      results.push(res);
    }
    return results.length === 1 ? results[0] : results;
  } finally {
    try { conn.close(); } catch(e) {}
  }
}

// Helper: satu perintah simpel
async function mikrotikQuery(cfg, command, params = []) {
  return mikrotikExec(cfg, [{ command, query: params }]);
}

// ─── ADMIN: Daftar Mikrotik ───
app.get('/api/admin/mikrotik', requireAuth, (req, res) => {
  const list = db.prepare('SELECT name, host, port, username FROM mikrotik_config').all();
  res.json(list);
});

app.post('/api/admin/mikrotik', requireAuth, (req, res) => {
  const { name, host, port, username, password } = req.body;
  if (!name || !host || !username || !password)
    return res.status(400).json({ success: false, message: 'name, host, username, password wajib diisi' });
  try {
    db.prepare('INSERT INTO mikrotik_config (name, host, port, username, password) VALUES (?, ?, ?, ?, ?)')
      .run(name, host, parseInt(port) || 8728, username, password);
    res.json({ success: true, message: `Mikrotik "${name}" berhasil ditambahkan` });
  } catch(e) {
    res.status(409).json({ success: false, message: `Mikrotik "${name}" sudah ada` });
  }
});

app.put('/api/admin/mikrotik', requireAuth, (req, res) => {
  const { name, host, port, username, password } = req.body;
  const existing = getMikrotikCfg(name);
  if (!name || !existing)
    return res.status(404).json({ success: false, message: `Mikrotik "${name}" tidak ditemukan` });
  db.prepare('UPDATE mikrotik_config SET host=?, port=?, username=?, password=? WHERE name=?')
    .run(
      host     || existing.host,
      parseInt(port) || existing.port,
      username || existing.username,
      password || existing.password,
      name
    );
  res.json({ success: true, message: `Mikrotik "${name}" berhasil diperbarui` });
});

app.delete('/api/admin/mikrotik/:name', requireAuth, (req, res) => {
  const name = decodeURIComponent(req.params.name);
  if (!getMikrotikCfg(name))
    return res.status(404).json({ success: false, message: `Mikrotik "${name}" tidak ditemukan` });
  db.prepare('DELETE FROM mikrotik_config WHERE name = ?').run(name);
  res.json({ success: true, message: `Mikrotik "${name}" berhasil dihapus` });
});

// ─── TEST KONEKSI ───
app.post('/api/mikrotik/test', requireAuth, async (req, res) => {
  const { mikrotikName } = req.body;
  const cfg = getMikrotikCfg(mikrotikName);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    const info = await mikrotikQuery(cfg, '/system/identity/print');
    const name = info[0]?.name || '—';
    res.json({ success: true, message: `Koneksi berhasil! Identity: ${name}` });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── PPPOE: LIST SECRETS ───
app.get('/api/mikrotik/:name/pppoe/secrets', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    // Ambil semua secret, filter pppoe di server side agar kompatibel semua versi RouterOS
    const secrets = await mikrotikQuery(cfg, '/ppp/secret/print');
    // Filter hanya service=pppoe (atau all jika ada yg tidak ber-service)
    const filtered = (secrets || []).filter(s => !s.service || s.service === 'pppoe');
    res.json({ success: true, secrets: filtered });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── PPPOE: TAMBAH SECRET ───
app.post('/api/mikrotik/:name/pppoe/secrets', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  const { username, password, profile, remoteAddress, comment } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, message: 'username dan password wajib' });
  try {
    const args = [
      `=name=${username}`,
      `=password=${password}`,
      `=service=pppoe`,
    ];
    if (profile)       args.push(`=profile=${profile}`);
    if (remoteAddress) args.push(`=remote-address=${remoteAddress}`);
    if (comment)       args.push(`=comment=${comment}`);
    await mikrotikQuery(cfg, '/ppp/secret/add', args);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── PPPOE: EDIT SECRET ───
app.patch('/api/mikrotik/:name/pppoe/secrets/:id', async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    const args = [`=.id=${req.params.id}`];
    const { password, profile, remoteAddress, comment, disabled } = req.body;
    if (password      !== undefined) args.push(`=password=${password}`);
    if (profile       !== undefined) args.push(`=profile=${profile}`);
    if (remoteAddress !== undefined && remoteAddress !== "") {
      const ipRegex = /^\d{1,3}(\.\d{1,3}){3}$/;
      if (remoteAddress === "" || ipRegex.test(remoteAddress)) args.push(`=remote-address=${remoteAddress}`);
    }
    if (comment       !== undefined) args.push(`=comment=${comment}`);
    if (disabled      !== undefined) args.push(`=disabled=${disabled ? 'yes' : 'no'}`);
    await mikrotikQuery(cfg, '/ppp/secret/set', args);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── PPPOE: HAPUS SECRET ───
app.delete('/api/mikrotik/:name/pppoe/secrets/:id', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    await mikrotikQuery(cfg, '/ppp/secret/remove', [`=.id=${req.params.id}`]);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── PPPOE: ACTIVE SESSIONS ───
app.get('/api/mikrotik/:name/pppoe/active', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    const { q } = req.query;
    const query = [];
    if (q) query.push(`?name=${q}`);
    const active = await mikrotikQuery(cfg, '/ppp/active/print', query);
    res.json({ success: true, active: active || [] });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── PPPOE: DISCONNECT SESI ───
app.post('/api/mikrotik/:name/pppoe/active/:id/disconnect', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    await mikrotikQuery(cfg, '/ppp/active/remove', [`=.id=${req.params.id}`]);
    res.json({ success: true, message: 'Sesi berhasil diputus' });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── PPP PROFILES ───
app.get('/api/mikrotik/:name/pppoe/profiles', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    const profiles = await mikrotikQuery(cfg, '/ppp/profile/print');
    res.json({ success: true, profiles: profiles || [] });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── SYSTEM RESOURCE ───
app.get('/api/mikrotik/:name/resource', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    const [resource, identity] = await mikrotikExec(cfg, [
      { command: '/system/resource/print' },
      { command: '/system/identity/print' },
    ]);
    res.json({ success: true, resource: resource[0] || {}, identity: identity[0] || {} });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});


// ─── DEBUG: raw print secrets (sementara untuk troubleshoot) ───
app.get('/api/mikrotik/:name/debug/secrets', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    const raw = await mikrotikQuery(cfg, '/ppp/secret/print');
    res.json({ success: true, count: raw?.length, sample: raw?.slice(0,3), keys: raw?.[0] ? Object.keys(raw[0]) : [] });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message, stack: e.stack });
  }
});

// ─── PPPOE: DEBUG ACTIVE (inspect field yang tersedia) ───
app.get('/api/mikrotik/:name/pppoe/debug-active', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    const active = await mikrotikQuery(cfg, '/ppp/active/print');
    res.json({
      success: true,
      count: active?.length || 0,
      fields: active?.[0] ? Object.keys(active[0]) : [],
      sample: active?.[0] || null,
      all: active?.slice(0, 3) || [],
    });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── DEBUG: cek interface PPPoE yang tersedia ───
app.get('/api/mikrotik/:name/interface/debug-pppoe', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    const interfaces = await mikrotikQuery(cfg, '/interface/print');
    const pppoeIfaces = (interfaces || []).filter(i => i.type === 'pppoe-in');
    res.json({
      success: true,
      total: interfaces?.length,
      pppoeCount: pppoeIfaces.length,
      fields: pppoeIfaces[0] ? Object.keys(pppoeIfaces[0]) : [],
      sample: pppoeIfaces.slice(0, 3),
    });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── PPPOE: ACTIVE + TRAFFIC (gabungkan /ppp/active + /interface) ───
app.get('/api/mikrotik/:name/pppoe/active-traffic', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    // Ambil session aktif dan interface list secara paralel
    const [activeSessions, allInterfaces] = await Promise.all([
      mikrotikQuery(cfg, '/ppp/active/print'),
      mikrotikQuery(cfg, '/interface/print'),
    ]);

    // Buat map interface PPPoE by username
    // RouterOS format nama: "<pppoe-USERNAME@DOMAIN>" → strip jadi "USERNAME@DOMAIN"
    const ifaceMap = {};
    (allInterfaces || []).forEach(iface => {
      if (iface.type === 'pppoe-in') {
        const m = iface.name.match(/^<pppoe-(.+)>$/);
        const key = m ? m[1] : iface.name;
        ifaceMap[key] = iface;
      }
    });

    // Gabungkan: cocokkan session.name (username PPPoE) dengan key interface
    const merged = (activeSessions || []).map(session => {
      const matchedIface = ifaceMap[session.name];

      return {
        ...session,
        'rx-byte':    matchedIface?.['rx-byte']  ?? null,
        'tx-byte':    matchedIface?.['tx-byte']  ?? null,
        'rx-rate':    matchedIface?.['rx-rate']  ?? null,
        'tx-rate':    matchedIface?.['tx-rate']  ?? null,
        'running':    matchedIface?.running      ?? null,
        'iface-name': matchedIface?.name         ?? null,
      };
    });

    const withTraffic = merged.filter(s => s['rx-byte'] !== null).length;

    res.json({
      success: true,
      count: merged.length,
      withTraffic,
      pppoeInterfaces: Object.keys(ifaceMap).length,
      data: merged,
    });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── PPPOE: ACTIVE + BPS real-time (2 snapshot, selisih dibagi interval) ───
app.get('/api/mikrotik/:name/pppoe/active-bps', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });

  try {
    // Snapshot 1
    const [snap1Sessions, snap1Ifaces] = await Promise.all([
      mikrotikQuery(cfg, '/ppp/active/print'),
      mikrotikQuery(cfg, '/interface/print'),
    ]);

    // Tunggu 2 detik
    await new Promise(r => setTimeout(r, 2000));

    // Snapshot 2 (interface saja, session tidak berubah signifikan dalam 2 detik)
    const snap2Ifaces = await mikrotikQuery(cfg, '/interface/print');

    // Helper: strip format "<pppoe-USERNAME>" → "USERNAME"
    function ifaceKey(name) {
      const m = name.match(/^<pppoe-(.+)>$/);
      return m ? m[1] : name;
    }

    // Buat map snapshot 1 (key = username)
    const snap1Map = {};
    (snap1Ifaces || []).filter(i => i.type === 'pppoe-in').forEach(i => {
      snap1Map[ifaceKey(i.name)] = {
        rxByte: Number(i['rx-byte'] || 0),
        txByte: Number(i['tx-byte'] || 0),
      };
    });

    // Buat map snapshot 2 (key = username)
    const snap2Map = {};
    (snap2Ifaces || []).filter(i => i.type === 'pppoe-in').forEach(i => {
      snap2Map[ifaceKey(i.name)] = {
        rxByte:  Number(i['rx-byte']  || 0),
        txByte:  Number(i['tx-byte']  || 0),
        rxRate:  i['rx-rate']  ?? null,
        txRate:  i['tx-rate']  ?? null,
        running: i.running,
      };
    });

    function fmtBps(bps) {
      if (bps >= 1e6) return (bps / 1e6).toFixed(2) + ' Mbps';
      if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
      return bps.toFixed(0) + ' bps';
    }

    // Gabungkan dengan session aktif
    const merged = (snap1Sessions || []).map(session => {
      const s1 = snap1Map[session.name];
      const s2 = snap2Map[session.name];

      let rxBps = 0, txBps = 0;
      if (s1 && s2) {
        rxBps = Math.max(0, (s2.rxByte - s1.rxByte) / 2) * 8; // bps
        txBps = Math.max(0, (s2.txByte - s1.txByte) / 2) * 8;
      }

      return {
        ...session,
        'rx-byte':    s2?.rxByte    ?? null,
        'tx-byte':    s2?.txByte    ?? null,
        'rx-bps':     rxBps,
        'tx-bps':     txBps,
        'rx-bps-fmt': fmtBps(rxBps),
        'tx-bps-fmt': fmtBps(txBps),
        'rx-rate':    s2?.rxRate    ?? null,
        'tx-rate':    s2?.txRate    ?? null,
        'running':    s2?.running   ?? null,
        'iface-name': session.name,
      };
    });

    res.json({
      success: true,
      count: merged.length,
      interval: '2s',
      data: merged,
    });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── PPPOE: TRAFFIC PER SESSION (untuk modal detail) ───
// Ambil rx-byte & tx-byte dari interface PPPoE yang cocok dengan session username
app.get('/api/mikrotik/:name/pppoe/traffic', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });

  const { sessionId, username } = req.query;
  if (!sessionId && !username) {
    return res.status(400).json({ success: false, message: 'Parameter sessionId atau username wajib diisi' });
  }

  try {
    // Ambil session aktif dan interface list secara paralel
    const [activeSessions, allInterfaces] = await Promise.all([
      mikrotikQuery(cfg, '/ppp/active/print'),
      mikrotikQuery(cfg, '/interface/print'),
    ]);

    // Cari session berdasarkan .id atau username
    let session = null;
    if (sessionId) {
      session = (activeSessions || []).find(s => s['.id'] === sessionId);
    }
    if (!session && username) {
      session = (activeSessions || []).find(s => s.name === username);
    }

    if (!session) {
      return res.status(404).json({ success: false, message: 'Sesi tidak ditemukan atau sudah terputus' });
    }

    // Cari interface PPPoE yang cocok dengan username session
    // RouterOS format nama interface: "<pppoe-USERNAME>" atau "pppoe-USERNAME"
    const sessionUser = session.name;
    const matchedIface = (allInterfaces || []).find(iface => {
      if (iface.type !== 'pppoe-in') return false;
      const stripped = iface.name.replace(/^<pppoe-/, '').replace(/>$/, '');
      return stripped === sessionUser || iface.name === sessionUser;
    });

    const rxBytes = matchedIface ? Number(matchedIface['rx-byte'] || 0) : 0;
    const txBytes = matchedIface ? Number(matchedIface['tx-byte'] || 0) : 0;

    res.json({
      success:   true,
      sessionId: session['.id'],
      username:  sessionUser,
      rxBytes,
      txBytes,
      interface: matchedIface?.name ?? '—',
      running:   matchedIface?.running ?? null,
    });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ─── API: POLL LOG (untuk halaman admin) ───
app.get('/api/poll-log', requireAuth, (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 200;
    const oltName = req.query.olt_name || null;
    let query = 'SELECT * FROM poll_log';
    const params = [];
    if (oltName) { query += ' WHERE olt_name = ?'; params.push(oltName); }
    query += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);
    const rows = db.prepare(query).all(...params);
    res.json(rows);
  } catch(err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── API: DB STATS (untuk halaman admin) ───
app.get('/api/db-stats', requireAuth, (req, res) => {
  try {
    const tables = ['history', 'onu_cache', 'poll_log'].map(t => ({
      name: t,
      count: db.prepare(`SELECT COUNT(*) as c FROM ${t}`).get().c,
    }));
    res.json({ success: true, tables });
  } catch(err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── API: CLEAR ONU CACHE (untuk halaman admin) ───
app.delete('/api/onu-cache/clear', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM onu_cache').run();
    db.prepare('DELETE FROM poll_log').run();
    res.json({ success: true, message: 'Cache ONU dan poll log berhasil dihapus' });
  } catch(err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── PORT ───
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
  console.log(`[POLLER] Background poller aktif, interval: ${POLL_INTERVAL_MS / 60000} menit`);
});