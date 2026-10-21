const express = require('express');
const { Telnet } = require('telnet-client');
const cors = require('cors');
const path = require('path');
const Database = require('better-sqlite3');
const snmp = require('net-snmp');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const createUptimeMonitor = require('./uptime-monitor-backend');

const JWT_SECRET = process.env.JWT_SECRET || 'nocs-secret-key-ganti-di-production';

const app = express();
app.use(cors());
app.use(express.json());

// --- AUTH MIDDLEWARE ---
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

// --- STATIC FILES (public bebas akses) ---
app.use(express.static(path.join(__dirname, 'public')));

// --- SQLITE SETUP ---
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

// --- TABEL CACHE ONU ---
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
  CREATE TABLE IF NOT EXISTS olt_health (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    olt_name    TEXT NOT NULL,
    slot_index  TEXT NOT NULL,
    card_type   TEXT,
    oper_status INTEGER,
    cpu_load    INTEGER,
    mem_usage   INTEGER,
    updated_at  TEXT DEFAULT (datetime('now', 'localtime')),
    UNIQUE(olt_name, slot_index)
  );
  CREATE TABLE IF NOT EXISTS olt_sys_info (
    olt_name    TEXT PRIMARY KEY,
    sys_uptime  TEXT,
    updated_at  TEXT DEFAULT (datetime('now', 'localtime'))
  );
`);

const uptimeMonitor = createUptimeMonitor(db, requireAuth);
app.use('/api/uptime', uptimeMonitor.router);
uptimeMonitor.startScheduler(); 

// Migration: tambah kolom rxPower jika belum ada (untuk database lama)
try {
  db.exec(`ALTER TABLE history ADD COLUMN rxPower TEXT`);
} catch(e) { /* kolom sudah ada, abaikan */ }

// --- TABEL USERS ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role    TEXT NOT NULL DEFAULT 'operator',
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )
`);

// --- TABEL MIKROTIK CONFIG (persisten) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS mikrotik_config (
    name     TEXT PRIMARY KEY,
    host     TEXT NOT NULL,
    port     INTEGER DEFAULT 8728,
    username TEXT NOT NULL,
    password TEXT NOT NULL
  )
`);

// --- TABEL SNMP DEVICE CONFIG (persisten) � device generik dipantau via SNMP ---
db.exec(`
  CREATE TABLE IF NOT EXISTS snmp_device_config (
    name      TEXT PRIMARY KEY,
    host      TEXT NOT NULL,
    port      INTEGER DEFAULT 161,
    community TEXT DEFAULT 'public'
  )
`);

// --- TABEL PROXMOX CONFIG (persisten) — monitoring resource via API token Proxmox VE ---
// token_id     : format "user@realm!tokenname", contoh "monitor@pve!nocs"
// token_secret : UUID secret yang muncul sekali saat token dibuat
db.exec(`
  CREATE TABLE IF NOT EXISTS proxmox_config (
    name         TEXT PRIMARY KEY,
    host         TEXT NOT NULL,
    port         INTEGER DEFAULT 8006,
    token_id     TEXT NOT NULL,
    token_secret TEXT NOT NULL
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

// --- RESET ADMIN via ENV (darurat) ---
if (process.env.RESET_ADMIN_PASSWORD) {
  db.prepare('UPDATE users SET password_hash = ? WHERE username = ?')
    .run(hashPassword(process.env.RESET_ADMIN_PASSWORD), 'admin');
  console.log('[AUTH] Password admin berhasil direset via RESET_ADMIN_PASSWORD env var');
}

// --- API: LOGIN ---
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

// --- API: VERIFY TOKEN ---
app.get('/api/auth/verify', requireAuth, (req, res) => {
  res.json({ success: true, user: req.user });
});

// --- API: LOGOUT ---
app.post('/api/auth/logout', requireAuth, (req, res) => {
  res.json({ success: true, message: 'Logout berhasil' });
});

// --- API: DAFTAR USER (admin only) ---
app.get('/api/users', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Akses ditolak' });
  const users = db.prepare('SELECT id, username, role, created_at FROM users').all();
  res.json({ success: true, users });
});

// --- API: TAMBAH USER (admin only) ---
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

// --- API: HAPUS USER (admin only) ---
app.delete('/api/users/:id', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Akses ditolak' });
  if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ success: false, message: 'Tidak bisa menghapus akun sendiri' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// --- API: GANTI PASSWORD ---
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

// --- TELEGRAM CONFIG ---
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '8472144825:AAHiPFn45XInWpMOJaCiUnYOFl5kPbvsnhQ';
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID   || '-4871262336';
const TELEGRAM_ENABLED   = !!TELEGRAM_BOT_TOKEN && !!TELEGRAM_CHAT_ID;

const OLT_CONFIG = {
  'OLT-C320-DEMPET': {
    host: '10.136.1.1',
    username: 'zte',
    password: 'zte',
    port: 233,
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
  'OLT-C300-DEMPET - CCTV': {
    host: '10.136.3.1',
    username: 'zte',
    password: 'zte',
    port: 233,
    vendor: 'OLT2-CCTV',
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
      `tr069-mgmt 1 state unlock`,
      `tr069-mgmt 1 acs http://192.168.11.21:1708 validate basic username acs@merdeka.net.id password merdeka`,
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
      `tr069-mgmt 1 state unlock`,
      `tr069-mgmt 1 acs http://192.168.11.21:1708 validate basic username acs@merdeka.net.id password merdeka`,
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
      `tr069-mgmt 1 state unlock`,
      `tr069-mgmt 1 acs http://192.168.11.21:1708 validate basic username acs@merdeka.net.id password merdeka`,
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
      `tr069-mgmt 1 state unlock`,
      `tr069-mgmt 1 acs http://192.168.11.21:1708 validate basic username acs@merdeka.net.id password merdeka`,
      `end`,
      `write`,
      '',
    ].join('\n');
  }

  if (vendor === 'OLT2-CCTV') {
    return [
      `conf t`,
      `interface gpon-olt_1/${slot}/${port}`,
      `onu ${onuId} type ZTE-F609 sn ${sn}`,
      `exit`,
      `interface gpon-onu_1/${slot}/${port}:${onuId}`,
      `name ${lokasi} - ${namaPelanggan}`,
      `description 1$$ ${namaPelanggan} - ${lokasi} $$`,
      `tcont 1 name MTC profile 100M`,
      `tcont 2 name HOT profile 100M`,
      `gemport 1 name MTC tcont 1`,
      `gemport 1 traffic-limit upstream UP100M downstream DW100M`,
      `gemport 2 name HOT tcont 2`,
      `gemport 2 traffic-limit upstream UP100M downstream DW100M`,
      `service-port 1 vport 1 user-vlan 602 vlan 602`,
      `service-port 2 vport 2 user-vlan 502 vlan 502`,
      `port-identification format DSL-FORUM-PON sport 1`,
      `pppoe-intermediate-agent enable sport 1`,
      `exit`,
      `pon-onu-mng gpon-onu_1/${slot}/${port}:${onuId}`,
      `service MTC gemport 1 vlan 602`,
      `service HOT gemport 2 vlan 502`,
      `wan-ip 1 mode pppoe username ${idPppoe}@MERDEKA.NET.ID  password ${idPppoe} vlan-profile PPPoE host 1`,
      `wan-ip 1 ping-response enable traceroute-response enable`,
      `security-mgmt 1 state enable mode forward protocol web`,
      `vlan port eth_0/1 mode tag vlan 502`,
      `vlan port eth_0/2 mode tag vlan 502`,
      `vlan port eth_0/3 mode tag vlan 502`,
      `vlan port eth_0/4 mode tag vlan 502`,
      `end`,
      `write`,
      '',
    ].join('\n');
  }


  return `! Unknown vendor: ${vendor}`;
}

// // --- API: GET OLTs ---
// app.get('/api/olts', requireAuth, (req, res) => {
//   const list = Object.entries(OLT_CONFIG).map(([name, cfg]) => ({
//     name,
//     host: cfg.host,
//     port: cfg.port,
//     username: cfg.username,
//     vendor: cfg.vendor,
//   }));
//   res.json(list);
// });

app.get('/api/olts', requireAuth, (req, res) => {
  const list = Object.entries(OLT_CONFIG)
    .map(([name, cfg]) => ({
      name,
      host: cfg.host,
      port: cfg.port,
      username: cfg.username,
      vendor: cfg.vendor,
    }));
  res.json(list);
});

// --- API: GET HISTORY ---
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

// --- API: ADD HISTORY ---
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

// --- API: DELETE ONE HISTORY ---
app.delete('/api/history/:id', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM history WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// --- API: CLEAR ALL HISTORY ---
app.delete('/api/history', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM history').run();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// --- TELNET HELPER ---
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

// --- API: ACTIVATE ---
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

    // --- QUERY RX OPTICAL POWER ---
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

// --- API: TEST TELNET ---
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

// --- API: SCAN UNCONFIGURED ONU ---
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

// --- API: CARI ONU ID KOSONG (belum dipakai) DI SUATU PORT ---
// Dipakai saat registrasi ONU baru yang belum ke-config: mencari ID pertama yang
// belum dipakai oleh ONU lain di port yang sama, berdasarkan data onu_cache
// (hasil polling SNMP berkala) sehingga tidak perlu telnet on-demand.
app.post('/api/find-free-onuid', requireAuth, (req, res) => {
  const { oltName, slot, port, maxId } = req.body;

  if (!oltName || !slot || !port) {
    return res.status(400).json({ success: false, message: 'Field wajib: OLT, Slot, Port' });
  }

  const oltCfg = OLT_CONFIG[oltName];
  if (!oltCfg) {
    return res.status(404).json({ success: false, message: `OLT "${oltName}" tidak ditemukan` });
  }

  const slotNum = parseInt(slot);
  const portNum = parseInt(port);
  const limit = parseInt(maxId) || 128; // ZTE C320 GPON: umumnya maksimal 128 ONU per port

  if (isNaN(slotNum) || isNaN(portNum)) {
    return res.status(400).json({ success: false, message: 'Slot/Port harus berupa angka' });
  }

  try {
    const rows = db.prepare(
      'SELECT onu_id FROM onu_cache WHERE olt_name = ? AND slot = ? AND port = ? AND onu_id IS NOT NULL ORDER BY onu_id'
    ).all(oltName, slotNum, portNum);

    const usedIds = rows.map(r => r.onu_id);
    const usedSet = new Set(usedIds);

    let freeId = null;
    for (let i = 1; i <= limit; i++) {
      if (!usedSet.has(i)) { freeId = i; break; }
    }

    if (freeId === null) {
      return res.json({
        success: false,
        message: `Semua ID (1-${limit}) di port gpon-olt_1/${slot}/${port} sudah terpakai`,
        usedIds, maxId: limit,
      });
    }

    res.json({
      success: true,
      freeId,
      usedIds,
      maxId: limit,
      message: `ID kosong ditemukan: ${freeId} (${usedIds.length} ID sudah terpakai di port ini)`,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Gagal membaca cache ONU: ' + err.message });
  }
});

// --- API: ADMIN � TAMBAH OLT ---
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

// --- API: ADMIN � EDIT OLT ---
app.put('/api/admin/olt', requireAuth, (req, res) => {
  const { name, host, port, username, password, vendor } = req.body;
  if (!name || !OLT_CONFIG[name]) {
    return res.status(404).json({ success: false, message: `OLT "${name}" tidak ditemukan` });
  }
  OLT_CONFIG[name] = { host, port: parseInt(port) || 23, username: username || 'zte', password: password || 'zte', vendor };
  res.json({ success: true, message: `OLT "${name}" berhasil diperbarui` });
});

// --- API: ADMIN � HAPUS OLT ---
app.delete('/api/admin/olt/:name', requireAuth, (req, res) => {
  const name = decodeURIComponent(req.params.name);
  if (!OLT_CONFIG[name]) {
    return res.status(404).json({ success: false, message: `OLT "${name}" tidak ditemukan` });
  }
  delete OLT_CONFIG[name];
  res.json({ success: true, message: `OLT "${name}" berhasil dihapus` });
});

// --- API: ADMIN � GET OLT DETAIL (dengan credential) ---
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

// --- SNMP HELPERS ---
const SNMP_COMMUNITY = 'public';
const SNMP_PORT = 161;
const SNMP_VERSION = snmp.Version2c;
const SNMP_TIMEOUT = 10000; // 10 dtk (sebelumnya 5000): walk tabel ZTE C300 bisa lambat
const SNMP_RETRIES = 1;

// OID ZTE GPON C320/C300 (verified via snmpwalk)
const OID = {
  // ONU name/display name � suffix: <portIndex>.<onuId>
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
  // OLT RX power (receive from ONU side) � unit: 0.001 dBm signed
  oltRxPower:       '1.3.6.1.4.1.3902.1015.1010.11.2.1.2',
  // Upstream octets
  upOctets:         '1.3.6.1.2.1.31.1.1.1.6',
  // Downstream octets
  downOctets:       '1.3.6.1.2.1.31.1.1.1.10',
  // sysUpTime
  sysUpTime:        '1.3.6.1.2.1.1.3.0',

  // --- Chassis / Card health (ZTE-AN-CHASSIS-MIB, belum diverifikasi manual —
  //     diambil dari dokumentasi spesifikasi MIB ZTE C300/C320, mohon dicek
  //     hasil aktualnya setelah deploy) ---
  // Nama/tipe card per slot (STRING) — suffix: <rack>.<shelf>.<slot>
  cardType:         '1.3.6.1.4.1.3902.1082.10.1.2.4.1.4',
  // Status operasional card (INTEGER)
  cardOperStatus:   '1.3.6.1.4.1.3902.1082.10.1.2.4.1.5',
  // CPU load card (INTEGER, persen)
  cardCpuLoad:      '1.3.6.1.4.1.3902.1082.10.1.2.4.1.9',
  // Memory usage card (INTEGER, persen)
  cardMemUsage:     '1.3.6.1.4.1.3902.1082.10.1.2.4.1.11',
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
    session.subtree(rootOid, 10, (varbinds) => {
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

// Bungkus snmpGetSubtree dengan pengukuran waktu per-OID, supaya kelihatan
// di log OID/subtree mana yang jadi bottleneck untuk OLT tertentu.
// Hanya nge-log kalau durasinya cukup signifikan (>1.5s) supaya log tidak
// penuh untuk OLT yang memang cepat (mis. KARANGAWEN/MINTRENG).
async function timedSubtree(oltName, host, rootOid, label) {
  const t0 = Date.now();
  try {
    const rows = await snmpGetSubtree(host, rootOid);
    const dur = Date.now() - t0;
    if (dur > 1500) {
      console.log(`[POLLER][DIAG] ${oltName} · ${label}: ${rows.length} baris dalam ${dur}ms`);
    }
    return rows;
  } catch (e) {
    const dur = Date.now() - t0;
    console.log(`[POLLER][DIAG] ${oltName} · ${label}: GAGAL setelah ${dur}ms — ${e.message}`);
    throw e;
  }
}

// Sama seperti snmpGetSubtree, tapi maxRepetitions bisa diatur.
// ZTE C300 sering membalas GeneralError kalau GETBULK terlalu besar.
function snmpGetSubtreeRep(host, rootOid, maxRep = 3) {
  return new Promise((resolve, reject) => {
    const session = snmpSession(host);
    const results = [];
    session.subtree(rootOid, maxRep, (varbinds) => {
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

// Walk per port: subtree kecil. Kalau satu port gagal (GeneralError dari agent C300),
// ONU di port itu diambil lewat GET langsung per-OID (batch kecil, dibatasi waktu),
// sehingga satu port bermasalah tidak mengosongkan datanya.
const PORT_FALLBACK_BUDGET_MS = 20000;
async function walkByPort(oltName, host, rootOid, label, portIdxList, fallbackSuffixes = [], maxRep = 3) {
  const t0 = Date.now();
  const all = [];
  const failed = [];
  let fbRows = 0;
  const leaf = label === 'onuRxPower' ? '.1' : '';
  // Redaman hanya ada untuk ONU online: port yang tidak punya ONU online dilewati
  // (di C300, walk port seperti itu malah GeneralError dan menghabiskan puluhan detik).
  const skipOfflinePorts = label === 'onuRxPower' && fallbackSuffixes.length > 0;
  let skipped = 0;
  for (const p of portIdxList) {
    if (skipOfflinePorts && !fallbackSuffixes.some(sf => sf.split('.')[0] === String(p))) {
      skipped++;
      continue;
    }
    let ok = false;
    for (let attempt = 0; attempt < 2 && !ok; attempt++) {
      try {
        all.push(...await snmpGetSubtreeRep(host, `${rootOid}.${p}`, maxRep));
        ok = true;
      } catch (e) {
        // GeneralError itu deterministik, retry cuma buang waktu
        if (/GeneralError/i.test(String(e && e.message))) break;
        await sleep(300);
      }
    }
    if (ok) continue;

    const { slot, port } = parseOnuIndex(p, 0);
    failed.push(`1/${slot}/${port}`);
    // Fallback: GET per-OID, batch 4, dibatasi PORT_FALLBACK_BUDGET_MS per port
    const sfx = fallbackSuffixes.filter(sf => sf.split('.')[0] === String(p));
    const t1 = Date.now();
    const pushVbs = (vbs) => {
      for (const vb of vbs || []) {
        if (snmp.isVarbindError(vb)) continue;
        all.push({ oid: vb.oid, value: vb.value });
        fbRows++;
      }
    };
    for (let i = 0; i < sfx.length && Date.now() - t1 < PORT_FALLBACK_BUDGET_MS; i += 4) {
      const oids = sfx.slice(i, i + 4).map(sf => `${rootOid}.${sf}${leaf}`);
      try { pushVbs(await snmpGet(host, oids)); }
      catch (e) {
        for (const o of oids) {
          if (Date.now() - t1 >= PORT_FALLBACK_BUDGET_MS) break;
          try { pushVbs(await snmpGet(host, [o])); } catch (e2) {}
        }
      }
    }
  }
  console.log(`[POLLER][DIAG] ${oltName} · ${label} per-port: ${all.length} baris, ${failed.length}/${portIdxList.length} port gagal, ${skipped} port dilewati (tanpa ONU online)${failed.length ? ' (' + failed.join(', ') + ', fallback GET: ' + fbRows + ' baris)' : ''}, ${Date.now() - t0}ms`);
  // Kalau tidak dapat apa pun, lempar error supaya cache lama dipertahankan (bukan ditimpa kosong)
  if (all.length === 0) throw new Error(`${label}: semua port gagal`);
  return all;
}

// GET dengan timeout pendek & tanpa retry: ONU yang tidak menjawab tidak boleh menahan poll lama.
function snmpGetFast(host, oids) {
  return new Promise((resolve, reject) => {
    const session = snmp.createSession(host, SNMP_COMMUNITY, {
      port: SNMP_PORT, retries: 0, timeout: 3000, version: SNMP_VERSION,
    });
    session.get(oids, (err, varbinds) => {
      session.close();
      if (err) return reject(err);
      resolve(varbinds);
    });
  });
}

// Ambil nilai per ONU lewat GET (batch kecil), tanpa walk. Dipakai untuk redaman C300:
// walk tabel redaman C300 macet/timeout saat GETNEXT melompati celah nomor ONU, dan agent
// C300 lambat (~0,25 dtk/ONU). Jadi tiap panggilan hanya mengambil SEBAGIAN ONU (dibatasi
// waktu), lalu lanjut dari posisi terakhir di panggilan berikutnya (rotasi), dan nilai
// yang belum terambil memakai cache. Semua ONU online tercover dalam beberapa siklus.
// suffixes: array "<portIndex>.<onuId>".
const ONU_GET_BATCH = 6;
const ONU_GET_BUDGET_MS = 25000;
const onuGetCursor = new Map(); // "olt|label" -> indeks mulai berikutnya
async function getByOnu(oltName, host, rootOid, label, suffixes, budgetMs = ONU_GET_BUDGET_MS) {
  const t0 = Date.now();
  const leaf = label === 'onuRxPower' ? '.1' : '';
  const list = [...suffixes].sort();
  if (!list.length) return [];
  const key = `${oltName}|${label}`;
  const start = (onuGetCursor.get(key) || 0) % list.length;
  const rows = [];
  let done = 0, batches = 0, batchGagal = 0, onuGagal = 0;
  const pushVbs = (vbs) => {
    for (const vb of vbs || []) {
      if (snmp.isVarbindError(vb)) continue;
      rows.push({ oid: vb.oid, value: vb.value });
    }
  };
  while (done < list.length && Date.now() - t0 < budgetMs) {
    const chunk = [];
    for (let k = 0; k < ONU_GET_BATCH && done + k < list.length; k++) {
      chunk.push(list[(start + done + k) % list.length]);
    }
    const oids = chunk.map(sf => `${rootOid}.${sf}${leaf}`);
    batches++;
    try {
      pushVbs(await snmpGetFast(host, oids));
    } catch (e) {
      // satu OID bermasalah menggagalkan seluruh batch -> ulangi satu-satu
      batchGagal++;
      for (const o of oids) {
        if (Date.now() - t0 >= budgetMs) break;
        try { pushVbs(await snmpGetFast(host, [o])); } catch (e2) { onuGagal++; }
      }
    }
    done += chunk.length;
  }
  onuGetCursor.set(key, (start + done) % list.length);
  const valid = rows.filter(r => { const v = Number(r.value); return v !== 65535 && !isNaN(v); }).length;
  console.log(`[POLLER][DIAG] ${oltName} · ${label} per-ONU GET: diproses ${done}/${list.length} (mulai idx ${start}), ${rows.length} baris (${valid} valid), ${batchGagal}/${batches} batch gagal, ${onuGagal} ONU gagal, ${Date.now() - t0}ms`);
  if (rows.length === 0 && done > 0) throw new Error(`${label}: GET per ONU tidak mengembalikan data`);
  return rows;
}

// OID yang di C300 harus di-walk per port (walk tunggal -> GeneralError)
const C300_BY_PORT = ['onuLastOnline', 'onuLastOffline'];

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

// --------------------------------------------------------------
// --- SNMP DEVICE GENERIK (device apapun yang support SNMP, IF-MIB standar) ---
// Dipakai untuk widget "Live Bandwidth Traffic" di Dashboard, tanpa perlu API Mikrotik (port 8728)
// --------------------------------------------------------------

// OID standar IF-MIB (RFC 2863) � berlaku umum utk switch/router/device apapun
const IFMIB = {
  ifDescr:       '1.3.6.1.2.1.2.2.1.2',   // nama/deskripsi interface - suffix: <ifIndex>
  ifOperStatus:  '1.3.6.1.2.1.2.2.1.8',   // status: 1=up, 2=down - suffix: <ifIndex>
  ifHCInOctets:  '1.3.6.1.2.1.31.1.1.1.6',  // counter byte masuk 64-bit (ifXTable, tidak semua device support) - suffix: <ifIndex>
  ifHCOutOctets: '1.3.6.1.2.1.31.1.1.1.10', // counter byte keluar 64-bit (ifXTable, tidak semua device support) - suffix: <ifIndex>
  ifInOctets:    '1.3.6.1.2.1.2.2.1.10',  // counter byte masuk 32-bit (ifTable dasar, fallback universal) - suffix: <ifIndex>
  ifOutOctets:   '1.3.6.1.2.1.2.2.1.16',  // counter byte keluar 32-bit (ifTable dasar, fallback universal) - suffix: <ifIndex>
  sysName:       '1.3.6.1.2.1.1.5.0',
};

function getSnmpDeviceCfg(name) {
  return db.prepare('SELECT * FROM snmp_device_config WHERE name = ?').get(name);
}

// Sama seperti snmpSession() tapi community bisa custom per-device
function snmpSessionC(host, community) {
  return snmp.createSession(host, community || SNMP_COMMUNITY, {
    port: SNMP_PORT,
    retries: SNMP_RETRIES,
    timeout: SNMP_TIMEOUT,
    version: SNMP_VERSION,
  });
}

function snmpGetC(host, community, oids) {
  return new Promise((resolve, reject) => {
    const session = snmpSessionC(host, community);
    session.get(oids, (err, varbinds) => {
      session.close();
      if (err) return reject(err);
      resolve(varbinds);
    });
  });
}

function snmpGetSubtreeC(host, community, rootOid) {
  return new Promise((resolve, reject) => {
    const session = snmpSessionC(host, community);
    const results = [];
    session.subtree(rootOid, 10, (varbinds) => {
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

// --- ADMIN: CRUD Device SNMP ---
app.get('/api/admin/snmp-device', requireAuth, (req, res) => {
  const list = db.prepare('SELECT name, host, port, community FROM snmp_device_config').all();
  res.json(list);
});

app.post('/api/admin/snmp-device', requireAuth, (req, res) => {
  const { name, host, port, community } = req.body;
  if (!name || !host)
    return res.status(400).json({ success: false, message: 'name dan host wajib diisi' });
  try {
    db.prepare('INSERT INTO snmp_device_config (name, host, port, community) VALUES (?, ?, ?, ?)')
      .run(name, host, parseInt(port) || 161, community || 'public');
    res.json({ success: true, message: `Device "${name}" berhasil ditambahkan` });
  } catch(e) {
    res.status(409).json({ success: false, message: `Device "${name}" sudah ada` });
  }
});

app.put('/api/admin/snmp-device', requireAuth, (req, res) => {
  const { name, host, port, community } = req.body;
  const existing = getSnmpDeviceCfg(name);
  if (!name || !existing)
    return res.status(404).json({ success: false, message: `Device "${name}" tidak ditemukan` });
  db.prepare('UPDATE snmp_device_config SET host=?, port=?, community=? WHERE name=?')
    .run(
      host || existing.host,
      parseInt(port) || existing.port,
      community || existing.community,
      name
    );
  res.json({ success: true, message: `Device "${name}" berhasil diperbarui` });
});

app.delete('/api/admin/snmp-device/:name', requireAuth, (req, res) => {
  const name = decodeURIComponent(req.params.name);
  if (!getSnmpDeviceCfg(name))
    return res.status(404).json({ success: false, message: `Device "${name}" tidak ditemukan` });
  db.prepare('DELETE FROM snmp_device_config WHERE name = ?').run(name);
  res.json({ success: true, message: `Device "${name}" berhasil dihapus` });
});

// --- TEST KONEKSI SNMP ---
app.post('/api/snmp-device/test', requireAuth, async (req, res) => {
  const { deviceName, host, port, community } = req.body;
  const cfg = getSnmpDeviceCfg(deviceName) || { host, port, community };
  if (!cfg.host) return res.status(400).json({ success: false, message: 'Host wajib diisi' });
  try {
    const vbs = await snmpGetC(cfg.host, cfg.community, [IFMIB.sysName]);
    if (snmp.isVarbindError(vbs[0])) throw new Error('Tidak ada respon dari device (cek IP/community/firewall)');
    res.json({ success: true, message: `Terhubung! sysName: ${vbs[0].value.toString()}` });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// --- SNMP DEVICE: DAFTAR INTERFACE (utk widget Live Bandwidth) ---
app.get('/api/snmp-device/:name/interfaces', requireAuth, async (req, res) => {
  const cfg = getSnmpDeviceCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Device tidak ditemukan' });
  try {
    const [descRows, statusRows] = await Promise.all([
      snmpGetSubtreeC(cfg.host, cfg.community, IFMIB.ifDescr),
      snmpGetSubtreeC(cfg.host, cfg.community, IFMIB.ifOperStatus),
    ]);
    const statusMap = {};
    statusRows.forEach(r => {
      const ifIndex = r.oid.replace(IFMIB.ifOperStatus + '.', '');
      statusMap[ifIndex] = Number(r.value) === 1;
    });
    const interfaces = descRows.map(r => {
      const ifIndex = r.oid.replace(IFMIB.ifDescr + '.', '');
      return { ifIndex, name: r.value.toString(), running: !!statusMap[ifIndex] };
    });
    res.json({ success: true, interfaces });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message + ' (cek IP/community/firewall SNMP)' });
  }
});

// Konversi value hasil net-snmp jadi Number dengan benar.
// PENTING: utk tipe Counter64 (ifHCInOctets/ifHCOutOctets), net-snmp mengembalikan
// value sbg Buffer mentah (big-endian raw bytes), BUKAN angka JS biasa.
// Number(buffer) akan selalu jadi NaN (lalu ke-serialize jadi null oleh JSON,
// dan di-default-kan ke 0 di frontend) - itu penyebab traffic selalu kebaca 0.
function snmpValueToNumber(value) {
  if (Buffer.isBuffer(value)) {
    let n = 0n;
    for (const byte of value) n = (n << 8n) | BigInt(byte);
    return Number(n);
  }
  return Number(value);
}

// --- SNMP DEVICE: TRAFFIC (rx/tx byte counter, utk widget Live Bandwidth) ---
app.get('/api/snmp-device/:name/interface/traffic', requireAuth, async (req, res) => {
  const cfg = getSnmpDeviceCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Device tidak ditemukan' });

  const { ifIndex } = req.query;
  if (!ifIndex) return res.status(400).json({ success: false, message: 'Parameter ifIndex wajib diisi' });

  try {
    // Coba dulu counter 64-bit (ifXTable) - lebih akurat utk interface >100Mbps
    let vbs = await snmpGetC(cfg.host, cfg.community, [
      `${IFMIB.ifHCInOctets}.${ifIndex}`,
      `${IFMIB.ifHCOutOctets}.${ifIndex}`,
    ]);
    let hasHC = !snmp.isVarbindError(vbs[0]) && !snmp.isVarbindError(vbs[1]);

    // Fallback ke counter 32-bit (ifTable dasar) kalau device tidak support ifXTable
    // (umum terjadi pada switch/ONU/router low-end yang cuma implement IF-MIB dasar)
    if (!hasHC) {
      vbs = await snmpGetC(cfg.host, cfg.community, [
        `${IFMIB.ifInOctets}.${ifIndex}`,
        `${IFMIB.ifOutOctets}.${ifIndex}`,
      ]);
    }

    const rxBytes = !snmp.isVarbindError(vbs[0]) ? snmpValueToNumber(vbs[0].value) : 0;
    const txBytes = !snmp.isVarbindError(vbs[1]) ? snmpValueToNumber(vbs[1].value) : 0;

    if (snmp.isVarbindError(vbs[0]) && snmp.isVarbindError(vbs[1])) {
      return res.status(500).json({ success: false, message: `Device tidak mengembalikan counter traffic utk ifIndex ${ifIndex} (baik ifXTable maupun ifTable dasar). Cek apakah interface ini benar & OID counter didukung device.` });
    }

    res.json({ success: true, ifIndex, rxBytes, txBytes, counterType: hasHC ? '64-bit' : '32-bit' });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Konversi ONU portIndex ZTE C320 ? slot/port
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
  let val = parseInt(raw);
  if (isNaN(val)) return null;
  // Redaman lebih buruk dari -30 dBm butuh raw negatif, tapi net-snmp kadang
  // membacanya sebagai unsigned 32-bit sehingga wrap ke angka raksasa
  // (mendekati 4.294.967.295). Deteksi dan koreksi di sini.
  if (val > 0x7FFFFFFF) val -= 0x100000000;
  const dbm = (val - 15000) * 0.002;
  if (dbm < -40 || dbm > 5) return null; // sanity check (diperlonggar dari -35 ke -40)
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

// --- API: SNMP � MONITOR ONU LIST ---
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

    // 2. Walk ONU name table � suffix: <portIndex>.<onuId>
    const nameRows = await snmpGetSubtree(host, OID.onuName);
    if (!nameRows.length) {
      return res.json({ ...result, onus: [], error: 'Tidak ada data ONU dari SNMP. Pastikan SNMP v2c diaktifkan di OLT dan community "public" benar.' });
    }

    // 3. Walk ONU oper status � suffix: <portIndex>.<onuId>
    // Helper: C300 di-walk per port untuk OID tertentu (walk tunggal -> GeneralError)
    const isC300 = /C300/.test(oltName);
    const monPortIdx = [...new Set(nameRows.map(r => r.oid.replace(OID.onuName + '.', '').split('.')[0]))];
    // C300: redaman diisi bertahap oleh poller background; endpoint ini baca dari cache
    const cacheRx = {};
    if (isC300) {
      try {
        db.prepare('SELECT suffix, rx_power FROM onu_cache WHERE olt_name = ?').all(oltName)
          .forEach(r => { cacheRx[r.suffix] = r.rx_power; });
      } catch (e) {}
    }
    const walkMon = (key) => (isC300 && key === 'onuRxPower')
      ? Promise.resolve([])
      : (isC300 && C300_BY_PORT.includes(key))
      ? walkByPort(oltName, host, OID[key], key, monPortIdx, nameRows.map(r => r.oid.replace(OID.onuName + '.', '')))
      : snmpGetSubtree(host, OID[key]);

    let statusMap = {};
    try {
      const statusRows = await snmpGetSubtree(host, OID.onuOperStatus);
      statusRows.forEach(r => {
        const suffix = r.oid.replace(OID.onuOperStatus + '.', '');
        statusMap[suffix] = Number(r.value);
      });
    } catch(e) {}

    // 4. Walk ONU RX power � suffix: <portIndex>.<onuId>.1
    let rxMap = {};
    try {
      const rxRows = await walkMon('onuRxPower');
      rxRows.forEach(r => {
        const full = r.oid.replace(OID.onuRxPower + '.', '');
        // strip segmen angka TERAKHIR apa pun (bukan cuma literal ".1"),
        // karena entryIndex-nya bisa beda-beda tergantung slot/kartu
        const key = full.replace(/\.\d+$/, '');
        rxMap[key] = r.value;
      });
    } catch(e) {}

    // 5. Walk ONU serial number � suffix: <portIndex>.<onuId>
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

    // 6. Walk ONU last online time � suffix: <portIndex>.<onuId>
    let lastOnlineMap = {};
    try {
      const loRows = await walkMon('onuLastOnline');
      loRows.forEach(r => {
        const suffix = r.oid.replace(OID.onuLastOnline + '.', '');
        lastOnlineMap[suffix] = r.value ? r.value.toString() : null;
      });
    } catch(e) {}

    // 7. Walk ONU last offline time � suffix: <portIndex>.<onuId>
    let lastOfflineMap = {};
    try {
      const lofRows = await walkMon('onuLastOffline');
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
        serialNumber: snMap[suffix] || '�',
        lastOnline: lastOnlineMap[suffix] || null,
        lastOffline: lastOfflineMap[suffix] || null,
        statusCode,
        statusLabel: st.label,
        statusColor: st.color,
        rxPower: isC300 ? (cacheRx[suffix] !== undefined ? cacheRx[suffix] : null) : rxPowerToDbm(rxRaw),
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
    if (msg.includes('Timeout')) hint = 'Timeout � pastikan SNMP diaktifkan di OLT, port 161 UDP tidak diblokir firewall.';
    else if (msg.includes('ECONNREFUSED')) hint = 'Koneksi ditolak � periksa host/IP OLT.';
    res.json({ success: false, ...result, onus: [], error: hint || msg });
  }
});

// --- API: SNMP — RENAME ONU (ubah "name" di OLT, dipakai tombol Edit di Monitor ONU) ---
// Cuma mengubah atribut "name" (OID onuName, yang tampil sebagai kolom ONU/PELANGGAN di
// Monitor ONU). SENGAJA tidak menyentuh "description" (OID onuDesc, format "N$$...$$") —
// itu field terpisah yang cuma di-set sekali saat aktivasi awal (lihat generateScript) dan
// tidak pernah dibaca/ditampilkan di Monitor ONU, jadi berisiko salah rekonstruksi kalau
// ikut diubah di sini tanpa tahu persis lokasi & nama pelanggan aslinya terpisah.
app.patch('/api/snmp/onu-rename', requireAuth, async (req, res) => {
  const { oltName, slot, port, onuId, name } = req.body;

  if (!oltName || slot === undefined || slot === null || port === undefined || port === null ||
      onuId === undefined || onuId === null || !name) {
    return res.status(400).json({ success: false, message: 'Field wajib: oltName, slot, port, onuId, name' });
  }

  const slotNum = Number(slot), portNum = Number(port), onuIdNum = Number(onuId);
  if (!Number.isInteger(slotNum) || !Number.isInteger(portNum) || !Number.isInteger(onuIdNum)) {
    return res.status(400).json({ success: false, message: 'slot/port/onuId harus berupa angka' });
  }

  const newName = String(name).trim();
  if (!newName) {
    return res.status(400).json({ success: false, message: 'Nama tidak boleh kosong' });
  }
  // Cegah command injection ke sesi Telnet OLT — telnetExec mengirim tiap command apa
  // adanya, jadi newline di dalam nama bisa dipakai buat nyelipin command CLI tambahan.
  if (/[\r\n]/.test(newName)) {
    return res.status(400).json({ success: false, message: 'Nama tidak boleh mengandung baris baru' });
  }

  const oltCfg = OLT_CONFIG[oltName];
  if (!oltCfg) {
    return res.status(404).json({ success: false, message: `OLT "${oltName}" tidak ditemukan` });
  }

  const iface = `gpon-onu_1/${slotNum}/${portNum}:${onuIdNum}`;
  const commands = [
    `conf t`,
    `interface ${iface}`,
    `name ${newName}`,
    `end`,
    `write`,
  ];
  const log = [];

  try {
    log.push(`[INFO] Connecting to ${oltCfg.host}:${oltCfg.port || 23} via Telnet...`);
    await telnetExec(oltCfg, commands, log);
    log.push(`[OK]   Nama ONU ${iface} berhasil diubah menjadi "${newName}"`);

    // Update cache lokal langsung supaya Monitor ONU konsisten sebelum poll berikutnya (tiap 2 menit)
    try {
      db.prepare(`
        UPDATE onu_cache SET name = ?, updated_at = datetime('now','localtime')
        WHERE olt_name = ? AND slot = ? AND port = ? AND onu_id = ?
      `).run(newName, oltName, slotNum, portNum, onuIdNum);
    } catch (cacheErr) {
      log.push(`[WARN] Gagal update cache lokal: ${cacheErr.message}`);
    }

    res.json({ success: true, name: newName, log: log.join('\n') });
  } catch (err) {
    log.push(`[FAIL] Telnet Error: ${err.message}`);
    res.status(500).json({ success: false, message: err.message, log: log.join('\n') });
  }
});

// --- API: SNMP — GANTI DEVICE / SN ONU (dipakai tombol "Ganti device" di Monitor ONU) ---
// Dipakai saat ONU fisik mati/rusak diganti unit baru: slot/port/onuId dan semua config
// yang sudah ada di interface gpon-onu (name, tcont, gemport, service-port, pon-onu-mng,
// wan-ip pppoe, dst — lihat generateScript) TIDAK disentuh sama sekali dan TIDAK perlu
// dihapus/didaftar ulang — cukup masuk ke interface ONU yang sama lalu ganti binding SN-nya
// pakai "registration-method sn <SN_BARU>". Begitu device fisik baru online dengan SN itu,
// otomatis kepakein config gpon-onu yang lama.
app.patch('/api/snmp/onu-replace', requireAuth, async (req, res) => {
  const { oltName, slot, port, onuId, oldSn, newSn } = req.body;

  if (!oltName || slot === undefined || slot === null || port === undefined || port === null ||
      onuId === undefined || onuId === null || !newSn) {
    return res.status(400).json({ success: false, message: 'Field wajib: oltName, slot, port, onuId, newSn' });
  }

  const slotNum = Number(slot), portNum = Number(port), onuIdNum = Number(onuId);
  if (!Number.isInteger(slotNum) || !Number.isInteger(portNum) || !Number.isInteger(onuIdNum)) {
    return res.status(400).json({ success: false, message: 'slot/port/onuId harus berupa angka' });
  }

  const sn = String(newSn).trim().toUpperCase();
  // Format umum SN ONU GPON: 4 huruf vendor id + 8 karakter hex, tapi dilonggarkan
  // supaya tetap menerima varian vendor lain — yang penting bukan whitespace/karakter aneh
  // yang bisa dipakai buat nyelipin command CLI tambahan ke sesi Telnet OLT.
  if (!/^[A-Z0-9]{4,32}$/.test(sn)) {
    return res.status(400).json({ success: false, message: 'Format SN baru tidak valid (huruf/angka saja, 4-32 karakter, tanpa spasi)' });
  }
  if (oldSn && sn === String(oldSn).trim().toUpperCase()) {
    return res.status(400).json({ success: false, message: 'SN baru sama dengan SN lama' });
  }

  const oltCfg = OLT_CONFIG[oltName];
  if (!oltCfg) {
    return res.status(404).json({ success: false, message: `OLT "${oltName}" tidak ditemukan` });
  }

  const onuIface = `gpon-onu_1/${slotNum}/${portNum}:${onuIdNum}`;
  const commands = [
    `conf t`,
    `interface ${onuIface}`,
    `registration-method sn ${sn}`,
    `end`,
    `write`,
  ];
  const log = [];

  try {
    log.push(`[INFO] Connecting to ${oltCfg.host}:${oltCfg.port || 23} via Telnet...`);
    await telnetExec(oltCfg, commands, log);

    // Kalau OLT nolak command intinya, telnetExec cuma nyatet [WARN] tanpa nge-throw —
    // deteksi manual di sini biar user tetap tahu gagal.
    const coreFailed = log.some(l => l.startsWith('[WARN]') && l.includes('registration-method sn'));
    if (coreFailed) {
      return res.status(500).json({
        success: false,
        message: `OLT menolak perintah ganti SN untuk ${onuIface}. Cek log untuk detail.`,
        log: log.join('\n'),
      });
    }

    log.push(`[OK]   SN ONU ${onuIface} berhasil diganti menjadi "${sn}"`);

    // Update cache lokal langsung supaya Monitor ONU konsisten sebelum poll berikutnya (tiap 2 menit)
    try {
      db.prepare(`
        UPDATE onu_cache SET serial_number = ?, updated_at = datetime('now','localtime')
        WHERE olt_name = ? AND slot = ? AND port = ? AND onu_id = ?
      `).run(sn, oltName, slotNum, portNum, onuIdNum);
    } catch (cacheErr) {
      log.push(`[WARN] Gagal update cache lokal: ${cacheErr.message}`);
    }

    res.json({ success: true, serialNumber: sn, log: log.join('\n') });
  } catch (err) {
    log.push(`[FAIL] Telnet Error: ${err.message}`);
    res.status(500).json({ success: false, message: err.message, log: log.join('\n') });
  }
});

// --- API: SNMP — HAPUS ONU (dipakai tombol "Hapus ONU" di Monitor ONU) ---
// Menghapus registrasi ONU dari OLT: masuk ke interface gpon-olt_1/slot/port (interface
// PON fisik), lalu "no onu <onuId>" — ini otomatis membuang seluruh config yang menempel
// di interface gpon-onu_1/slot/port:onuId (name, tcont, gemport, service-port, pon-onu-mng,
// wan-ip pppoe, dst), jadi tidak perlu unconfigure tiap bagian satu-satu. Dipakai kalau
// pelanggan berhenti berlangganan / ONU dicabut permanen dari ODP.
app.delete('/api/snmp/onu-delete', requireAuth, async (req, res) => {
  const { oltName, slot, port, onuId } = req.body;

  if (!oltName || slot === undefined || slot === null || port === undefined || port === null ||
      onuId === undefined || onuId === null) {
    return res.status(400).json({ success: false, message: 'Field wajib: oltName, slot, port, onuId' });
  }

  const slotNum = Number(slot), portNum = Number(port), onuIdNum = Number(onuId);
  if (!Number.isInteger(slotNum) || !Number.isInteger(portNum) || !Number.isInteger(onuIdNum)) {
    return res.status(400).json({ success: false, message: 'slot/port/onuId harus berupa angka' });
  }

  const oltCfg = OLT_CONFIG[oltName];
  if (!oltCfg) {
    return res.status(404).json({ success: false, message: `OLT "${oltName}" tidak ditemukan` });
  }

  const oltIface = `gpon-olt_1/${slotNum}/${portNum}`;
  const onuIface = `gpon-onu_1/${slotNum}/${portNum}:${onuIdNum}`;
  const commands = [
    `conf t`,
    `interface ${oltIface}`,
    `no onu ${onuIdNum}`,
    `end`,
    `write`,
  ];
  const log = [];

  try {
    log.push(`[INFO] Connecting to ${oltCfg.host}:${oltCfg.port || 23} via Telnet...`);
    await telnetExec(oltCfg, commands, log);

    // Kalau OLT nolak command intinya, telnetExec cuma nyatet [WARN] tanpa nge-throw —
    // deteksi manual di sini biar user tetap tahu gagal.
    const coreFailed = log.some(l => l.startsWith('[WARN]') && l.includes(`no onu ${onuIdNum}`));
    if (coreFailed) {
      return res.status(500).json({
        success: false,
        message: `OLT menolak perintah hapus ONU ${onuIface}. Cek log untuk detail.`,
        log: log.join('\n'),
      });
    }

    log.push(`[OK]   ONU ${onuIface} berhasil dihapus dari ${oltIface}`);

    // Hapus baris cache lokal langsung supaya Monitor ONU konsisten sebelum poll berikutnya (tiap 2 menit)
    try {
      db.prepare(`
        DELETE FROM onu_cache WHERE olt_name = ? AND slot = ? AND port = ? AND onu_id = ?
      `).run(oltName, slotNum, portNum, onuIdNum);
    } catch (cacheErr) {
      log.push(`[WARN] Gagal hapus cache lokal: ${cacheErr.message}`);
    }

    res.json({ success: true, log: log.join('\n') });
  } catch (err) {
    log.push(`[FAIL] Telnet Error: ${err.message}`);
    res.status(500).json({ success: false, message: err.message, log: log.join('\n') });
  }
});

// --- API: SNMP � TRAFFIC COUNTER (single ONU) ---
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
    const upOct   = (!snmp.isVarbindError(vbs[0])) ? snmpValueToNumber(vbs[0].value) : null;
    const downOct = (!snmp.isVarbindError(vbs[1])) ? snmpValueToNumber(vbs[1].value) : null;

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

// --- API: BACA CACHE ONU (cepat, dari DB) ---
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

// --- API: STATUS POLLER ---
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

// --- API: TRIGGER POLL MANUAL ---
app.post('/api/poll-now', requireAuth, async (req, res) => {
  const { oltName } = req.body;
  res.json({ success: true, message: 'Polling dimulai di background' });
  if (oltName && OLT_CONFIG[oltName]) {
    pollOlt(oltName, OLT_CONFIG[oltName], true).catch(e => console.error('[POLLER]', oltName, e.message));
  } else {
    pollAllOlts();
  }
});

// -------------------------------------------------------
// --- BACKGROUND POLLER ---
// -------------------------------------------------------

const POLL_INTERVAL_MS = 60 * 1000; // 60 detik (30 dtk terlalu agresif untuk agent SNMP ZTE C300)
// Data yang jarang berubah (nama, serial, rx power, last online/offline, kesehatan card)
// hanya di-walk tiap SLOW_EVERY siklus. Status online/offline di-walk SETIAP siklus.
const SLOW_EVERY = 5;
const SNMP_WALK_GAP_MS = 500; // jeda antar walk ke OLT yang sama
const oltPollCount = new Map(); // oltName -> jumlah siklus sukses
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let nextPollTime = Date.now() + POLL_INTERVAL_MS;
let pollingInProgress = false; // guard supaya poll berikutnya tidak tumpang tindih kalau poll sebelumnya belum selesai

// --- TELEGRAM NOTIFIKASI ---
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

  // -- Deteksi ONU LOS baru (belum pernah dinotifikasi) --
  const newLos = losOnus.filter(o => {
    const key = `${oltName}|${o.suffix}`;
    return !_losNotified.has(key);
  });

  // Tandai semua ONU LOS saat ini sebagai sudah dinotifikasi
  const currentLosKeys = new Set(losOnus.map(o => `${oltName}|${o.suffix}`));

  // -- Deteksi ONU yang kembali UP (sebelumnya LOS, sekarang online) --
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

  // -- Kirim notifikasi ONU LOS baru --
  newLos.forEach(o => {
    const iface  = `1/${o.slot}/${o.port}:${o.onuId}`;
    const nama   = o.name || '�';
    const sn     = o.serialNumber || '�';
    const rx     = (o.rxPower !== null && o.rxPower !== undefined) ? `${o.rxPower} dBm` : 'N/A';

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

  // -- Kirim notifikasi ONU kembali UP --
  recoveredOnus.forEach(o => {
    const iface  = `1/${o.slot}/${o.port}:${o.onuId}`;
    const nama   = o.name || '�';
    const sn     = o.serialNumber || '�';
    const rx     = (o.rxPower !== null && o.rxPower !== undefined) ? `${o.rxPower} dBm` : '�';

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

// --- API: TEST TELEGRAM ---
app.post('/api/telegram/test', requireAuth, async (req, res) => {
  if (!TELEGRAM_ENABLED) {
    return res.json({ success: false, message: 'TELEGRAM_BOT_TOKEN atau TELEGRAM_CHAT_ID belum diset di environment variable' });
  }
  try {
    await sendTelegram('? <b>Test Notifikasi</b>\n\nKoneksi Telegram berhasil! Notifikasi ONU LOS aktif.');
    res.json({ success: true, message: 'Pesan test berhasil dikirim ke group Telegram' });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Simpan hasil SNMP ke DB
function saveOnuCache(oltName, onus) {
   // Hapus ONU yang sudah tidak ada di OLT (reconcile)
  if (onus.length > 0) {
    const suffixes = onus.map(o => o.suffix);
    const placeholders = suffixes.map(() => '?').join(',');
    db.prepare(`
      DELETE FROM onu_cache 
      WHERE olt_name = ? AND suffix NOT IN (${placeholders})
    `).run(oltName, ...suffixes);
  }
  
  
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
async function snmpFetchOnus(oltName, oltCfg, forceSlow = false) {
  const host = oltCfg.host;
  const result = { onus: [], sysUptime: null };

  // sysUptime (optional)
  try {
    const uptimeVbs = await snmpGet(host, [OID.sysUpTime]);
    if (uptimeVbs[0] && !snmp.isVarbindError(uptimeVbs[0])) {
      result.sysUptime = uptime100thToStr(uptimeVbs[0].value);
    }
  } catch(e) {}

  // Cache lama: dipakai untuk field "lambat" yang tidak di-walk pada siklus ini
  const cacheRows = db.prepare('SELECT * FROM onu_cache WHERE olt_name = ?').all(oltName);
  const cacheMap = {};
  cacheRows.forEach(r => { cacheMap[r.suffix] = r; });

  const cycle = oltPollCount.get(oltName) || 0;
  const slow = forceSlow || cacheRows.length === 0 || cycle % SLOW_EVERY === 0;
  result.slow = slow;

  // 1) Status ONU: WAJIB, tiap siklus. Kalau gagal/kosong -> lempar error,
  //    sehingga cache lama TIDAK ditimpa dan poll_log mencatat success = 0.
  const statusRows = await timedSubtree(oltName, host, OID.onuOperStatus, 'onuOperStatus');
  if (!statusRows.length) throw new Error('onuOperStatus kosong/timeout, data lama dipertahankan');

  // 2) Data lambat: SERIAL (satu per satu), hanya saat siklus "slow".
  //    null = tidak diambil/gagal -> pakai nilai dari cache.
  // Daftar portIndex unik dari hasil walk status (bagian pertama suffix)
  const portIdxList = [...new Set(
    statusRows.map(r => r.oid.replace(OID.onuOperStatus + '.', '').split('.')[0])
  )];
  const onlineSuffixes = statusRows
    .filter(r => Number(r.value) === 3)
    .map(r => r.oid.replace(OID.onuOperStatus + '.', ''));
  const walkOptional = async (key) => {
    await sleep(SNMP_WALK_GAP_MS);
    try {
      if (/C300/.test(oltName) && key === 'onuRxPower') {
        return await getByOnu(oltName, host, OID[key], key, onlineSuffixes);
      }
      if (/C300/.test(oltName) && C300_BY_PORT.includes(key)) {
        return await walkByPort(oltName, host, OID[key], key, portIdxList, onlineSuffixes);
      }
      return await timedSubtree(oltName, host, OID[key], key);
    } catch (e) { return null; }
  };
  let nameRows = null, rxRows = null, snRows = null, loRows = null, lofRows = null;
  if (slow) {
    nameRows = await walkOptional('onuName');
    rxRows   = await walkOptional('onuRxPower');
    snRows   = await walkOptional('onuSerial');
    loRows   = await walkOptional('onuLastOnline');
    lofRows  = await walkOptional('onuLastOffline');
    if (nameRows && !nameRows.length) nameRows = null;
  }
  // C300: redaman diambil bertahap (rotasi) di SETIAP siklus, bukan hanya siklus slow
  if (!slow && /C300/.test(oltName)) {
    rxRows = await walkOptional('onuRxPower');
  }

  const statusMap = {};
  statusRows.forEach(r => {
    const suffix = r.oid.replace(OID.onuOperStatus + '.', '');
    statusMap[suffix] = Number(r.value);
  });

  const rxMap = {};
  (rxRows || []).forEach(r => {
    const full = r.oid.replace(OID.onuRxPower + '.', '');
    rxMap[full.replace(/\.1$/, '')] = r.value;
  });

  const snMapLocal = {};
  (snRows || []).forEach(r => {
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
  (loRows || []).forEach(r => {
    const suffix = r.oid.replace(OID.onuLastOnline + '.', '');
    lastOnlineMap[suffix] = r.value ? r.value.toString() : null;
  });

  const lastOfflineMap = {};
  (lofRows || []).forEach(r => {
    const suffix = r.oid.replace(OID.onuLastOffline + '.', '');
    lastOfflineMap[suffix] = r.value ? r.value.toString() : null;
  });

  const phaseMap = {
    1: { label: 'LOS',        color: 'err',  online: false },
    3: { label: 'ONLINE',     color: 'ok',   online: true  },
    4: { label: 'DYING GASP', color: 'err',  online: false },
    6: { label: 'OFFLINE',    color: 'err',  online: false },
  };

  // Daftar dasar ONU: dari walk nama kalau ada, kalau tidak dari status + nama di cache
  const baseList = nameRows
    ? nameRows.map(row => ({
        suffix: row.oid.replace(OID.onuName + '.', ''),
        name: row.value ? row.value.toString() : '',
      }))
    : statusRows.map(r => {
        const suffix = r.oid.replace(OID.onuOperStatus + '.', '');
        return { suffix, name: (cacheMap[suffix] && cacheMap[suffix].name) || '' };
      });
  if (!baseList.length) throw new Error('Tidak ada data ONU dari SNMP');

  baseList.forEach(({ suffix, name }) => {
    const parts = suffix.split('.');
    if (parts.length < 2) return;
    const c = cacheMap[suffix] || {};
    const { slot, port, onuId } = parseOnuIndex(parts[0], parts[1]);
    const statusCode = statusMap[suffix] !== undefined ? statusMap[suffix] : -1;
    const st = phaseMap[statusCode] || { label: `CODE ${statusCode}`, color: 'muted', online: false };

    // Field lambat: nilai baru kalau berhasil di-walk, kalau tidak pakai cache
    // 65535 = "tidak ada data" dari agent -> rxPowerToDbm menghasilkan null.
    // Untuk ONU online, nilai valid terakhir dari cache dipertahankan.
    const rxNew = rxRows ? rxPowerToDbm(rxMap[suffix] !== undefined ? rxMap[suffix] : null) : null;
    const rxPower = rxRows
      ? (rxNew !== null ? rxNew : (st.online && c.rx_power != null ? c.rx_power : null))
      : (c.rx_power !== undefined ? c.rx_power : null);
    const serialNumber = snRows ? (snMapLocal[suffix] || c.serial_number || '—') : (c.serial_number || '—');
    const lastOnline  = loRows  ? (lastOnlineMap[suffix]  || null) : (c.last_online  || null);
    const lastOffline = lofRows ? (lastOfflineMap[suffix] || null) : (c.last_offline || null);

    result.onus.push({
      suffix,
      slot, port, onuId,
      name,
      serialNumber,
      lastOnline,
      lastOffline,
      statusCode,
      statusLabel:  st.label,
      statusColor:  st.color,
      rxPower,
      online:       st.online,
    });
  });

  oltPollCount.set(oltName, cycle + 1);

  result.onus.sort((a, b) => (a.slot - b.slot) || (a.port - b.port) || (a.onuId - b.onuId));
  return result;
}

// --- Fetch kesehatan chassis (CPU/RAM per card/slot) ---
// Best-effort: kalau OID ini tidak didukung firmware tertentu, kembalikan array kosong
// tanpa melempar error (supaya tidak mengganggu polling ONU yang jadi fungsi utama).
async function snmpFetchCardHealth(oltName, host) {
  const walkCard = async (key) => {
    await sleep(SNMP_WALK_GAP_MS);
    try { return await timedSubtree(oltName, host, OID[key], key); } catch (e) { return []; }
  };
  const typeRows   = await walkCard('cardType');
  const statusRows = await walkCard('cardOperStatus');
  const cpuRows    = await walkCard('cardCpuLoad');
  const memRows    = await walkCard('cardMemUsage');

  if (!cpuRows.length && !memRows.length && !typeRows.length) return [];

  const typeMap = {};
  typeRows.forEach(r => {
    const idx = r.oid.replace(OID.cardType + '.', '');
    typeMap[idx] = Buffer.isBuffer(r.value) ? r.value.toString('ascii').replace(/[^\x20-\x7E]/g, '') : (r.value ? r.value.toString() : '');
  });
  const statusMap = {};
  statusRows.forEach(r => {
    const idx = r.oid.replace(OID.cardOperStatus + '.', '');
    statusMap[idx] = Number(r.value);
  });
  const cpuMap = {};
  cpuRows.forEach(r => {
    const idx = r.oid.replace(OID.cardCpuLoad + '.', '');
    cpuMap[idx] = Number(r.value);
  });
  const memMap = {};
  memRows.forEach(r => {
    const idx = r.oid.replace(OID.cardMemUsage + '.', '');
    memMap[idx] = Number(r.value);
  });

  // Gabungkan semua index yang pernah muncul di salah satu OID
  const allIdx = new Set([...Object.keys(typeMap), ...Object.keys(statusMap), ...Object.keys(cpuMap), ...Object.keys(memMap)]);

  const cards = [...allIdx].map(idx => {
    const parts = idx.split('.');
    const slotNum = parts.length ? parseInt(parts[parts.length - 1]) : null;
    return {
      slotIndex: idx,
      slotNum: isNaN(slotNum) ? null : slotNum,
      cardType: typeMap[idx] || '',
      operStatus: statusMap[idx] !== undefined ? statusMap[idx] : null,
      cpuLoad: cpuMap[idx] !== undefined && !isNaN(cpuMap[idx]) ? cpuMap[idx] : null,
      memUsage: memMap[idx] !== undefined && !isNaN(memMap[idx]) ? memMap[idx] : null,
    };
  }).filter(c => c.cpuLoad !== null || c.memUsage !== null); // buang baris kosong total

  cards.sort((a, b) => (a.slotNum ?? 0) - (b.slotNum ?? 0));
  return cards;
}

function saveOltHealth(oltName, cards, sysUptime) {
  if (cards.length > 0) {
    const idxs = cards.map(c => c.slotIndex);
    const placeholders = idxs.map(() => '?').join(',');
    db.prepare(`
      DELETE FROM olt_health
      WHERE olt_name = ? AND slot_index NOT IN (${placeholders})
    `).run(oltName, ...idxs);

    const upsert = db.prepare(`
      INSERT INTO olt_health (olt_name, slot_index, card_type, oper_status, cpu_load, mem_usage, updated_at)
      VALUES (@olt_name, @slot_index, @card_type, @oper_status, @cpu_load, @mem_usage, @updated_at)
      ON CONFLICT(olt_name, slot_index) DO UPDATE SET
        card_type   = excluded.card_type,
        oper_status = excluded.oper_status,
        cpu_load    = excluded.cpu_load,
        mem_usage   = excluded.mem_usage,
        updated_at  = excluded.updated_at
    `);
    const nowLocal = new Date().toLocaleString('sv-SE', { timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone }).replace('T', ' ');
    const insertMany = db.transaction((items) => { for (const c of items) upsert.run(c); });
    insertMany(cards.map(c => ({
      olt_name: oltName,
      slot_index: c.slotIndex,
      card_type: c.cardType,
      oper_status: c.operStatus,
      cpu_load: c.cpuLoad,
      mem_usage: c.memUsage,
      updated_at: nowLocal,
    })));
  }

  if (sysUptime !== null && sysUptime !== undefined) {
    db.prepare(`
      INSERT INTO olt_sys_info (olt_name, sys_uptime, updated_at)
      VALUES (?, ?, datetime('now','localtime'))
      ON CONFLICT(olt_name) DO UPDATE SET sys_uptime = excluded.sys_uptime, updated_at = excluded.updated_at
    `).run(oltName, sysUptime);
  }
}

// --- API: kesehatan semua OLT (CPU/RAM per slot + uptime), buat kartu ringkasan dashboard ---
app.get('/api/olt-health', requireAuth, (req, res) => {
  try {
    const healthRows = db.prepare('SELECT * FROM olt_health ORDER BY olt_name, slot_index').all();
    const sysRows = db.prepare('SELECT * FROM olt_sys_info').all();
    const sysMap = {};
    sysRows.forEach(r => { sysMap[r.olt_name] = r; });

    const byOlt = {};
    healthRows.forEach(r => {
      if (!byOlt[r.olt_name]) byOlt[r.olt_name] = [];
      byOlt[r.olt_name].push({
        slotIndex: r.slot_index,
        cardType: r.card_type,
        operStatus: r.oper_status,
        cpuLoad: r.cpu_load,
        memUsage: r.mem_usage,
        updatedAt: r.updated_at,
      });
    });

    const oltNames = new Set([...Object.keys(byOlt), ...Object.keys(sysMap)]);
    const result = [...oltNames].map(name => ({
      oltName: name,
      sysUptime: sysMap[name]?.sys_uptime || null,
      updatedAt: sysMap[name]?.updated_at || null,
      cards: byOlt[name] || [],
    }));

    res.json({ success: true, data: result });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Poll satu OLT ? simpan ke DB
async function pollOlt(oltName, oltCfg, forceSlow = false) {
  const t0 = Date.now();
  console.log(`[POLLER] Polling ${oltName} (${oltCfg.host})...`);
  try {
    const data = await snmpFetchOnus(oltName, oltCfg, forceSlow);
    saveOnuCache(oltName, data.onus);
    checkAndNotifyLos(oltName, data.onus);

    // Kesehatan chassis (CPU/RAM/uptime) — best-effort, jangan sampai gagalnya
    // OID ini menghentikan polling ONU yang jadi fungsi utama.
    try {
      if (data.slow) {
        const cards = await snmpFetchCardHealth(oltName, oltCfg.host);
        saveOltHealth(oltName, cards, data.sysUptime);
      }
    } catch (healthErr) {
      console.log(`[POLLER][HEALTH] ${oltName}: gagal ambil CPU/RAM — ${healthErr.message}`);
    }

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
// Deduplikasi berdasarkan host:port agar OLT dengan IP sama tidak di-poll ganda
async function pollAllOlts() {
  if (pollingInProgress) {
    console.log('[POLLER] Skip: polling sebelumnya masih berjalan (belum selesai)');
    return;
  }
  pollingInProgress = true;
  const tStart = Date.now();

  try {

  const entries = Object.entries(OLT_CONFIG);
  console.log(`[POLLER] Mulai polling ${entries.length} OLT...`);

  // Deduplikasi: kelompokkan OLT berdasarkan host:port
  // Jika ada dua OLT dengan host:port sama, hanya poll satu kali
  const seenHosts = new Map(); // key: "host:port" ? name OLT pertama yang akan dipoll
  const pollEntries = [];      // entries yang benar-benar akan dipoll
  const skipEntries = [];      // entries yang diskip karena IP duplikat

  for (const [name, cfg] of entries) {
    const hostKey = `${cfg.host}:${cfg.port || 23}`;
    if (!seenHosts.has(hostKey)) {
      seenHosts.set(hostKey, name);
      pollEntries.push([name, cfg]);
    } else {
      skipEntries.push({ name, duplicateOf: seenHosts.get(hostKey) });
      console.log(`[POLLER] Skip ${name} � IP sama dengan ${seenHosts.get(hostKey)} (${cfg.host})`);
    }
  }

  await Promise.allSettled(pollEntries.map(([name, cfg]) => pollOlt(name, cfg)));

  // Salin data cache dari OLT yang dipoll ke OLT yang diskip (IP sama)
  for (const { name, duplicateOf } of skipEntries) {
    try {
      const sourceRows = db.prepare(
        'SELECT * FROM onu_cache WHERE olt_name = ?'
      ).all(duplicateOf);

      if (sourceRows.length > 0) {
        const nowLocal = new Date()
          .toLocaleString('sv-SE', { timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone })
          .replace('T', ' ');

        // Hapus cache lama untuk OLT yang diskip
        db.prepare('DELETE FROM onu_cache WHERE olt_name = ?').run(name);

        // Salin dari source, ganti olt_name
        const upsert = db.prepare(`
          INSERT INTO onu_cache
            (olt_name, suffix, slot, port, onu_id, name, serial_number,
             status_code, status_label, status_color, rx_power, online,
             last_online, last_offline, updated_at)
          VALUES
            (@olt_name, @suffix, @slot, @port, @onu_id, @name, @serial_number,
             @status_code, @status_label, @status_color, @rx_power, @online,
             @last_online, @last_offline, @updated_at)
        `);

        const insertMany = db.transaction((rows) => {
          for (const row of rows) {
            upsert.run({
              olt_name:      name,
              suffix:        row.suffix,
              slot:          row.slot,
              port:          row.port,
              onu_id:        row.onu_id,
              name:          row.name,
              serial_number: row.serial_number,
              status_code:   row.status_code,
              status_label:  row.status_label,
              status_color:  row.status_color,
              rx_power:      row.rx_power,
              online:        row.online,
              last_online:   row.last_online,
              last_offline:  row.last_offline,
              updated_at:    nowLocal,
            });
          }
        });
        insertMany(sourceRows);
        console.log(`[POLLER] Cache ${name} disalin dari ${duplicateOf} (${sourceRows.length} ONU)`);
      }
    } catch (e) {
      console.error(`[POLLER] Gagal salin cache ke ${name}: ${e.message}`);
    }
  }

  const durationTotal = Date.now() - tStart;
  console.log(`[POLLER] Semua OLT selesai dipoll dalam ${durationTotal}ms`);

  } catch (e) {
    console.error(`[POLLER] pollAllOlts error: ${e.message}`);
  } finally {
    pollingInProgress = false;
    nextPollTime = Date.now() + POLL_INTERVAL_MS;
    console.log(`[POLLER] Poll berikutnya: ${new Date(nextPollTime).toLocaleTimeString('id-ID')}`);

    // Jadwalkan poll berikutnya SETELAH poll saat ini benar-benar selesai
    // (bukan setInterval tetap) supaya tidak overlap kalau durasi polling
    // pernah lebih lama dari POLL_INTERVAL_MS.
    setTimeout(pollAllOlts, POLL_INTERVAL_MS);
  }
}

// Jalankan poller pertama kali saat server start (delay 3 detik)
setTimeout(pollAllOlts, 3000);

// --- CLEANUP OTOMATIS poll_log (simpan 3 hari terakhir) ---
const POLL_LOG_RETENTION_DAYS = 3;
const CLEANUP_INTERVAL_MS = 24 * 60 * 60 * 1000; // jalankan tiap 24 jam

function cleanupPollLog() {
  try {
    const result = db.prepare(`
      DELETE FROM poll_log
      WHERE polled_at < datetime('now', '-${POLL_LOG_RETENTION_DAYS} days', 'localtime')
    `).run();
    console.log(`[CLEANUP] poll_log: ${result.changes} baris lama dihapus (retensi ${POLL_LOG_RETENTION_DAYS} hari)`);
  } catch (err) {
    console.error('[CLEANUP] Gagal cleanup poll_log:', err.message);
  }
}

// Jalankan pertama kali saat server start (delay 10 detik)
setTimeout(cleanupPollLog, 10000);

// Ulangi tiap 24 jam
setInterval(cleanupPollLog, CLEANUP_INTERVAL_MS);

// --------------------------------------------------------------
// --- MIKROTIK INTEGRATION (port 8728 binary API) ---
// --------------------------------------------------------------

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

// --- ADMIN: Daftar Mikrotik ---
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

// --- TEST KONEKSI ---
app.post('/api/mikrotik/test', requireAuth, async (req, res) => {
  const { mikrotikName } = req.body;
  const cfg = getMikrotikCfg(mikrotikName);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    const info = await mikrotikQuery(cfg, '/system/identity/print');
    const name = info[0]?.name || '�';
    res.json({ success: true, message: `Koneksi berhasil! Identity: ${name}` });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// --- PPPOE: LIST SECRETS ---
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

// --- PPPOE: TAMBAH SECRET ---
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

// --- PPPOE: EDIT SECRET ---
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

// --- PPPOE: HAPUS SECRET ---
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

// --- PPPOE: ACTIVE SESSIONS ---
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

// --- PPPOE: DISCONNECT SESI ---
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

// --- PPP PROFILES ---
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

// --- SYSTEM RESOURCE ---
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


// --- DEBUG: raw print secrets (sementara untuk troubleshoot) ---
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

// --- PPPOE: DEBUG ACTIVE (inspect field yang tersedia) ---
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

// --- DEBUG: cek interface PPPoE yang tersedia ---
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

// --- PPPOE: ACTIVE + TRAFFIC (gabungkan /ppp/active + /interface) ---
app.get('/api/mikrotik/:name/pppoe/active-traffic', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    // Ambil session aktif dan interface list secara paralel
    // '=stats' wajib disertakan supaya rx-byte/tx-byte ikut terkirim oleh RouterOS
    const [activeSessions, allInterfaces] = await Promise.all([
      mikrotikQuery(cfg, '/ppp/active/print'),
      mikrotikQuery(cfg, '/interface/print', ['=stats']),
    ]);

    // Buat map interface PPPoE by username
    // RouterOS format nama: "<pppoe-USERNAME@DOMAIN>" ? strip jadi "USERNAME@DOMAIN"
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

// --- PPPOE: ACTIVE + BPS real-time (2 snapshot, selisih dibagi interval) ---
app.get('/api/mikrotik/:name/pppoe/active-bps', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });

  try {
    // Snapshot 1
    // '=stats' wajib disertakan supaya rx-byte/tx-byte ikut terkirim oleh RouterOS
    const [snap1Sessions, snap1Ifaces] = await Promise.all([
      mikrotikQuery(cfg, '/ppp/active/print'),
      mikrotikQuery(cfg, '/interface/print', ['=stats']),
    ]);

    // Tunggu 2 detik
    await new Promise(r => setTimeout(r, 2000));

    // Snapshot 2 (interface saja, session tidak berubah signifikan dalam 2 detik)
    const snap2Ifaces = await mikrotikQuery(cfg, '/interface/print', ['=stats']);

    // Helper: strip format "<pppoe-USERNAME>" ? "USERNAME"
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

// --- PPPOE: TRAFFIC PER SESSION (untuk modal detail) ---
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
    // '=stats' wajib disertakan supaya rx-byte/tx-byte ikut terkirim oleh RouterOS
    const [activeSessions, allInterfaces] = await Promise.all([
      mikrotikQuery(cfg, '/ppp/active/print'),
      mikrotikQuery(cfg, '/interface/print', ['=stats']),
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
      interface: matchedIface?.name ?? '�',
      running:   matchedIface?.running ?? null,
    });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// --- INTERFACE: DAFTAR INTERFACE (untuk widget Live Bandwidth di Dashboard) ---
app.get('/api/mikrotik/:name/interfaces', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });
  try {
    const raw = await mikrotikQuery(cfg, '/interface/print');
    const interfaces = (raw || []).map(i => ({
      name:     i.name,
      type:     i.type,
      running:  i.running === true || i.running === 'true',
      disabled: i.disabled === true || i.disabled === 'true',
    }));
    res.json({ success: true, interfaces });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// --- INTERFACE: TRAFFIC (rx/tx byte counter, untuk widget Live Bandwidth di Dashboard) ---
app.get('/api/mikrotik/:name/interface/traffic', requireAuth, async (req, res) => {
  const cfg = getMikrotikCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Mikrotik tidak ditemukan' });

  const { interface: ifaceName } = req.query;
  if (!ifaceName) {
    return res.status(400).json({ success: false, message: 'Parameter interface wajib diisi' });
  }

  try {
    // '=stats' wajib disertakan, karena RouterOS API tidak mengirim rx-byte/tx-byte
    // di /interface/print kalau tidak diminta secara eksplisit.
    const allInterfaces = await mikrotikQuery(cfg, '/interface/print', ['=stats']);
    const matched = (allInterfaces || []).find(i => i.name === ifaceName);

    if (!matched) {
      return res.status(404).json({ success: false, message: `Interface "${ifaceName}" tidak ditemukan` });
    }

    res.json({
      success:   true,
      interface: matched.name,
      rxBytes:   Number(matched['rx-byte'] || 0),
      txBytes:   Number(matched['tx-byte'] || 0),
      running:   matched.running === true || matched.running === 'true',
    });
  } catch(e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// --- API: POLL LOG (untuk halaman admin) ---
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

// --- API: DB STATS (untuk halaman admin) ---
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

// --- API: CLEAR ONU CACHE (untuk halaman admin) ---
app.delete('/api/onu-cache/clear', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM onu_cache').run();
    db.prepare('DELETE FROM poll_log').run();
    res.json({ success: true, message: 'Cache ONU dan poll log berhasil dihapus' });
  } catch(err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ============================================================
// PATCH: Tambahkan kode ini ke server.js NOCS (port 3000)
// Letakkan SEBELUM baris: const PORT = process.env.PORT || 3000;
// ============================================================

// --- NETBACKUP PROXY CONFIG ---
const NETBACKUP_URL = process.env.NETBACKUP_URL || 'http://localhost:4001';

// Helper: forward request ke NetBackup
async function nbFetch(path, options = {}) {
  const url = NETBACKUP_URL + path;
  const fetchOptions = {
    method: options.method || 'GET',
    headers: { 'Content-Type': 'application/json' },
  };
  if (options.body) {
    fetchOptions.body = JSON.stringify(options.body);
  }
  const r = await fetch(url, fetchOptions);
  const body = await r.json();
  return { status: r.status, body };
}

// --- API: NETBACKUP PROXY � GET semua perangkat ---
app.get('/api/netbackup/devices', requireAuth, async (req, res) => {
  try {
    const r = await nbFetch('/api/devices');
    res.status(r.status).json(r.body);
  } catch(e) {
    res.status(503).json({ success: false, message: 'NetBackup tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: NETBACKUP PROXY � Tambah perangkat ---
app.post('/api/netbackup/devices', requireAuth, async (req, res) => {
  try {
    const r = await nbFetch('/api/devices', { method: 'POST', body: req.body });
    res.status(r.status).json(r.body);
  } catch(e) {
    res.status(503).json({ success: false, message: 'NetBackup tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: NETBACKUP PROXY � Edit perangkat ---
app.put('/api/netbackup/devices/:id', requireAuth, async (req, res) => {
  try {
    const r = await nbFetch('/api/devices/' + req.params.id, { method: 'PUT', body: req.body });
    res.status(r.status).json(r.body);
  } catch(e) {
    res.status(503).json({ success: false, message: 'NetBackup tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: NETBACKUP PROXY � Hapus perangkat ---
app.delete('/api/netbackup/devices/:id', requireAuth, async (req, res) => {
  try {
    const r = await nbFetch('/api/devices/' + req.params.id, { method: 'DELETE' });
    res.status(r.status).json(r.body);
  } catch(e) {
    res.status(503).json({ success: false, message: 'NetBackup tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: NETBACKUP PROXY � Trigger backup manual ---
app.post('/api/netbackup/backup/:id', requireAuth, async (req, res) => {
  try {
    const r = await nbFetch('/api/backup/' + req.params.id, { method: 'POST' });
    res.status(r.status).json(r.body);
  } catch(e) {
    res.status(503).json({ success: false, message: 'NetBackup tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: NETBACKUP PROXY � Stats dashboard ---
app.get('/api/netbackup/stats', requireAuth, async (req, res) => {
  try {
    const r = await nbFetch('/api/stats');
    res.status(r.status).json(r.body);
  } catch(e) {
    res.status(503).json({ success: false, message: 'NetBackup tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: NETBACKUP PROXY � Log backup ---
app.get('/api/netbackup/logs', requireAuth, async (req, res) => {
  try {
    const r = await nbFetch('/api/logs');
    res.status(r.status).json(r.body);
  } catch(e) {
    res.status(503).json({ success: false, message: 'NetBackup tidak dapat dijangkau: ' + e.message });
  }
});
// ============================================================
// END PATCH server.js
// ============================================================

// ============================================================
// PATCH: FFmpeg Agent Proxy (VPS terpisah)
// ============================================================

// --- FFMPEG AGENT PROXY CONFIG (multi-VPS) ---
// Daftar VPS FFmpeg ditulis LANGSUNG di sini (tidak pakai .env).
// Tambah/kurangi VPS tinggal edit array di bawah ini, lalu restart server.
// - id    : bebas, dipakai internal saja (jangan sama antar VPS)
// - label : nama yang tampil di dropdown dashboard
// - url   : alamat ffmpeg-agent.js di VPS tsb (termasuk port, default 4002)
// - key   : HARUS SAMA PERSIS dengan AGENT_KEY di .env agent VPS tsb
let FFMPEG_AGENTS = [
  {
    id: 'streaming1',
    label: 'Server Streaming 1',
    url: 'http://192.168.11.26:4002',
    key: 'e6d8325faabc1693390628ea61619ab544749bea543b136290818055ce01ce44',
  },
  {
    id: 'streaming2',
    label: 'Server Streaming 2',
    url: 'http://192.168.11.28:4002',
    key: '578b0a6fdc72a4d003979860486623019ca8aeffea7c1ad972b02ad635d04ce4',
  },
  // {
  //   id: 'streaming3',
  //   label: 'Server Streaming 3',
  //   url: 'http://IP_SERVER_3:4002',
  //   key: 'KEY_SERVER_3',
  // },
];
if (FFMPEG_AGENTS.length === 0) {
  console.warn('[FFMPEG_AGENTS] kosong � isi array FFMPEG_AGENTS di server.js agar halaman FFmpeg berfungsi.');
}

function getFfmpegAgent(agentId) {
  return FFMPEG_AGENTS.find(a => a.id === agentId);
}

// Helper: forward request ke FFmpeg Agent tertentu (berdasarkan agentId)
async function ffmpegFetch(agentId, agentPath, options = {}) {
  const agent = getFfmpegAgent(agentId);
  if (!agent) throw new Error(`Agent "${agentId}" tidak ditemukan di konfigurasi FFMPEG_AGENTS`);
  const url = agent.url + agentPath;
  const fetchOptions = {
    method: options.method || 'GET',
    headers: { 'Content-Type': 'application/json', 'X-Agent-Key': agent.key },
  };
  if (options.body) fetchOptions.body = JSON.stringify(options.body);
  const r = await fetch(url, fetchOptions);
  const body = await r.json();
  return { status: r.status, body };
}

// --- API: FFMPEG � daftar VPS/agent yang terkonfigurasi ---
app.get('/api/ffmpeg/agents', requireAuth, (req, res) => {
  res.json({ success: true, agents: FFMPEG_AGENTS.map(a => ({ id: a.id, label: a.label || a.id })) });
});

// --- API: FFMPEG � daftar status semua service (per agent) ---
app.get('/api/ffmpeg/:agentId/services', requireAuth, async (req, res) => {
  try {
    const r = await ffmpegFetch(req.params.agentId, '/services');
    res.status(r.status).json(r.body);
  } catch (e) {
    res.status(503).json({ success: false, message: 'FFmpeg agent tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: FFMPEG � start/stop/restart service (semua role login boleh) ---
app.post('/api/ffmpeg/:agentId/services/:name/:action', requireAuth, async (req, res) => {
  const { agentId, name, action } = req.params;
  if (!['start', 'stop', 'restart'].includes(action)) {
    return res.status(400).json({ success: false, message: 'Aksi tidak dikenal' });
  }
  try {
    const r = await ffmpegFetch(agentId, `/services/${encodeURIComponent(name)}/${action}`, { method: 'POST' });
    res.status(r.status).json(r.body);
  } catch (e) {
    res.status(503).json({ success: false, message: 'FFmpeg agent tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: FFMPEG � log service (untuk debug) ---
app.get('/api/ffmpeg/:agentId/services/:name/log', requireAuth, async (req, res) => {
  try {
    const r = await ffmpegFetch(req.params.agentId, `/services/${encodeURIComponent(req.params.name)}/log`);
    res.status(r.status).json(r.body);
  } catch (e) {
    res.status(503).json({ success: false, message: 'FFmpeg agent tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: FFMPEG � daftar file .sh (per agent) ---
app.get('/api/ffmpeg/:agentId/scripts', requireAuth, async (req, res) => {
  try {
    const r = await ffmpegFetch(req.params.agentId, '/scripts');
    res.status(r.status).json(r.body);
  } catch (e) {
    res.status(503).json({ success: false, message: 'FFmpeg agent tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: FFMPEG � baca isi file .sh (per agent) ---
app.get('/api/ffmpeg/:agentId/scripts/:name', requireAuth, async (req, res) => {
  try {
    const r = await ffmpegFetch(req.params.agentId, `/scripts/${encodeURIComponent(req.params.name)}`);
    res.status(r.status).json(r.body);
  } catch (e) {
    res.status(503).json({ success: false, message: 'FFmpeg agent tidak dapat dijangkau: ' + e.message });
  }
});

// --- API: FFMPEG � simpan isi file .sh (semua role login boleh, per agent) ---
app.put('/api/ffmpeg/:agentId/scripts/:name', requireAuth, async (req, res) => {
  try {
    const r = await ffmpegFetch(req.params.agentId, `/scripts/${encodeURIComponent(req.params.name)}`, {
      method: 'PUT',
      body: { content: req.body.content },
    });
    res.status(r.status).json(r.body);
  } catch (e) {
    res.status(503).json({ success: false, message: 'FFmpeg agent tidak dapat dijangkau: ' + e.message });
  }
});

// ============================================================
// END PATCH: FFmpeg Agent Proxy
// ============================================================

// ============================================================
// PATCH: Proxmox VE Resource Monitoring (API token, port 8006)
// ============================================================
// Cara buat token di Proxmox:
//   Datacenter > Permissions > API Tokens > Add
//   User: monitor@pve (buat user khusus), Token ID: nocs, UNCHECK "Privilege Separation"
//   Beri role "PVEAuditor" (read-only) di path "/" untuk user tsb.
// Isi "token_id" = monitor@pve!nocs dan "token_secret" = UUID yang tampil.

function getProxmoxCfg(name) {
  return db.prepare('SELECT * FROM proxmox_config WHERE name = ?').get(name);
}

// Request ke API Proxmox. Pakai modul https (bukan fetch) supaya bisa menerima
// sertifikat self-signed bawaan Proxmox (rejectUnauthorized: false) HANYA untuk koneksi ini.
const proxmoxAgent = new (require('https').Agent)({ rejectUnauthorized: false });
function proxmoxFetch(cfg, apiPath) {
  return new Promise((resolve, reject) => {
    const req = require('https').request({
      host: cfg.host,
      port: cfg.port || 8006,
      path: '/api2/json' + apiPath,
      method: 'GET',
      agent: proxmoxAgent,
      timeout: 10000,
      headers: { Authorization: `PVEAPIToken=${cfg.token_id}=${cfg.token_secret}` },
    }, (r) => {
      let data = '';
      r.on('data', c => data += c);
      r.on('end', () => {
        if (r.statusCode < 200 || r.statusCode >= 300) {
          const hint = r.statusCode === 401 ? ' (token ID/secret salah)'
                     : r.statusCode === 403 ? ' (token tidak punya izin — beri role PVEAuditor di path /)' : '';
          return reject(new Error(`Proxmox HTTP ${r.statusCode}${hint}`));
        }
        try { resolve(JSON.parse(data).data); }
        catch (e) { reject(new Error('Respon Proxmox bukan JSON valid')); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('Timeout menghubungi Proxmox (cek IP/port/firewall)')));
    req.on('error', reject);
    req.end();
  });
}

// --- ADMIN: CRUD Proxmox ---
app.get('/api/admin/proxmox', requireAuth, (req, res) => {
  // token_secret sengaja TIDAK dikirim balik ke frontend
  const list = db.prepare('SELECT name, host, port, token_id FROM proxmox_config').all();
  res.json(list);
});

app.post('/api/admin/proxmox', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Akses ditolak' });
  const { name, host, port, token_id, token_secret } = req.body;
  if (!name || !host || !token_id || !token_secret)
    return res.status(400).json({ success: false, message: 'name, host, token_id, token_secret wajib diisi' });
  try {
    db.prepare('INSERT INTO proxmox_config (name, host, port, token_id, token_secret) VALUES (?, ?, ?, ?, ?)')
      .run(name, host, parseInt(port) || 8006, token_id, token_secret);
    res.json({ success: true, message: `Proxmox "${name}" berhasil ditambahkan` });
  } catch (e) {
    res.status(409).json({ success: false, message: `Proxmox "${name}" sudah ada` });
  }
});

app.put('/api/admin/proxmox', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Akses ditolak' });
  const { name, host, port, token_id, token_secret } = req.body;
  const existing = name && getProxmoxCfg(name);
  if (!existing) return res.status(404).json({ success: false, message: `Proxmox "${name}" tidak ditemukan` });
  db.prepare('UPDATE proxmox_config SET host=?, port=?, token_id=?, token_secret=? WHERE name=?')
    .run(
      host || existing.host,
      parseInt(port) || existing.port,
      token_id || existing.token_id,
      token_secret || existing.token_secret, // kosong = pertahankan secret lama
      name
    );
  res.json({ success: true, message: `Proxmox "${name}" berhasil diperbarui` });
});

app.delete('/api/admin/proxmox/:name', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Akses ditolak' });
  const name = decodeURIComponent(req.params.name);
  if (!getProxmoxCfg(name))
    return res.status(404).json({ success: false, message: `Proxmox "${name}" tidak ditemukan` });
  db.prepare('DELETE FROM proxmox_config WHERE name = ?').run(name);
  res.json({ success: true, message: `Proxmox "${name}" berhasil dihapus` });
});

// --- TEST KONEKSI ---
app.post('/api/proxmox/test', requireAuth, async (req, res) => {
  const { proxmoxName, host, port, token_id, token_secret } = req.body;
  const cfg = (proxmoxName && getProxmoxCfg(proxmoxName)) || { host, port, token_id, token_secret };
  if (!cfg.host || !cfg.token_id || !cfg.token_secret)
    return res.status(400).json({ success: false, message: 'host, token_id, token_secret wajib diisi' });
  try {
    const v = await proxmoxFetch(cfg, '/version');
    res.json({ success: true, message: `Terhubung! Proxmox VE ${v.version}` });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// --- RESOURCE: ringkasan node + VM/LXC + storage dalam satu panggilan ---
// Pakai /cluster/resources — satu request sudah memuat semua node, qemu, lxc, storage
// (cocok juga untuk standalone node tanpa cluster).
app.get('/api/proxmox/:name/resources', requireAuth, async (req, res) => {
  const cfg = getProxmoxCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Proxmox tidak ditemukan' });
  try {
    const items = (await proxmoxFetch(cfg, '/cluster/resources')) || [];
    const pct = (used, total) => (total > 0 ? Math.round((used / total) * 1000) / 10 : 0);

    const nodes = items.filter(i => i.type === 'node').map(n => ({
      node: n.node,
      online: n.status === 'online',
      uptime: n.uptime || 0,
      cpu: Math.round((n.cpu || 0) * 1000) / 10,        // persen
      cpuCores: n.maxcpu || 0,
      memUsed: n.mem || 0,
      memTotal: n.maxmem || 0,
      memPct: pct(n.mem, n.maxmem),
      diskUsed: n.disk || 0,
      diskTotal: n.maxdisk || 0,
      diskPct: pct(n.disk, n.maxdisk),
    })).sort((a, b) => a.node.localeCompare(b.node));

    const guests = items.filter(i => i.type === 'qemu' || i.type === 'lxc').map(g => ({
      vmid: g.vmid,
      name: g.name || `${g.type}-${g.vmid}`,
      type: g.type === 'qemu' ? 'VM' : 'LXC',
      node: g.node,
      status: g.status,                                  // running / stopped
      template: !!g.template,
      uptime: g.uptime || 0,
      cpu: Math.round((g.cpu || 0) * 1000) / 10,
      cpuCores: g.maxcpu || 0,
      memUsed: g.mem || 0,
      memTotal: g.maxmem || 0,
      memPct: pct(g.mem, g.maxmem),
      diskTotal: g.maxdisk || 0,
      netIn: g.netin || 0,                               // counter byte kumulatif
      netOut: g.netout || 0,
    })).filter(g => !g.template).sort((a, b) => a.vmid - b.vmid);

    const storages = items.filter(i => i.type === 'storage').map(s => ({
      storage: s.storage,
      node: s.node,
      shared: !!s.shared,
      status: s.status,
      used: s.disk || 0,
      total: s.maxdisk || 0,
      pct: pct(s.disk, s.maxdisk),
    })).sort((a, b) => a.node.localeCompare(b.node) || a.storage.localeCompare(b.storage));

    res.json({
      success: true,
      ts: new Date().toISOString(),
      summary: {
        nodesOnline: nodes.filter(n => n.online).length,
        nodesTotal: nodes.length,
        guestsRunning: guests.filter(g => g.status === 'running').length,
        guestsTotal: guests.length,
      },
      nodes, guests, storages,
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// --- RINGKASAN SEMUA SERVER PROXMOX (untuk kartu node di Dashboard) ---
// Mengumpulkan node dari semua server yang terdaftar dalam satu panggilan.
// Cache singkat (10 dtk) supaya refresh dashboard berulang tidak membebani Proxmox.
let _pveSummaryCache = { ts: 0, data: null };
app.get('/api/proxmox/summary', requireAuth, async (req, res) => {
  try {
    if (_pveSummaryCache.data && Date.now() - _pveSummaryCache.ts < 10000) {
      return res.json(_pveSummaryCache.data);
    }
    const servers = db.prepare('SELECT * FROM proxmox_config').all();
    const pct = (used, total) => (total > 0 ? Math.round((used / total) * 1000) / 10 : 0);

    const results = await Promise.allSettled(servers.map(async (cfg) => {
      const items = (await proxmoxFetch(cfg, '/cluster/resources')) || [];
      const guests = items.filter(i => (i.type === 'qemu' || i.type === 'lxc') && !i.template);
      const nodes = items.filter(i => i.type === 'node').map(n => {
        const g = guests.filter(x => x.node === n.node);
        return {
          server: cfg.name,
          node: n.node,
          online: n.status === 'online',
          uptime: n.uptime || 0,
          cpu: Math.round((n.cpu || 0) * 1000) / 10,
          cpuCores: n.maxcpu || 0,
          memUsed: n.mem || 0,
          memTotal: n.maxmem || 0,
          memPct: pct(n.mem, n.maxmem),
          diskUsed: n.disk || 0,
          diskTotal: n.maxdisk || 0,
          diskPct: pct(n.disk, n.maxdisk),
          guestsRunning: g.filter(x => x.status === 'running').length,
          guestsTotal: g.length,
        };
      }).sort((a, b) => a.node.localeCompare(b.node));
      return nodes;
    }));

    const nodes = [];
    const errors = [];
    results.forEach((r, i) => {
      if (r.status === 'fulfilled') nodes.push(...r.value);
      else errors.push({ server: servers[i].name, message: r.reason && r.reason.message });
    });

    const payload = { success: true, ts: new Date().toISOString(), serverCount: servers.length, nodes, errors };
    _pveSummaryCache = { ts: Date.now(), data: payload };
    res.json(payload);
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// --- DETAIL SATU NODE (load average, swap, versi kernel, dst) ---
app.get('/api/proxmox/:name/node/:node/status', requireAuth, async (req, res) => {
  const cfg = getProxmoxCfg(req.params.name);
  if (!cfg) return res.status(404).json({ success: false, message: 'Proxmox tidak ditemukan' });
  // node name dipakai di path URL — batasi karakter supaya tidak bisa nyelipin path lain
  if (!/^[A-Za-z0-9._-]+$/.test(req.params.node))
    return res.status(400).json({ success: false, message: 'Nama node tidak valid' });
  try {
    const s = await proxmoxFetch(cfg, `/nodes/${req.params.node}/status`);
    res.json({
      success: true,
      node: req.params.node,
      uptime: s.uptime,
      cpuPct: Math.round((s.cpu || 0) * 1000) / 10,
      loadavg: s.loadavg || [],
      cpuModel: s.cpuinfo?.model || null,
      cpuCores: s.cpuinfo?.cpus || null,
      cpuSockets: s.cpuinfo?.sockets || null,
      mem: s.memory || null,
      swap: s.swap || null,
      rootfs: s.rootfs || null,
      pveVersion: s.pveversion || null,
      kernel: s.kversion || null,
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ============================================================
// END PATCH: Proxmox VE Resource Monitoring
// ============================================================

// --- PORT ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
  console.log(`[POLLER] Background poller aktif, interval: ${POLL_INTERVAL_MS / 60000} menit`);
});