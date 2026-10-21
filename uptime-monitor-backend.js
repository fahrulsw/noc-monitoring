// ============================================================
// PING / UPTIME MONITOR — modul backend (Node.js + Express + better-sqlite3)
// ============================================================
//
// Dibuat untuk dipasang ke server.js kamu yang sudah ada. Modul ini
// pakai instance `db` (better-sqlite3) dan `requireAuth` yang SAMA
// dengan yang sudah ada di server.js — jadi tidak bikin koneksi DB
// baru dan otomatis ikut proteksi login yang sudah berjalan.
//
// CARA PASANG (3 baris di server.js):
//
//   1) Taruh dekat require lain di paling atas server.js:
//        const createUptimeMonitor = require('./uptime-monitor-backend');
//
//   2) Taruh SETELAH `const db = new Database(...)` dan SETELAH
//      `function requireAuth(...)` didefinisikan (keduanya sudah ada
//      lebih awal di server.js kamu):
//        const uptimeMonitor = createUptimeMonitor(db, requireAuth);
//        app.use('/api/uptime', uptimeMonitor.router);
//        uptimeMonitor.startScheduler();
//
//   3) Taruh sebelum `app.listen(...)` di paling bawah kalau belum
//      sempat ditaruh di langkah 2 — urutannya bebas asal sebelum
//      app.listen dan sesudah db + requireAuth ada.
//
// TIDAK ADA package npm baru yang perlu diinstall — express &
// better-sqlite3 kamu sudah pakai untuk fitur lain. Sisanya modul
// bawaan Node (child_process, http, https, os).
//
// CATATAN ICMP PING:
// icmpPing() di bawah memanggil binary `ping` bawaan OS lewat
// child_process. Kalau server dijalankan di container minimal tanpa
// command ping, install dulu: `apt-get install -y iputils-ping`
// (Debian/Ubuntu) atau `apk add iputils` (Alpine).
// ============================================================

const https = require('https');
const http = require('http');
const { exec } = require('child_process');
const os = require('os');

const HISTORY_LIMIT = 200;            // jumlah histori check yg disimpan per monitor
const CHECK_INTERVAL_MS = 60 * 1000;  // interval check background (default: tiap 60 detik)
const CHECK_TIMEOUT_MS = 8000;        // timeout per check HTTP
const PING_TIMEOUT_S = 2;             // timeout per ping ICMP (detik)

function genId() {
  return 'mon_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// Ping ICMP pakai binary `ping` sistem (tanpa dependency npm tambahan).
function icmpPing(host) {
  return new Promise((resolve) => {
    const isWin = os.platform() === 'win32';
    const cmd = isWin
      ? `ping -n 1 -w ${PING_TIMEOUT_S * 1000} ${host}`
      : `ping -c 1 -W ${PING_TIMEOUT_S} ${host}`;
    const started = Date.now();
    exec(cmd, { timeout: (PING_TIMEOUT_S + 2) * 1000 }, (err, stdout) => {
      if (err) return resolve({ up: false, latencyMs: null, packetLoss: 100 });
      let latencyMs = null;
      const timeMatch = stdout.match(/time[=<]([\d.]+)\s*ms/i);
      if (timeMatch) latencyMs = parseFloat(timeMatch[1]);
      else latencyMs = Date.now() - started; // fallback kasar kalau parsing gagal
      const lossMatch = stdout.match(/(\d+)%\s*(packet\s*)?loss/i);
      const packetLoss = lossMatch ? parseInt(lossMatch[1], 10) : 0;
      resolve({ up: packetLoss < 100, latencyMs, packetLoss });
    });
  });
}

// HTTP(S) check: status code, response time, dan info sertifikat SSL (kalau https).
function httpCheck(targetUrl) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(targetUrl); } catch (e) {
      return resolve({ up: false, statusCode: null, latencyMs: null, ssl: null, error: 'URL tidak valid' });
    }
    const lib = u.protocol === 'https:' ? https : http;
    const started = Date.now();
    const req = lib.get(u, { timeout: CHECK_TIMEOUT_MS }, (res) => {
      const latencyMs = Date.now() - started;
      let sslInfo = null;
      if (u.protocol === 'https:' && res.socket && res.socket.getPeerCertificate) {
        const cert = res.socket.getPeerCertificate();
        if (cert && cert.valid_to) {
          const validTo = new Date(cert.valid_to);
          const daysLeft = Math.round((validTo - Date.now()) / (1000 * 60 * 60 * 24));
          sslInfo = { valid: daysLeft > 0, validTo: cert.valid_to, daysLeft };
        }
      }
      res.on('data', () => {}); // buang body, cukup status & header
      res.on('end', () => {
        resolve({
          up: res.statusCode >= 200 && res.statusCode < 400,
          statusCode: res.statusCode,
          latencyMs,
          ssl: sslInfo,
        });
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ up: false, statusCode: null, latencyMs: null, ssl: null, error: 'timeout' }); });
    req.on('error', (e) => resolve({ up: false, statusCode: null, latencyMs: null, ssl: null, error: e.message }));
  });
}

/**
 * @param {import('better-sqlite3').Database} db  instance db yang sama dipakai server.js
 * @param {Function} requireAuth  middleware auth yang sama dipakai server.js
 */
module.exports = function createUptimeMonitor(db, requireAuth) {
  const express = require('express');
  const router = express.Router();

  // ---------- Tabel SQLite (dibuat kalau belum ada, aman dipanggil berkali-kali) ----------
  db.exec(`
    CREATE TABLE IF NOT EXISTS uptime_monitors (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      target      TEXT NOT NULL,
      check_type  TEXT NOT NULL,        -- 'ping' | 'http'
      category    TEXT NOT NULL,        -- 'internal' | 'external'
      paused      INTEGER DEFAULT 0,
      created_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS uptime_checks (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      monitor_id   TEXT NOT NULL,
      ts           INTEGER NOT NULL,
      up           INTEGER NOT NULL,
      latency_ms   REAL,
      packet_loss  INTEGER,
      status_code  INTEGER,
      ssl_valid    INTEGER,
      ssl_valid_to TEXT,
      ssl_days_left INTEGER,
      error        TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_uptime_checks_monitor ON uptime_checks(monitor_id, ts);
  `);

  // ---------- Helper query ----------
  function rowToMonitor(row) {
    return {
      id: row.id,
      name: row.name,
      target: row.target,
      checkType: row.check_type,
      category: row.category,
      paused: !!row.paused,
      createdAt: row.created_at,
    };
  }

  function rowToCheck(row) {
    return {
      t: row.ts,
      up: !!row.up,
      latencyMs: row.latency_ms,
      packetLoss: row.packet_loss,
      statusCode: row.status_code,
      ssl: row.ssl_valid == null ? null : { valid: !!row.ssl_valid, validTo: row.ssl_valid_to, daysLeft: row.ssl_days_left },
      error: row.error,
    };
  }

  function getHistory(monitorId, limit) {
    const rows = db.prepare(
      'SELECT * FROM uptime_checks WHERE monitor_id = ? ORDER BY ts ASC LIMIT ?'
    ).all(monitorId, limit);
    return rows.map(rowToCheck);
  }

  function getLastCheck(monitorId) {
    const row = db.prepare(
      'SELECT * FROM uptime_checks WHERE monitor_id = ? ORDER BY ts DESC LIMIT 1'
    ).get(monitorId);
    return row ? rowToCheck(row) : null;
  }

  function computeUptimePct(monitorId) {
    const row = db.prepare(
      'SELECT COUNT(*) as total, SUM(up) as ups FROM uptime_checks WHERE monitor_id = ?'
    ).get(monitorId);
    if (!row || !row.total) return null;
    return +((row.ups / row.total) * 100).toFixed(2);
  }

  function trimHistory(monitorId) {
    db.prepare(`
      DELETE FROM uptime_checks WHERE monitor_id = ? AND id NOT IN (
        SELECT id FROM uptime_checks WHERE monitor_id = ? ORDER BY id DESC LIMIT ?
      )
    `).run(monitorId, monitorId, HISTORY_LIMIT);
  }

  // ---------- Runner check ----------
  async function runCheck(monitor) {
    let result;
    if (monitor.checkType === 'ping') {
      result = await icmpPing(monitor.target);
    } else {
      result = await httpCheck(monitor.target);
    }
    const ts = Date.now();
    db.prepare(`
      INSERT INTO uptime_checks
        (monitor_id, ts, up, latency_ms, packet_loss, status_code, ssl_valid, ssl_valid_to, ssl_days_left, error)
      VALUES (@monitor_id, @ts, @up, @latency_ms, @packet_loss, @status_code, @ssl_valid, @ssl_valid_to, @ssl_days_left, @error)
    `).run({
      monitor_id: monitor.id,
      ts,
      up: result.up ? 1 : 0,
      latency_ms: result.latencyMs != null ? result.latencyMs : null,
      packet_loss: result.packetLoss != null ? result.packetLoss : null,
      status_code: result.statusCode != null ? result.statusCode : null,
      ssl_valid: result.ssl ? (result.ssl.valid ? 1 : 0) : null,
      ssl_valid_to: result.ssl ? result.ssl.validTo : null,
      ssl_days_left: result.ssl ? result.ssl.daysLeft : null,
      error: result.error || null,
    });
    trimHistory(monitor.id);
    return { t: ts, ...result };
  }

  // ---------- Scheduler background ----------
  let schedulerStarted = false;
  function startScheduler() {
    if (schedulerStarted) return;
    schedulerStarted = true;

    async function tick() {
      const monitors = db.prepare('SELECT * FROM uptime_monitors WHERE paused = 0').all().map(rowToMonitor);
      for (const monitor of monitors) {
        try { await runCheck(monitor); } catch (e) { console.error('[uptime] check error', monitor.name, e.message); }
      }
    }

    tick(); // jalankan sekali begitu server start
    setInterval(tick, CHECK_INTERVAL_MS);
    console.log('[uptime] scheduler jalan, interval', CHECK_INTERVAL_MS / 1000, 'detik');
  }

  // ============================================================
  // REST API — semua di bawah /api/uptime, wajib login (requireAuth)
  // ============================================================
  router.use(requireAuth);

  // GET /api/uptime/monitors — list semua monitor + status terakhir
  router.get('/monitors', (req, res) => {
    try {
      const rows = db.prepare('SELECT * FROM uptime_monitors ORDER BY created_at ASC').all();
      const result = rows.map(row => {
        const m = rowToMonitor(row);
        return {
          ...m,
          lastResult: getLastCheck(m.id),
          lastCheck: (getLastCheck(m.id) || {}).t || null,
          uptimePct: computeUptimePct(m.id),
          history: getHistory(m.id, 50),
        };
      });
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/uptime/monitors/:id — detail 1 monitor + histori penuh
  router.get('/monitors/:id', (req, res) => {
    try {
      const row = db.prepare('SELECT * FROM uptime_monitors WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ error: 'not found' });
      const m = rowToMonitor(row);
      res.json({ ...m, lastResult: getLastCheck(m.id), uptimePct: computeUptimePct(m.id), history: getHistory(m.id, HISTORY_LIMIT) });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/uptime/monitors — tambah monitor baru
  // body: { name, target, checkType: 'ping'|'http', category: 'internal'|'external' }
  router.post('/monitors', async (req, res) => {
    try {
      const { name, target, checkType, category } = req.body || {};
      if (!name || !target || !['ping', 'http'].includes(checkType)) {
        return res.status(400).json({ error: 'name, target, dan checkType (ping/http) wajib diisi' });
      }
      const monitor = {
        id: genId(),
        name,
        target,
        checkType,
        category: category === 'internal' ? 'internal' : 'external',
        createdAt: Date.now(),
      };
      db.prepare(`
        INSERT INTO uptime_monitors (id, name, target, check_type, category, paused, created_at)
        VALUES (@id, @name, @target, @checkType, @category, 0, @createdAt)
      `).run(monitor);

      // Langsung check sekali biar tidak perlu nunggu tick scheduler berikutnya
      runCheck(monitor).catch(() => {});

      res.json(monitor);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // PATCH /api/uptime/monitors/:id — update nama/target/pause
  router.patch('/monitors/:id', (req, res) => {
    try {
      const row = db.prepare('SELECT * FROM uptime_monitors WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ error: 'not found' });
      const { name, target, paused } = req.body || {};
      db.prepare(`
        UPDATE uptime_monitors SET
          name = COALESCE(@name, name),
          target = COALESCE(@target, target),
          paused = COALESCE(@paused, paused)
        WHERE id = @id
      `).run({
        id: req.params.id,
        name: name !== undefined ? name : null,
        target: target !== undefined ? target : null,
        paused: paused !== undefined ? (paused ? 1 : 0) : null,
      });
      const updated = db.prepare('SELECT * FROM uptime_monitors WHERE id = ?').get(req.params.id);
      res.json(rowToMonitor(updated));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // DELETE /api/uptime/monitors/:id — hapus monitor + histori-nya
  router.delete('/monitors/:id', (req, res) => {
    try {
      db.prepare('DELETE FROM uptime_checks WHERE monitor_id = ?').run(req.params.id);
      db.prepare('DELETE FROM uptime_monitors WHERE id = ?').run(req.params.id);
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/uptime/monitors/:id/check — trigger check manual (tombol "cek sekarang")
  router.post('/monitors/:id/check', async (req, res) => {
    try {
      const row = db.prepare('SELECT * FROM uptime_monitors WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ error: 'not found' });
      const result = await runCheck(rowToMonitor(row));
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return { router, startScheduler };
};
