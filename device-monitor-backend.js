// ============================================================
// MONITORING ROUTER & SWITCH (SNMP)
// - Status up/down + latency (ICMP, fallback RTT SNMP)
// - CPU, RAM, suhu, uptime  (OID khusus Mikrotik / Cisco / Huawei, fallback HOST-RESOURCES-MIB)
// - Status & trafik tiap port/interface (ifTable + ifXTable, counter 64-bit bila ada)
// - Riwayat sampel disimpan di SQLite (default 14 hari)
//
// Pasang di server.js (setelah db & requireAuth tersedia):
//   require('./device-monitor-backend')(app, { requireAuth, db });
// Butuh: net-snmp (sudah dipakai server.js)
// ============================================================
const snmp = require('net-snmp');
const { execFile } = require('child_process');

const POLL_INTERVAL_MS = 60 * 1000;
const POLL_CONCURRENCY = 5;
const SNMP_TIMEOUT_MS  = 3000;
const KEEP_DAYS        = 14;
const MAX_IFACES       = 512;

// ── OID ──
const O = {
  sysDescr: '1.3.6.1.2.1.1.1.0', sysObjectID: '1.3.6.1.2.1.1.2.0', sysUpTime: '1.3.6.1.2.1.1.3.0', sysName: '1.3.6.1.2.1.1.5.0',
  hrProcLoad: '1.3.6.1.2.1.25.3.3.1.2',
  hrStorageType: '1.3.6.1.2.1.25.2.3.1.2', hrStorageDescr: '1.3.6.1.2.1.25.2.3.1.3', hrStorageUnits: '1.3.6.1.2.1.25.2.3.1.4',
  hrStorageSize: '1.3.6.1.2.1.25.2.3.1.5', hrStorageUsed: '1.3.6.1.2.1.25.2.3.1.6', hrStorageRam: '1.3.6.1.2.1.25.2.1.2',
  ciscoCpu5m: '1.3.6.1.4.1.9.9.109.1.1.1.1.8', ciscoCpu5mOld: '1.3.6.1.4.1.9.9.109.1.1.1.1.5',
  ciscoMemUsed: '1.3.6.1.4.1.9.9.48.1.1.1.5', ciscoMemFree: '1.3.6.1.4.1.9.9.48.1.1.1.6',
  ciscoSensorType: '1.3.6.1.4.1.9.9.91.1.1.1.1.1', ciscoSensorValue: '1.3.6.1.4.1.9.9.91.1.1.1.1.4',
  huaweiCpu: '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5', huaweiMem: '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7', huaweiTemp: '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11',
  mtTemp: '1.3.6.1.4.1.14988.1.1.3.10.0', mtCpuTemp: '1.3.6.1.4.1.14988.1.1.3.11.0',
  ifName: '1.3.6.1.2.1.31.1.1.1.1', ifAlias: '1.3.6.1.2.1.31.1.1.1.18', ifHCIn: '1.3.6.1.2.1.31.1.1.1.6', ifHCOut: '1.3.6.1.2.1.31.1.1.1.10',
  ifHighSpeed: '1.3.6.1.2.1.31.1.1.1.15',
  ifDescr: '1.3.6.1.2.1.2.2.1.2', ifAdmin: '1.3.6.1.2.1.2.2.1.7', ifOper: '1.3.6.1.2.1.2.2.1.8', ifIn: '1.3.6.1.2.1.2.2.1.10', ifOut: '1.3.6.1.2.1.2.2.1.16',
  ifSpeed: '1.3.6.1.2.1.2.2.1.5',
};

const VENDOR_PREFIX = [['1.3.6.1.4.1.14988', 'mikrotik'], ['1.3.6.1.4.1.9.', 'cisco'], ['1.3.6.1.4.1.2011', 'huawei']];
const detectVendor = oid => { const s = String(oid || ''); for (const [p, v] of VENDOR_PREFIX) if (s.startsWith(p)) return v; return 'generic'; };

// ── helper SNMP ──
function mkSession(d) {
  return snmp.createSession(d.host, d.community, {
    port: d.port || 161, retries: 1, timeout: SNMP_TIMEOUT_MS,
    version: d.snmp_version === '1' ? snmp.Version1 : snmp.Version2c,
  });
}
const str = v => (Buffer.isBuffer(v) ? v.toString('utf8') : String(v == null ? '' : v));
function num(vb) {
  const v = vb && vb.value;
  if (v == null) return null;
  if (Buffer.isBuffer(v)) { let n = 0n; for (const b of v) n = (n << 8n) | BigInt(b); return Number(n); }
  const n = Number(v); return Number.isFinite(n) ? n : null;
}
function get(session, oids) {
  return new Promise((resolve, reject) => session.get(oids, (err, vbs) => err ? reject(err) : resolve(vbs)));
}
function walk(session, oid) {
  return new Promise(resolve => {
    const out = [];
    try {
      session.subtree(oid, 20, vbs => { for (const vb of vbs) if (!snmp.isVarbindError(vb)) out.push(vb); }, () => resolve(out));
    } catch (e) { resolve(out); }
  });
}
const idxOf = (vb, base) => vb.oid.slice(base.length + 1);
async function walkMap(session, oid, conv) {          // -> Map(index -> nilai)
  const m = new Map();
  for (const vb of await walk(session, oid)) m.set(idxOf(vb, oid), conv ? conv(vb) : vb.value);
  return m;
}
const avg = a => a.length ? a.reduce((x, y) => x + y, 0) / a.length : null;

function ping(host) {
  return new Promise(resolve => {
    if (!/^[A-Za-z0-9][A-Za-z0-9.\-:]*$/.test(host)) return resolve(null);
    execFile('ping', ['-c', '1', '-W', '2', host], { timeout: 4000 }, (err, out) => {
      const m = /time[=<]([\d.]+)\s*ms/.exec(String(out || ''));
      resolve(m ? parseFloat(m[1]) : null);
    });
  });
}

// ── pengumpul metrik per vendor ──
async function readCpu(s, vendor) {
  if (vendor === 'cisco') {
    let m = await walkMap(s, O.ciscoCpu5m, num);
    if (!m.size) m = await walkMap(s, O.ciscoCpu5mOld, num);
    if (m.size) return Math.max(...m.values());
  }
  if (vendor === 'huawei') {
    const m = await walkMap(s, O.huaweiCpu, num);
    const vals = [...m.values()].filter(v => v != null && v >= 0 && v <= 100);
    if (vals.length) return Math.max(...vals);
  }
  const m = await walkMap(s, O.hrProcLoad, num);
  const vals = [...m.values()].filter(v => v != null);
  return avg(vals);
}
async function readMem(s, vendor) {
  if (vendor === 'cisco') {
    const used = await walkMap(s, O.ciscoMemUsed, num), free = await walkMap(s, O.ciscoMemFree, num);
    if (used.size) { const k = [...used.keys()].sort((a, b) => a - b)[0]; const u = used.get(k), f = free.get(k); if (u != null && f != null && u + f > 0) return u / (u + f) * 100; }
  }
  if (vendor === 'huawei') {
    const m = await walkMap(s, O.huaweiMem, num);
    const vals = [...m.values()].filter(v => v != null && v >= 0 && v <= 100 && v > 0);
    if (vals.length) return Math.max(...vals);
  }
  const type = await walkMap(s, O.hrStorageType, v => str(v.value));
  const ramIdx = [...type.entries()].filter(([, t]) => t === O.hrStorageRam).map(([i]) => i);
  if (!ramIdx.length) return null;
  const [size, used] = await Promise.all([walkMap(s, O.hrStorageSize, num), walkMap(s, O.hrStorageUsed, num)]);
  let best = null;
  for (const i of ramIdx) { const sz = size.get(i), us = used.get(i); if (sz > 0 && us != null && (!best || sz > best.sz)) best = { sz, us }; }
  return best ? best.us / best.sz * 100 : null;
}
async function readTemp(s, vendor) {
  if (vendor === 'mikrotik') {
    const vbs = await get(s, [O.mtTemp, O.mtCpuTemp]).catch(() => []);
    const vals = vbs.filter(v => !snmp.isVarbindError(v)).map(num).filter(v => v != null && v > 0).map(v => v / 10);
    if (vals.length) return Math.max(...vals);
  }
  if (vendor === 'cisco') {
    const [type, val] = await Promise.all([walkMap(s, O.ciscoSensorType, num), walkMap(s, O.ciscoSensorValue, num)]);
    const t = [...type.entries()].filter(([, v]) => v === 8).map(([i]) => val.get(i)).filter(v => v != null && v > 0 && v < 200);
    if (t.length) return Math.max(...t);
  }
  if (vendor === 'huawei') {
    const m = await walkMap(s, O.huaweiTemp, num);
    const t = [...m.values()].filter(v => v != null && v > 0 && v < 200);
    if (t.length) return Math.max(...t);
  }
  return null;
}
async function readIfaces(s) {
  const [name, descr, alias, admin, oper, hcIn, hcOut, hi, inO, outO, spd] = await Promise.all([
    walkMap(s, O.ifName, v => str(v.value)), walkMap(s, O.ifDescr, v => str(v.value)), walkMap(s, O.ifAlias, v => str(v.value)),
    walkMap(s, O.ifAdmin, num), walkMap(s, O.ifOper, num), walkMap(s, O.ifHCIn, num), walkMap(s, O.ifHCOut, num),
    walkMap(s, O.ifHighSpeed, num), walkMap(s, O.ifIn, num), walkMap(s, O.ifOut, num), walkMap(s, O.ifSpeed, num),
  ]);
  const idxs = [...(oper.size ? oper : descr).keys()].slice(0, MAX_IFACES);
  return idxs.map(i => ({
    idx: Number(i),
    name: name.get(i) || descr.get(i) || ('if' + i),
    alias: alias.get(i) || '',
    admin: admin.get(i) ?? null, oper: oper.get(i) ?? null,
    speed_mbps: hi.get(i) || (spd.get(i) ? Math.round(spd.get(i) / 1e6) : 0),
    in_oct: hcIn.has(i) ? hcIn.get(i) : (inO.get(i) ?? null),
    out_oct: hcOut.has(i) ? hcOut.get(i) : (outO.get(i) ?? null),
    hc: hcIn.has(i),
  }));
}

module.exports = function setupDeviceMonitor(app, { requireAuth, db }) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS net_devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE, host TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'router',            -- router | switch
      vendor TEXT NOT NULL DEFAULT 'auto',            -- auto | mikrotik | cisco | huawei | generic
      snmp_version TEXT NOT NULL DEFAULT '2c', community TEXT NOT NULL DEFAULT 'public', port INTEGER NOT NULL DEFAULT 161,
      enabled INTEGER NOT NULL DEFAULT 1,
      detected_vendor TEXT, sys_descr TEXT, sys_name TEXT,
      up INTEGER, last_error TEXT, last_poll INTEGER, up_since INTEGER,
      cpu REAL, mem_pct REAL, temp REAL, latency REAL, uptime_s INTEGER,
      created_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS net_device_samples (
      device_id INTEGER NOT NULL, ts INTEGER NOT NULL, up INTEGER, cpu REAL, mem_pct REAL, temp REAL, latency REAL
    );
    CREATE INDEX IF NOT EXISTS idx_net_samples ON net_device_samples (device_id, ts);
    CREATE TABLE IF NOT EXISTS net_device_ifaces (
      device_id INTEGER NOT NULL, if_index INTEGER NOT NULL, name TEXT, alias TEXT, admin INTEGER, oper INTEGER, speed_mbps INTEGER,
      in_bps REAL, out_bps REAL, in_oct REAL, out_oct REAL, ts INTEGER, PRIMARY KEY (device_id, if_index)
    );
  `);

  const prev = new Map();   // `${id}:${idx}` -> {in, out, ts, hc}
  const isAdmin = req => req.user && req.user.role === 'admin';
  const adminOnly = (req, res, next) => isAdmin(req) ? next() : res.status(403).json({ success: false, message: 'Akses ditolak — hanya admin' });
  // admin & operator boleh menambah / mengubah / menghapus / menguji / poll
  const manager = (req, res, next) => req.user && ['admin', 'operator'].includes(req.user.role) ? next() : res.status(403).json({ success: false, message: 'Akses ditolak — hanya admin / operator' });

  // ── polling satu device ──
  async function pollDevice(d) {
    const now = Date.now();
    const s = mkSession(d);
    s.on('error', () => {});
    const res = { up: 0, error: null };
    try {
      const t0 = Date.now();
      const vbs = await get(s, [O.sysDescr, O.sysObjectID, O.sysUpTime, O.sysName]);
      const rtt = Date.now() - t0;
      if (snmp.isVarbindError(vbs[2]) && snmp.isVarbindError(vbs[0])) throw new Error('Tidak ada respon SNMP');
      res.up = 1;
      const vendor = d.vendor !== 'auto' ? d.vendor : detectVendor(str(vbs[1] && vbs[1].value));
      const [icmp, cpu, mem, temp, ifs] = await Promise.all([
        ping(d.host),
        readCpu(s, vendor).catch(() => null), readMem(s, vendor).catch(() => null), readTemp(s, vendor).catch(() => null),
        readIfaces(s).catch(() => []),
      ]);
      Object.assign(res, {
        vendor, sys_descr: str(vbs[0].value).slice(0, 300), sys_name: str(vbs[3].value).slice(0, 100),
        uptime_s: snmp.isVarbindError(vbs[2]) ? null : Math.floor(num(vbs[2]) / 100),
        cpu, mem, temp, latency: icmp != null ? icmp : rtt, ifs,
      });
    } catch (e) {
      res.error = String(e.message || e).slice(0, 200);
    } finally { try { s.close(); } catch (e) {} }

    const wasUp = d.up;
    const upSince = res.up ? (wasUp === 1 && d.up_since ? d.up_since : now) : null;
    db.prepare(`UPDATE net_devices SET up=?, last_error=?, last_poll=?, up_since=?, detected_vendor=COALESCE(?, detected_vendor),
                sys_descr=COALESCE(?, sys_descr), sys_name=COALESCE(?, sys_name), cpu=?, mem_pct=?, temp=?, latency=?, uptime_s=? WHERE id=?`)
      .run(res.up, res.error, now, upSince, res.vendor || null, res.sys_descr || null, res.sys_name || null,
        res.up ? res.cpu : null, res.up ? res.mem : null, res.up ? res.temp : null, res.up ? res.latency : null, res.up ? res.uptime_s : null, d.id);
    db.prepare('INSERT INTO net_device_samples (device_id, ts, up, cpu, mem_pct, temp, latency) VALUES (?,?,?,?,?,?,?)')
      .run(d.id, now, res.up, res.cpu ?? null, res.mem ?? null, res.temp ?? null, res.latency ?? null);

    if (res.up && res.ifs) {
      const up = db.prepare(`INSERT INTO net_device_ifaces (device_id, if_index, name, alias, admin, oper, speed_mbps, in_bps, out_bps, in_oct, out_oct, ts)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id, if_index) DO UPDATE SET name=excluded.name, alias=excluded.alias, admin=excluded.admin,
        oper=excluded.oper, speed_mbps=excluded.speed_mbps, in_bps=excluded.in_bps, out_bps=excluded.out_bps, in_oct=excluded.in_oct, out_oct=excluded.out_oct, ts=excluded.ts`);
      const seen = new Set();
      db.transaction(() => {
        for (const i of res.ifs) {
          seen.add(i.idx);
          const k = d.id + ':' + i.idx, p = prev.get(k);
          let inB = null, outB = null;
          if (p && now > p.ts && i.in_oct != null && i.out_oct != null) {
            const dt = (now - p.ts) / 1000, wrap = i.hc ? 2 ** 64 : 2 ** 32;
            const delta = (c, o) => (c >= o ? c - o : (i.hc ? null : c + wrap - o));
            const di = delta(i.in_oct, p.in), dO = delta(i.out_oct, p.out);
            if (di != null) inB = di * 8 / dt;
            if (dO != null) outB = dO * 8 / dt;
          }
          prev.set(k, { in: i.in_oct, out: i.out_oct, ts: now });
          up.run(d.id, i.idx, i.name, i.alias, i.admin, i.oper, i.speed_mbps, inB, outB, i.in_oct, i.out_oct, now);
        }
        // hapus interface yang sudah tidak ada
        for (const r of db.prepare('SELECT if_index FROM net_device_ifaces WHERE device_id=?').all(d.id))
          if (!seen.has(r.if_index)) db.prepare('DELETE FROM net_device_ifaces WHERE device_id=? AND if_index=?').run(d.id, r.if_index);
      })();
    }
    return res;
  }

  let polling = false;
  async function pollAll() {
    if (polling) return; polling = true;
    try {
      const list = db.prepare('SELECT * FROM net_devices WHERE enabled=1').all();
      for (let i = 0; i < list.length; i += POLL_CONCURRENCY)
        await Promise.all(list.slice(i, i + POLL_CONCURRENCY).map(d => pollDevice(d).catch(e => console.warn('[NETDEV]', d.name, e.message))));
    } finally { polling = false; }
  }
  const timer = setInterval(pollAll, POLL_INTERVAL_MS); timer.unref && timer.unref();
  const first = setTimeout(pollAll, 5000); first.unref && first.unref();
  const pruner = setInterval(() => {
    db.prepare('DELETE FROM net_device_samples WHERE ts < ?').run(Date.now() - KEEP_DAYS * 86400000);
  }, 6 * 3600 * 1000); pruner.unref && pruner.unref();

  // ── API: baca (semua role login) ──
  const publicRow = r => ({
    id: r.id, name: r.name, host: r.host, kind: r.kind, vendor: r.vendor === 'auto' ? (r.detected_vendor || 'auto') : r.vendor,
    enabled: !!r.enabled, up: r.up == null ? null : !!r.up, last_error: r.last_error, last_poll: r.last_poll, up_since: r.up_since,
    cpu: r.cpu, mem_pct: r.mem_pct, temp: r.temp, latency: r.latency, uptime_s: r.uptime_s, sys_descr: r.sys_descr, sys_name: r.sys_name,
    if_total: r.if_total || 0, if_up: r.if_up || 0,
  });
  const listSql = `SELECT d.*, (SELECT COUNT(*) FROM net_device_ifaces i WHERE i.device_id=d.id) AS if_total,
                   (SELECT COUNT(*) FROM net_device_ifaces i WHERE i.device_id=d.id AND i.oper=1) AS if_up FROM net_devices d`;

  app.get('/api/net-devices', requireAuth, (req, res) => {
    const rows = db.prepare(listSql + ' ORDER BY d.kind, d.name').all().map(publicRow);
    res.json({ success: true, devices: rows, interval_s: POLL_INTERVAL_MS / 1000 });
  });
  app.get('/api/net-devices/:id', requireAuth, (req, res) => {
    const r = db.prepare(listSql + ' WHERE d.id=?').get(req.params.id);
    if (!r) return res.status(404).json({ success: false, message: 'Device tidak ditemukan' });
    const ifs = db.prepare('SELECT if_index, name, alias, admin, oper, speed_mbps, in_bps, out_bps FROM net_device_ifaces WHERE device_id=? ORDER BY if_index').all(r.id);
    res.json({ success: true, device: publicRow(r), interfaces: ifs });
  });
  app.get('/api/net-devices/:id/history', requireAuth, (req, res) => {
    const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 24, 1), KEEP_DAYS * 24);
    const since = Date.now() - hours * 3600000;
    const rows = db.prepare('SELECT ts, up, cpu, mem_pct, temp, latency FROM net_device_samples WHERE device_id=? AND ts>=? ORDER BY ts').all(req.params.id, since);
    const maxPts = 240, step = Math.ceil(rows.length / maxPts);     // ringkas supaya ringan
    const out = [];
    for (let i = 0; i < rows.length; i += step) {
      const g = rows.slice(i, i + step), a = k => { const v = g.map(x => x[k]).filter(x => x != null); return v.length ? v.reduce((p, c) => p + c, 0) / v.length : null; };
      out.push({ ts: g[0].ts, up: g.every(x => x.up) ? 1 : 0, cpu: a('cpu'), mem_pct: a('mem_pct'), temp: a('temp'), latency: a('latency') });
    }
    res.json({ success: true, hours, samples: out });
  });

  // ── API: kelola (admin) ──
  const clean = b => {
    const name = String(b.name || '').trim(), host = String(b.host || '').trim();
    if (!name || name.length > 60) return { err: 'Nama wajib diisi (maks 60 karakter)' };
    if (!/^[A-Za-z0-9][A-Za-z0-9.\-:]{0,252}$/.test(host)) return { err: 'IP / hostname tidak valid' };
    const kind = ['router', 'switch'].includes(b.kind) ? b.kind : 'router';
    const vendor = ['auto', 'mikrotik', 'cisco', 'huawei', 'generic'].includes(b.vendor) ? b.vendor : 'auto';
    const snmp_version = b.snmp_version === '1' ? '1' : '2c';
    const port = Math.min(Math.max(parseInt(b.port, 10) || 161, 1), 65535);
    return { v: { name, host, kind, vendor, snmp_version, port, community: b.community != null ? String(b.community).slice(0, 100) : null, enabled: b.enabled === false || b.enabled === 0 ? 0 : 1 } };
  };

  app.get('/api/net-devices/:id/config', requireAuth, manager, (req, res) => {
    const r = db.prepare('SELECT id, name, host, kind, vendor, snmp_version, community, port, enabled FROM net_devices WHERE id=?').get(req.params.id);
    if (!r) return res.status(404).json({ success: false, message: 'Device tidak ditemukan' });
    if (!isAdmin(req)) r.community = '';        // operator tidak melihat community yang tersimpan
    res.json({ success: true, config: r });
  });
  app.post('/api/net-devices', requireAuth, manager, async (req, res) => {
    const { v, err } = clean(req.body || {});
    if (err) return res.status(400).json({ success: false, message: err });
    try {
      const info = db.prepare('INSERT INTO net_devices (name, host, kind, vendor, snmp_version, community, port, enabled) VALUES (?,?,?,?,?,?,?,?)')
        .run(v.name, v.host, v.kind, v.vendor, v.snmp_version, v.community || 'public', v.port, v.enabled);
      const d = db.prepare('SELECT * FROM net_devices WHERE id=?').get(info.lastInsertRowid);
      pollDevice(d).catch(() => {});
      res.json({ success: true, id: d.id });
    } catch (e) {
      res.status(e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 500).json({ success: false, message: e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'Nama device sudah dipakai' : e.message });
    }
  });
  app.put('/api/net-devices/:id', requireAuth, manager, (req, res) => {
    const old = db.prepare('SELECT * FROM net_devices WHERE id=?').get(req.params.id);
    if (!old) return res.status(404).json({ success: false, message: 'Device tidak ditemukan' });
    const { v, err } = clean(req.body || {});
    if (err) return res.status(400).json({ success: false, message: err });
    try {
      db.prepare('UPDATE net_devices SET name=?, host=?, kind=?, vendor=?, snmp_version=?, community=?, port=?, enabled=? WHERE id=?')
        .run(v.name, v.host, v.kind, v.vendor, v.snmp_version, v.community ? v.community : old.community, v.port, v.enabled, old.id);
      pollDevice(db.prepare('SELECT * FROM net_devices WHERE id=?').get(old.id)).catch(() => {});
      res.json({ success: true });
    } catch (e) {
      res.status(e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 500).json({ success: false, message: e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'Nama device sudah dipakai' : e.message });
    }
  });
  app.delete('/api/net-devices/:id', requireAuth, manager, (req, res) => {
    const id = req.params.id;
    db.transaction(() => {
      db.prepare('DELETE FROM net_device_samples WHERE device_id=?').run(id);
      db.prepare('DELETE FROM net_device_ifaces WHERE device_id=?').run(id);
      db.prepare('DELETE FROM net_devices WHERE id=?').run(id);
    })();
    res.json({ success: true });
  });
  app.post('/api/net-devices/:id/poll', requireAuth, manager, async (req, res) => {
    const d = db.prepare('SELECT * FROM net_devices WHERE id=?').get(req.params.id);
    if (!d) return res.status(404).json({ success: false, message: 'Device tidak ditemukan' });
    const r = await pollDevice(d);
    res.json({ success: true, up: !!r.up, error: r.error });
  });
  // tes koneksi sebelum disimpan
  app.post('/api/net-devices/test', requireAuth, manager, async (req, res) => {
    const { v, err } = clean(req.body || {});
    if (err) return res.status(400).json({ success: false, message: err });
    let community = v.community;
    if (!community && req.body.id) { const o = db.prepare('SELECT community FROM net_devices WHERE id=?').get(req.body.id); community = o && o.community; }
    const s = mkSession({ ...v, community: community || 'public' }); s.on('error', () => {});
    try {
      const t0 = Date.now();
      const vbs = await get(s, [O.sysDescr, O.sysObjectID, O.sysName]);
      if (snmp.isVarbindError(vbs[0])) throw new Error('Tidak ada respon SNMP');
      res.json({ success: true, rtt: Date.now() - t0, vendor: detectVendor(str(vbs[1].value)), sys_name: str(vbs[2].value), sys_descr: str(vbs[0].value).slice(0, 200) });
    } catch (e) {
      res.json({ success: false, message: 'Gagal: ' + (String(e.message).includes('Timeout') || String(e.message).includes('timeout') ? 'timeout — cek IP, community, dan izin SNMP di perangkat' : e.message) });
    } finally { try { s.close(); } catch (e) {} }
  });

  return { pollAll, pollDevice };
};