const fs = require('fs');
const filePath = process.argv[2];

if (!filePath) {
  console.error('Usage: node fix-nbfetch.js /path/to/server.js');
  process.exit(1);
}

let content = fs.readFileSync(filePath, 'utf8');

// Cari dan ganti seluruh fungsi nbFetch lama
const oldPattern = /async function nbFetch\(path, options = \{\}\) \{[\s\S]*?^}/m;

const newFn = `async function nbFetch(path, options = {}) {
  const url = NETBACKUP_URL + path;
  const fetchOptions = {
    method: options.method || 'GET',
    headers: { 'Content-Type': 'application/json' },
  };
  if (options.body) {
    fetchOptions.body = typeof options.body === 'string'
      ? options.body
      : JSON.stringify(options.body);
  }
  const r = await fetch(url, fetchOptions);
  const body = await r.json();
  return { status: r.status, body };
}`;

if (!oldPattern.test(content)) {
  console.error('❌ Fungsi nbFetch tidak ditemukan dengan pattern regex biasa, mencoba cara lain...');
  
  // Cari posisi manual
  const start = content.indexOf('async function nbFetch(');
  if (start === -1) {
    console.error('❌ nbFetch tidak ditemukan sama sekali!');
    process.exit(1);
  }
  
  // Cari penutup fungsi dengan menghitung kurung kurawal
  let depth = 0;
  let end = -1;
  let inFunc = false;
  for (let i = start; i < content.length; i++) {
    if (content[i] === '{') { depth++; inFunc = true; }
    if (content[i] === '}') { depth--; }
    if (inFunc && depth === 0) { end = i + 1; break; }
  }
  
  if (end === -1) {
    console.error('❌ Tidak bisa menemukan akhir fungsi nbFetch');
    process.exit(1);
  }
  
  const oldFn = content.substring(start, end);
  console.log('✅ Ditemukan fungsi lama:\n' + oldFn.substring(0, 100) + '...');
  
  content = content.substring(0, start) + newFn + content.substring(end);
} else {
  content = content.replace(oldPattern, newFn);
  console.log('✅ Berhasil replace dengan regex');
}

fs.writeFileSync(filePath, content);
console.log('✅ File berhasil diupdate!');
