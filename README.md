# ONU Activator — merdeka.net.id
Generate & Push Script Aktivasi ONU ke OLT via SSH

## Instalasi

```bash
# 1. Install dependencies
npm install

# 2. Jalankan server
node server.js
# atau dengan auto-reload:
npx nodemon server.js
```

Server akan berjalan di: http://localhost:3000

---

## Konfigurasi OLT

Edit `server.js` bagian `OLT_CONFIG`:

```js
const OLT_CONFIG = {
  'NAMA-OLT': {
    host: '192.168.1.10',     // IP OLT
    username: 'admin',         // Username SSH
    password: 'admin123',      // Password SSH
    port: 22,                  // Port SSH (default 22)
    vendor: 'huawei',          // huawei | zte | fiberhome
  },
};
```

Tambah sebanyak OLT yang diperlukan.

---

## Vendor yang Didukung

| Vendor     | Script Format               |
|------------|-----------------------------|
| Huawei     | MA5608T / MA5800             |
| ZTE        | C300 / C320                 |
| FiberHome  | AN5516                      |

---

## Fitur

- ✅ Generate script aktivasi ONU per vendor
- ✅ Push script langsung ke OLT via SSH
- ✅ Test koneksi SSH sebelum push
- ✅ Copy & Download script
- ✅ Support multi-OLT

## Keamanan

Gunakan di jaringan internal. Jangan expose port ke internet tanpa autentikasi.
