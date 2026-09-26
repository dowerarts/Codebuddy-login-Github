# GitHub OAuth Login Automation

Node.js automation script untuk melakukan login GitHub dan otorisasi OAuth ke CodeBuddy secara otomatis. Script ini dirancang untuk berjalan dengan proxy rotasi, User-Agent acak, dan delay antar akun guna mengurangi deteksi mekanisme keamanan.

## Fitur Utama

- **Login GitHub otomatis** dengan email, password, dan 2FA (TOTP/6 digit).
- **OAuth CodeBuddy** melalui broker Keycloak (`Login with GitHub`).
- **Rotasi proxy** dengan session ID acak per akun (mendukung DataImpulse).
- **User-Agent & device token** acak untuk mengurangi fingerprint statis.
- **Delay antar akun** dan kontrol concurrency lewat environment variable.
- **Penanganan akun bermasalah**: akun yang `flagged`, `suspended`, atau `access-restricted` dicatat di `bad_accounts.txt` agar tidak dicoba ulang.
- **Session persistence**: menyimpan cookie hasil login ke file JSON per akun.

## Struktur File

```
.
├── github-login.js          # Script utama
├── codebuddy.txt            # Daftar akun (format: email|password|username|2fa)
├── proxy.txt                # Daftar proxy HTTP(S) (satu per baris)
├── device_tokens.txt        # (opsional) Daftar X-Device-Token
├── bad_accounts.txt         # (auto-generated) Akun bermasalah
└── sessions/                # (auto-generated) Cookie hasil login
```

## Persyaratan

- Node.js >= 18
- Paket npm: `axios`, `https-proxy-agent`, `totp-generator`

Install dependency:

```bash
npm install axios https-proxy-agent totp-generator
```

## Format Input

### `codebuddy.txt`

```
email1@example.com|password1|username1|2FA_SECRET_OR_CODE
email2@example.com|password2|username2
email3@example.com|password3|username3|2FA_SECRET_OR_CODE
```

Kolom:
1. Email akun GitHub
2. Password
3. Username GitHub
4. 2FA (opsional). Bisa berupa secret TOTP base32 atau kode 6 digit langsung.

### `proxy.txt`

```
http://user:pass@host:port
http://user:pass@gw.dataimpulse.com:823
```

Untuk proxy DataImpulse, script akan otomatis menambahkan `;sessid.<random>` pada username supaya setiap akun keluar dari IP/session berbeda.

### `device_tokens.txt` (opsional)

Satu `X-Device-Token` CodeBuddy per baris. Jika tidak ada, script akan generate token fallback acak per akun. Token terbaik adalah yang diambil dari browser DevTools saat login manual.

## Konfigurasi via Environment Variable

| Variable | Default | Keterangan |
|---|---|---|
| `CONCURRENCY` | `1` | Jumlah akun yang diproses bersamaan (maks 10). |
| `DELAY_MS` | `10000` | Jeda minimum antar akun (dalam ms). |
| `PROXY` | dari `proxy.txt` | Proxy statis untuk semua akun. |
| `USER_AGENT` | acak dari pool | User-Agent manual. |
| `CB_DEVICE_TOKEN` | - | Device token manual CodeBuddy. |
| `OCTO` | hardcoded | Nilai `_octo` cookie GitHub. |

## Cara Penggunaan

```bash
node github-login.js
```

Atau dengan pengaturan khusus:

```bash
CONCURRENCY=1 DELAY_MS=15000 node github-login.js
```

## Alur Kerja

1. **Memuat daftar akun** dari `codebuddy.txt`.
2. **Memilih proxy & UA** secara acak untuk setiap akun.
3. **Login GitHub**:
   - GET halaman home & login.
   - POST kredensial ke `/session`.
   - Jika muncul 2FA, generate TOTP dan POST ke `/sessions/two-factor`.
4. **OAuth CodeBuddy**:
   - Inisialisasi session CodeBuddy (`/console/accounts`, `/console/auth/risk-context`).
   - GET halaman authorize Keycloak.
   - Klik tombol `social-github` (broker login).
   - Redirect ke GitHub OAuth authorize dengan cookie login.
   - Kembali ke CodeBuddy dengan `code` untuk menukar session authenticated.
5. **Menyimpan hasil**:
   - Jika berhasil, cookie GitHub/CodeBuddy disimpan di folder `sessions/<email>/`.
   - Jika gagal, alasan kegagalan dicatat di ringkasan akhir.

## Output

Log di terminal menampilkan status tiap step:

```
[14.10.00] [>] [Main] ========== AKUN 1/5: user@example.com ==========
[14.10.00] [i] [Config] Using proxy: http://...__cr.id;sessid.xxx@gw.dataimpulse.com:823
[14.10.01] [+] [Step 1] Status: 200
...
[14.10.15] [i] [Main] ========== RINGKASAN ==========
[14.10.15] [+] [Main] Sukses: 1/5
[14.10.15] [!] [Main] Gagal: 4/5
```

## Troubleshooting

| Masalah | Penyebab umum | Solusi |
|---|---|---|
| `407 Proxy Authentication Required` | Kredensial proxy salah / session tidak valid. | Cek `proxy.txt`, pastikan username & password benar. |
| `account-flagged` / `suspended` | Akun GitHub sudah di-flag atau di-suspend. | Ganti akun; akun tersebut dicatat di `bad_accounts.txt`. |
| `access-restricted` / `security policy` | CodeBuddy/Tencent WAF mendeteksi pola otomatis. | Turunkan `CONCURRENCY`, naikkan `DELAY_MS`, ganti provider proxy, atau cooldown beberapa jam. |
| `authenticity_token tidak ditemukan` | GitHub mengembalikan halaman challenge/error. | Cek proxy, UA, dan pastikan IP tidak di-ban. |
| `no-first-session` | CodeBuddy tidak memberikan cookie session. | Cek koneksi/proxy atau device token. |

## Catatan Keamanan

- Script ini menyimpan password di plaintext (`codebuddy.txt`). Pastikan file tersebut tidak di-push ke repositori publik.
- Gunakan `.gitignore` untuk mengabaikan file sensitif:

```gitignore
codebuddy.txt
proxy.txt
device_tokens.txt
bad_accounts.txt
sessions/
.env
```

- Gunakan proxy yang valid dan jangan jalankan terlalu agresif supaya tidak melanggar kebijakan platform.

## Disclaimer

Script ini dibuat untuk tujuan edukasi dan otomatisasi akun yang Anda miliki secara sah. Penggunaan untuk aktivitas yang melanggar Terms of Service GitHub, CodeBuddy, atau hukum yang berlaku menjadi tanggung jawab pengguna sepenuhnya.
