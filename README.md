# XScanner v3

**Framework deteksi XSS (Cross-Site Scripting) berbasis Python dengan 152 juta+ kombinasi payload.**

> ⚠️ Gunakan hanya pada sistem yang Anda miliki atau memiliki izin tertulis eksplisit untuk diuji. Penggunaan tanpa izin adalah tindak pidana.

---

## Daftar Isi

- [Persyaratan Sistem](#persyaratan-sistem)
- [Instalasi](#instalasi)
- [Penggunaan Pertama Kali](#penggunaan-pertama-kali)
- [Cara Penggunaan Lengkap](#cara-penggunaan-lengkap)
- [Scan Profiles](#scan-profiles)
- [Fitur Tambahan](#fitur-tambahan)
- [Memahami Hasil Scan](#memahami-hasil-scan)
- [Format Laporan](#format-laporan)
- [Testing di Lab Lokal](#testing-di-lab-lokal)
- [FAQ](#faq)

---

## Persyaratan Sistem

| Kebutuhan | Versi minimum |
|-----------|--------------|
| Python | 3.11 atau lebih baru |
| pip | terbaru |
| OS | Linux / macOS / Windows |
| RAM | 512 MB (disarankan 1 GB) |

Cek versi Python Anda:

```bash
python3 --version
```

---

## Instalasi

### Langkah 1 — Clone repo

```bash
git clone https://github.com/Auto-runs/xscanner-v3.git
cd xscanner-v3
```

### Langkah 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### Langkah 3 — Verifikasi instalasi

```bash
python xscanner.py --help
```

Jika muncul daftar opsi, instalasi berhasil.

### Langkah 4 (Opsional) — Aktifkan headless browser verification

Fitur ini membuktikan bahwa XSS benar-benar ter-eksekusi di browser, bukan sekadar terefleksi sebagai teks.

```bash
pip install playwright
playwright install chromium
```

### Langkah 5 (Opsional) — Jalankan test suite

```bash
pip install pytest pytest-asyncio
python -m pytest tests/ -v
# Hasil yang diharapkan: 136 passed
```

---

## Penggunaan Pertama Kali

### Scan sederhana satu URL

```bash
python xscanner.py -u "https://target.com/search?q=test"
```

### Scan tanpa crawling (hanya parameter yang ada di URL)

```bash
python xscanner.py -u "https://target.com/page?id=1&name=test" --no-crawl
```

### Lihat hasil detail per finding

```bash
python xscanner.py -u "https://target.com/search?q=test" --details
```

---

## Cara Penggunaan Lengkap

### Scan dengan autentikasi (halaman yang butuh login)

Jika target memerlukan login, XScanner bisa otomatis mengisi form login:

```bash
python xscanner.py \
  -u "https://target.com/dashboard" \
  --login-url "https://target.com/login" \
  --username namauser \
  --password kataSandi123
```

### Scan dengan cookie (jika Anda sudah punya session)

```bash
python xscanner.py \
  -u "https://target.com/dashboard" \
  -c "session=abc123def456" \
  -c "csrf_token=xyz789"
```

### Scan dengan custom header

```bash
python xscanner.py \
  -u "https://target.com" \
  -H "Authorization: Bearer token_anda" \
  -H "X-API-Key: key_anda"
```

### Scan banyak target sekaligus dari file

Buat file `targets.txt`:
```
https://target.com/search?q=test
https://target.com/profile?id=1
https://target.com/comment?page=1
```

Kemudian jalankan:
```bash
python xscanner.py -l targets.txt --threads 10
```

### Scan dengan scope management (untuk bug bounty)

Batasi scan hanya ke domain yang diizinkan:

```bash
python xscanner.py \
  -u "https://target.com" \
  --scope "target.com" "*.target.com" \
  --exclude-scope "cdn.target.com" \
  --exclude-path "/logout" "/unsubscribe" "/delete"
```

### Scan via proxy (integrasi Burp Suite)

```bash
python xscanner.py \
  -u "https://target.com" \
  --proxy http://127.0.0.1:8080
```

### Scan dengan rate limiting (agar tidak ketahuan atau trigger WAF)

```bash
python xscanner.py \
  -u "https://target.com" \
  --rate-limit 2.0
# Artinya: jeda 2 detik antara setiap request
```

### Scan dan simpan laporan

```bash
python xscanner.py \
  -u "https://target.com" \
  -o hasil.json \
  --report-html hasil.html \
  --report-md hasil.md
```

---

## Scan Profiles

Pilih profile sesuai kebutuhan:

| Profile | Kecepatan | Kedalaman | Payload | Cocok untuk |
|---------|-----------|-----------|---------|-------------|
| `fast` | ⚡ Cepat | Dangkal | 200 | Recon awal |
| `normal` | ⚖️ Seimbang | Sedang | 500 | Scan standar |
| `deep` | 🐢 Lambat | Dalam | 2,000 | Full assessment |
| `stealth` | 🤫 Sangat lambat | Sedang | 300 | Hindari deteksi |

Cara pakai:

```bash
# Normal (default)
python xscanner.py -u "https://target.com"

# Deep scan
python xscanner.py -u "https://target.com" --deep

# Stealth
python xscanner.py -u "https://target.com" --profile stealth --rate-limit 3.0
```

---

## Fitur Tambahan

### Test XSS via HTTP Headers

Beberapa aplikasi merefleksikan header seperti `User-Agent` atau `Referer` — ini bisa jadi vektor XSS:

```bash
python xscanner.py -u "https://target.com" --test-headers
```

### Test HTTP Parameter Pollution

```bash
python xscanner.py -u "https://target.com" --test-hpp
```

### Test JSON API Endpoint

```bash
python xscanner.py -u "https://target.com/api" --test-json
```

### Blind XSS — deteksi XSS yang tidak langsung terlihat

Blind XSS terjadi ketika payload dieksekusi di halaman lain (misalnya admin panel). Anda butuh server penerima callback:

```bash
# Opsi 1: Gunakan built-in listener (jalankan di mesin yang bisa diakses publik)
python xscanner.py -u "https://target.com" --start-blind-server

# Opsi 2: Gunakan server eksternal (XSS Hunter, dll)
python xscanner.py -u "https://target.com" \
  --blind-callback "https://your.xsshunter.com/callback"
```

### Stored XSS — lacak XSS yang tersimpan di database

```bash
python xscanner.py -u "https://target.com" --second-order
```

### SPA Support — ekstrak parameter dari file JavaScript

Berguna untuk React, Vue, Angular, dll.:

```bash
python xscanner.py -u "https://target.com" --js-crawl
```

### Verifikasi dengan browser sungguhan

Membuktikan XSS benar-benar ter-eksekusi (butuh Playwright terinstall):

```bash
python xscanner.py -u "https://target.com" --verify-headless
```

### Checkpoint — lanjutkan scan yang terhenti

```bash
# Mulai scan dengan checkpoint
python xscanner.py -u "https://target.com" --checkpoint -o hasil.json

# Scan terhenti? Jalankan lagi perintah yang sama — akan lanjut dari titik berhenti
python xscanner.py -u "https://target.com" --checkpoint -o hasil.json
```

---

## Memahami Hasil Scan

Saat scan berjalan, Anda akan melihat output seperti ini:

```
[FOUND] Reflected XSS
  URL:      https://target.com/search
  Param:    q
  Context:  html
  Severity: High (100% confidence)
  Payload:  <script onerror=alert(1)>
```

**Penjelasan field:**

| Field | Arti |
|-------|------|
| `URL` | Halaman tempat XSS ditemukan |
| `Param` | Parameter yang rentan |
| `Context` | Di mana payload diinjeksikan di HTML |
| `Severity` | High / Medium / Low |
| `Confidence` | Seberapa yakin engine ini adalah XSS |
| `Payload` | Payload yang berhasil |

**Context yang mungkin muncul:**

| Context | Artinya |
|---------|---------|
| `html` | Payload masuk ke body HTML |
| `attribute` | Payload masuk ke nilai atribut (`value=""`, `alt=""`) |
| `js_string` | Payload masuk ke dalam string JavaScript |
| `javascript` | Payload masuk langsung ke kode JavaScript |
| `url` | Payload masuk ke nilai URL (`href`, `src`, `action`) |
| `comment` | Payload masuk ke komentar HTML |

---

## Format Laporan

### JSON (default, machine-readable)

```bash
python xscanner.py -u "https://target.com" -o laporan.json
```

Contoh output:
```json
{
  "tool": "XScanner v3.0",
  "timestamp": "2025-03-18T10:00:00+00:00",
  "total_findings": 2,
  "severity_summary": {"High": 2, "Medium": 0, "Low": 0},
  "findings": [
    {
      "url": "https://target.com/search",
      "param": "q",
      "xss_type": "reflected",
      "context": "html",
      "severity": "High",
      "payload": "<script onerror=alert(1)>",
      "verified": false
    }
  ]
}
```

### HTML (visual dashboard, cocok untuk presentasi)

```bash
python xscanner.py -u "https://target.com" --report-html laporan.html
```

### Markdown (cocok untuk laporan bug bounty)

```bash
python xscanner.py -u "https://target.com" --report-md laporan.md
```

### CSV (cocok untuk spreadsheet / tracking)

```bash
python xscanner.py -u "https://target.com" --report-csv laporan.csv
```

### SARIF (cocok untuk GitHub Code Scanning / CI/CD)

```bash
python xscanner.py -u "https://target.com" --report-sarif laporan.sarif
```

### Semua format sekaligus

```bash
python xscanner.py \
  -u "https://target.com" \
  -o laporan.json \
  --report-html laporan.html \
  --report-md laporan.md \
  --report-csv laporan.csv \
  --report-sarif laporan.sarif
```

---

## Testing di Lab Lokal

Sebelum testing ke target nyata, latih dulu di aplikasi rentan yang memang dibuat untuk belajar.

### DVWA (Damn Vulnerable Web Application)

```bash
# Install Docker terlebih dahulu, lalu:
docker run -d -p 8080:80 vulnerables/web-dvwa
```

Buka browser → `http://localhost:8080` → login dengan `admin` / `password` → set Security Level ke **Low**.

```bash
# Scan DVWA
python xscanner.py \
  -u "http://localhost:8080/vulnerabilities/xss_r/?name=test" \
  --no-crawl \
  --profile deep \
  --details \
  --report-html hasil_dvwa.html
```

### OWASP Juice Shop

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```

```bash
python xscanner.py \
  -u "http://localhost:3000" \
  --profile deep \
  --js-crawl \
  --report-html hasil_juiceshop.html
```

### bWAPP

```bash
docker run -d -p 80:80 raesene/bwapp
```

```bash
python xscanner.py \
  -u "http://localhost/bwapp/xss_get.php?firstname=test&lastname=test" \
  --no-crawl \
  --profile deep \
  --test-headers \
  --report-html hasil_bwapp.html
```

### WebGoat

```bash
docker run -d -p 8080:8080 webgoat/goat-and-wolf
```

```bash
python xscanner.py \
  -u "http://localhost:8080/WebGoat/" \
  --profile deep \
  --report-html hasil_webgoat.html
```

---

## Contoh Command Lengkap untuk Bug Bounty

```bash
# Langkah 1: Quick recon dulu
python xscanner.py \
  -u "https://target.com" \
  --profile fast \
  -o recon.json

# Langkah 2: Full scan jika recon ada temuan
python xscanner.py \
  -u "https://target.com" \
  --scope "target.com" "*.target.com" \
  --exclude-path "/logout" "/unsubscribe" \
  --login-url "https://target.com/login" \
  --username user_anda \
  --password password_anda \
  --profile deep \
  --test-headers \
  --test-hpp \
  --second-order \
  --js-crawl \
  --blind-callback "https://bxss.server-anda.com/cb" \
  --verify-headless \
  --report-html laporan_final.html \
  --report-md laporan_untuk_submission.md \
  --checkpoint \
  -o hasil_full.json

# Langkah 3: Verifikasi manual temuan sebelum submit ke program
```

---

## Seluruh Opsi CLI

```
-u, --url            Target URL (bisa diulang untuk multiple URL)
-l, --list           File teks berisi daftar URL target

--threads            Jumlah thread paralel [default: 10]
--timeout            Timeout per request dalam detik [default: 10]
--depth              Kedalaman crawling [default: 2]
--profile            Profil scan: fast | normal | deep | stealth
--deep               Shorthand untuk --profile deep
--no-crawl           Hanya test parameter di URL yang diberikan
--no-waf-bypass      Matikan teknik bypass WAF

-H, --header         Tambah custom header (bisa diulang)
-c, --cookie         Tambah cookie (bisa diulang)
--proxy              URL proxy, contoh: http://127.0.0.1:8080
--rate-limit         Jeda antar request dalam detik (0 = tanpa batas)

--login-url          URL halaman login untuk scan terautentikasi
--username           Username untuk login
--password           Password untuk login

--scope              Domain yang boleh di-scan (bisa diulang)
--exclude-scope      Domain yang tidak boleh di-scan (bisa diulang)
--exclude-path       Path yang dilewati, contoh: /logout (bisa diulang)

--test-headers       Test XSS via HTTP headers
--test-hpp           Test HTTP Parameter Pollution
--test-json          Test JSON API endpoint
--second-order       Track dan verifikasi stored/second-order XSS
--js-crawl           Ekstrak parameter dari file JavaScript (SPA)

--blind-callback     URL callback untuk blind XSS
--start-blind-server Jalankan listener blind XSS lokal di port 8765

--verify-headless    Verifikasi XSS di browser Chromium (butuh Playwright)

-o, --output         Path laporan JSON [default: xscanner_report.json]
--report-html        Path laporan HTML
--report-csv         Path laporan CSV
--report-md          Path laporan Markdown
--report-sarif       Path laporan SARIF (untuk CI/CD)

--checkpoint         Simpan progress dan lanjutkan jika scan terhenti
-v, --verbose        Tampilkan output lebih detail
--details            Tampilkan payload dan evidence per finding
-h, --help           Tampilkan bantuan
```

---

## FAQ

**Q: Scan saya berjalan lambat, bagaimana mempercepat?**

Gunakan profile `fast` dan tambah threads:
```bash
python xscanner.py -u "https://target.com" --profile fast --threads 20
```

**Q: Saya mendapat error "Connection refused" saat scan lokal**

Pastikan aplikasi lab sudah berjalan:
```bash
docker ps  # cek apakah container aktif
```

**Q: Apakah XScanner meninggalkan jejak di server target?**

Ya, seperti semua scanner. Selalu gunakan `--profile stealth` dan `--rate-limit` jika ingin meminimalkan noise di log server.

**Q: Payload apa yang paling sering berhasil?**

Tergantung context. XScanner otomatis memilih payload terbaik berdasarkan context yang terdeteksi. Untuk HTML context biasanya `<script onerror=alert(1)>`, untuk attribute context `" onmouseover="alert(1)"`, untuk JS string `';alert(1)//`.

**Q: Apakah XScanner bisa scan aplikasi React/Vue/Angular?**

Ya, gunakan `--js-crawl` untuk mengekstrak parameter dari file JavaScript SPA.

---

## Legal Notice

Tool ini disediakan **hanya untuk authorized security testing**.

- Dapatkan izin tertulis sebelum scan sistem apapun
- Patuhi scope program bug bounty yang Anda ikuti
- Penulis tidak bertanggung jawab atas penyalahgunaan
- Penggunaan tanpa izin adalah tindak pidana

---

*XScanner v3 · Python 3.11+ · 152,681,520 payload combinations · 136 tests passing*
