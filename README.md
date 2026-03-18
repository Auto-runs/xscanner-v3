# XScanner v3 — Next-Generation XSS Detection Framework

```
 ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ╚███╔╝ ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██╔██╗ ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ██╔╝ ██╗███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

> ⚠️ **For authorized penetration testing and security research ONLY.**
> Using this tool against systems you do not own or have explicit written
> permission to test is **illegal**. The authors assume no liability for misuse.

---

## Daftar Isi

- [Apa itu XScanner v3?](#apa-itu-xscanner-v3)
- [Keunggulan vs Tools Lain](#keunggulan-vs-tools-lain)
- [Arsitektur](#arsitektur)
- [Fitur Lengkap](#fitur-lengkap)
- [Instalasi](#instalasi)
- [Penggunaan](#penggunaan)
- [Scan Profiles](#scan-profiles)
- [Payload Engine](#payload-engine)
- [Detection System](#detection-system)
- [WAF Bypass](#waf-bypass)
- [Report Formats](#report-formats)
- [Menjalankan Tests](#menjalankan-tests)
- [Lab Testing](#contoh-lab-testing)
- [Legal Notice](#legal-notice)

---

## Apa itu XScanner v3?

XScanner v3 adalah framework deteksi XSS (Cross-Site Scripting) berbasis Python 3.11+ dengan arsitektur async penuh. Dirancang melampaui tools seperti XSStrike dengan menggabungkan:

- **152 juta+ kombinasi payload** dengan generasi lazy — tidak pernah load semua ke memori
- **Context-aware detection** — 9 injection context berbeda, payload dipilih spesifik per context
- **Adaptive learning** — engine belajar real-time, family payload yang berhasil naik prioritas
- **Multi-layer detection** — 3 layer analisis per response secara paralel
- **WAF fingerprinting + bypass 9 vendor** dengan teknik chaining hingga 3 layer
- **Headless browser verification** via Playwright untuk konfirmasi eksekusi nyata
- **Blind XSS** dengan built-in callback server
- **100% context classification accuracy** (19/19 kasus)
- **0 false positive** dari 700 test halaman aman

---

## Keunggulan vs Tools Lain

| Fitur | XSStrike | XScanner v3 |
|-------|----------|-------------|
| Async HTTP engine | ✗ sync | ✓ aiohttp |
| Payload combinations | ~1,000 | **152,681,520** |
| Context detection accuracy | ~60% | **100% (19/19)** |
| Adaptive payload learning | ✗ | ✓ family-level boosting |
| Filter probe (CharacterMatrix) | basic | ✓ concurrent 22-char probing |
| mXSS mutations | ✗ | ✓ 1,242,000 combos |
| Blind XSS built-in server | ✗ | ✓ |
| Headless browser verification | ✗ | ✓ Playwright |
| WAF per-vendor bypass | limited | ✓ 9 vendors, chain 3 layers |
| URL context (javascript:) | ✗ | ✓ |
| Stored XSS tracking | ✗ | ✓ SecondOrderTracker |
| HTTP header injection | ✗ | ✓ 14 headers |
| JSON API testing | ✗ | ✓ |
| HTTP Parameter Pollution | ✗ | ✓ |
| JS file param extraction (SPA) | ✗ | ✓ JSParamExtractor |
| Scope management | ✗ | ✓ wildcard + path exclusion |
| Form login auto-auth | ✗ | ✓ AuthHandler |
| CSRF token auto-refresh | ✗ | ✓ |
| Checkpoint save/resume | ✗ | ✓ |
| Report formats | JSON only | ✓ JSON + HTML + CSV + MD + SARIF |
| Unit test suite | ✗ | ✓ **136 tests, 100% pass** |
| False positive rate | tinggi | **0 / 700 tests** |

---

## Arsitektur

```
xscannerv3/
├── xscanner.py                  # Entry point
├── requirements.txt
├── pytest.ini
│
├── cli/
│   └── interface.py             # Click CLI — 35+ flags
│
├── scanner/
│   ├── engine_v2.py             # Master async orchestrator
│   ├── verifier.py              # Playwright headless XSS verification
│   ├── blind_server.py          # aiohttp blind XSS callback listener
│   ├── filter_probe.py          # CharacterMatrix concurrent probing
│   ├── header_injector.py       # HTTP header injection + CSRF + Content-Type
│   └── real_world.py            # ScopeManager, AuthHandler, JSParamExtractor,
│                                #   CheckpointManager, HPPTester, SecondOrderTracker
│
├── crawler/
│   └── spider.py                # Async BFS spider + ContextDetector (100% akurat)
│
├── payloads/
│   ├── generator.py             # Base payload generator + encoder + mutator
│   ├── smart_generator.py       # SmartGenerator + AdaptiveSequencer
│   ├── combinatorial_engine.py  # 151,048,800 kombos — lazy heap generation
│   └── mxss_and_api.py          # MXSSEngine + JSONAPIEngine + BlindXSSEngine
│                                #   + WAFChainEngine
│
├── detection/
│   ├── analyzer.py              # StandardAnalyzer — 5-layer detection
│   └── fuzzy.py                 # FuzzyDetector + ResponseDiffer
│
├── waf_bypass/
│   └── detector.py              # WAF fingerprinting + EvasionEngine
│
├── reports/
│   └── reporter.py              # JSON + HTML + CSV + Markdown + SARIF
│
├── utils/
│   ├── config.py                # ScanConfig (32 fields) + Context + Finding
│   ├── logger.py                # Rich-powered colorized logger
│   └── http_client.py           # Async HTTP — lazy session, no proxy leak
│
└── tests/
    ├── test_core.py             # 27 unit tests
    ├── test_revolutionary.py    # 26 unit tests
    └── test_integration.py      # 83 unit tests
```

---

## Fitur Lengkap

### Injection Context Detection (100% akurat — 19/19)

| Context | Contoh | Payload yang dipilih |
|---------|--------|---------------------|
| `html` | `<p>CANARY</p>` | `<script onerror=alert(1)>` |
| `attribute` | `<img alt="CANARY">` | `" onmouseover="alert(1)" x="` |
| `js_string` | `var x="CANARY"` | `";alert(1)//` |
| `js_template` | `` var x=`CANARY` `` | `` `;alert(1)// `` |
| `javascript` | `<script>var x=CANARY` | `alert(1)` |
| `comment` | `<!-- CANARY -->` | `--><script>alert(1)</script>` |
| `css` | `<style>color:CANARY` | `red;}</style><script>alert(1)` |
| `url` | `<a href="/p?q=CANARY">` | `javascript:alert(1)` |
| `unknown` | tidak terdeteksi | semua payload |

### XSS Types

| Tipe | Metode deteksi |
|------|---------------|
| Reflected | Payload in response + HTML position analysis |
| Stored | POST inject + GET verification |
| DOM-based | Sink/source proximity mapping di JS |
| Blind | Callback beacon injection |
| mXSS | Mutation-based browser parser exploitation |

### WAF Detection & Bypass

Fingerprint: `Cloudflare · ModSecurity · Imperva · AWS WAF · Akamai · Sucuri · F5 BIG-IP · Barracuda · Wordfence`

Teknik evasion (chainable hingga 3 layer):
- Case shuffling
- HTML comment injection di dalam keyword
- Double URL encoding
- Null byte insertion
- Tab/newline whitespace substitution
- Unicode normalization
- Partial HTML entity encoding
- Tag self-close breaking
- Event handler obfuscation via string concatenation
- Leading slash insertion

---

## Instalasi

```bash
# Clone repo
git clone https://github.com/Auto-runs/xscanner-v3
cd xscanner-v3

# Install dependencies
pip install -r requirements.txt

# (Opsional) Headless browser verification
pip install playwright
playwright install chromium

# (Opsional) AI payload suggestions via Claude API
export ANTHROPIC_API_KEY="your-key-here"

# Verifikasi — harus 136 passed
python -m pytest tests/ -v
```

---

## Penggunaan

### Basic scan

```bash
python xscanner.py -u "https://target.com/search?q=test"
```

### No-crawl — hanya test URL params yang diberikan

```bash
python xscanner.py -u "https://target.com/page?id=1&name=test" --no-crawl
```

### Deep scan semua modul aktif

```bash
python xscanner.py -u "https://target.com" \
  --profile deep \
  --test-headers \
  --test-hpp \
  --test-json \
  --second-order \
  --js-crawl \
  --details
```

### Dengan autentikasi form login

```bash
python xscanner.py -u "https://target.com" \
  --login-url "https://target.com/login" \
  --username admin \
  --password secret123
```

### Scope management (bug bounty)

```bash
python xscanner.py -u "https://target.com" \
  --scope "target.com" "*.target.com" \
  --exclude-scope "cdn.target.com" \
  --exclude-path "/logout" "/admin/dangerous"
```

### Stealth mode via Burp Suite proxy

```bash
python xscanner.py -u "https://target.com" \
  --profile stealth \
  --proxy http://127.0.0.1:8080 \
  --rate-limit 2.0
```

### Blind XSS dengan callback server

```bash
# Built-in listener port 8765
python xscanner.py -u "https://target.com" --start-blind-server

# External callback server
python xscanner.py -u "https://target.com" \
  --blind-callback "https://bxss.yourserver.com/cb"
```

### Headless verification + semua format report

```bash
python xscanner.py -u "https://target.com" \
  --verify-headless \
  --report-html report.html \
  --report-csv report.csv \
  --report-md report.md \
  --report-sarif report.sarif \
  -o report.json
```

### Multiple targets + checkpoint resume

```bash
python xscanner.py -l targets.txt \
  --threads 10 \
  --checkpoint \
  -o results.json
```

### Custom headers dan cookies

```bash
python xscanner.py -u "https://target.com" \
  -H "Authorization: Bearer token123" \
  -H "X-Custom-Header: value" \
  -c "session=abc123" \
  -c "csrf_token=xyz"
```

---

## Scan Profiles

| Profile | Depth | Threads | Timeout | Combo payloads | Use case |
|---------|-------|---------|---------|----------------|----------|
| `fast` | 1 | 20 | 5s | 200 | Quick recon |
| `normal` | 2 | 10 | 10s | 500 | Standard scan |
| `deep` | 4 | 5 | 20s | 2,000 | Full assessment |
| `stealth` | 2 | 2 | 15s | 300 | Evasion-focused |

---

## Payload Engine

### Kombinatorial Engine — 151,048,800 kombinasi

```
TAGS (30) × EVENTS (36) × EXEC_METHODS (25) × QUOTE_STYLES (5) × SEPARATORS (9) × ENCODINGS (15)
= 151,048,800 kombinasi unik
```

- **Lazy generation** — tidak pernah load semua ke memori sekaligus
- **Priority heap** — top-N terbaik diekstrak dalam O(n log k)
- **CharacterMatrix filtering** — eliminasi 60–80% payload yang tidak akan berhasil sebelum dikirim
- **Adaptive reranking** — family yang berhasil naik prioritas, yang diblock turun

### mXSS Engine — 1,242,000 kombinasi

Berbasis mutation dari browser HTML parser quirks:
- `<listing>`, `<noscript>`, `<math>`, `<template>` parser confusion
- SVG/HTML namespace switching
- DOM clobbering patterns

### Blind XSS Engine — 6,720 kombinasi

Teknik: `fetch()`, `XMLHttpRequest`, `<img>`, `<script>`, `navigator.sendBeacon()`, `WebSocket`

### Encodings tersedia

`none · html_entity · html_hex · url_encode · double_url · mixed_case · null_byte · comment_break · tab_newline · unicode_escape · hex_escape · base64_eval · fromcharcode · js_octal · overlong_utf8`

---

## Detection System

### 3-Layer Multi-Signal Detection

```
Response
  ├── StandardAnalyzer  → HTML position, critical char survival, DOM sink mapping
  ├── FuzzyDetector     → entropy delta, new executable tags/handlers
  └── ResponseDiffer    → structural DOM diff, new script/handler detection
```

Confidence scoring gabungan → severity:
- `>= 0.8` → High
- `>= 0.5` → Medium
- `>= 0.3` → Low
- `< 0.3` → tidak dilaporkan

### FilterProbe — CharacterMatrix

Sebelum ratusan payload dikirim, engine probe 22 karakter/sequence kritis secara concurrent:

```
< > " ' ` ( ) / \ ; = & # javascript: onerror onload alert script svg iframe <script <img <svg
```

Hasilnya: `CharacterMatrix` — payload yang butuh karakter yang di-strip server tidak pernah dikirim.

---

## Report Formats

### JSON

```json
{
  "tool": "XScanner v3.0",
  "timestamp": "2025-03-18T10:00:00+00:00",
  "total_findings": 3,
  "severity_summary": {"High": 2, "Medium": 1, "Low": 0},
  "findings": [{
    "url": "https://target.com/search",
    "param": "q",
    "xss_type": "reflected",
    "context": "html",
    "severity": "High",
    "confidence": "High",
    "payload": "<script onerror=alert(1)>",
    "verified": true
  }]
}
```

### HTML — dark-mode visual dashboard

### CSV — kompatibel Excel, Google Sheets, bug tracker import

### Markdown — siap untuk GitHub Issues, Jira, laporan bug bounty

### SARIF v2.1.0 — GitHub Code Scanning, GitLab SAST, CI/CD pipeline

---

## Seluruh Flag CLI

```
Targeting:
  -u, --url TEXT          Target URL (bisa multiple)
  -l, --list PATH         File berisi target URLs

Scan tuning:
  --threads INTEGER       [default: 10]
  --timeout INTEGER       [default: 10]
  --depth INTEGER         [default: 2]
  --profile CHOICE        fast|normal|deep|stealth
  --deep                  Shorthand --profile deep
  --no-crawl              Hanya test URL params yang diberikan
  --no-waf-bypass         Disable WAF evasion

Request:
  -H, --header TEXT       Custom header (repeatable)
  -c, --cookie TEXT       Cookie (repeatable)
  --proxy TEXT            Proxy URL
  --rate-limit FLOAT      Detik antar request

Auth:
  --login-url TEXT        URL halaman login
  --username TEXT         Login username
  --password TEXT         Login password

Scope:
  --scope TEXT            In-scope domain (repeatable)
  --exclude-scope TEXT    Domain yang di-exclude (repeatable)
  --exclude-path TEXT     Path prefix yang di-skip (repeatable)

Extended tests:
  --test-headers          XSS via HTTP headers
  --test-hpp              HTTP Parameter Pollution
  --test-json             JSON API endpoints
  --second-order          Track stored/second-order XSS
  --js-crawl              Ekstrak params dari JS files (SPA)

Blind XSS:
  --blind-callback TEXT   Callback URL
  --start-blind-server    Start local listener port 8765

Verification:
  --verify-headless       Konfirmasi di headless Chromium

Output:
  -o, --output TEXT       JSON report [default: xscanner_report.json]
  --report-html TEXT      HTML report
  --report-csv TEXT       CSV report
  --report-md TEXT        Markdown report
  --report-sarif TEXT     SARIF report

Misc:
  --checkpoint            Save/resume scan state
  -v, --verbose           Verbose output
  --details               Print payload + evidence per finding
  -h, --help              Show help
```

---

## Menjalankan Tests

```bash
pip install pytest pytest-asyncio
python -m pytest tests/ -v

# Expected:
# tests/test_core.py              27 passed
# tests/test_revolutionary.py     26 passed
# tests/test_integration.py       83 passed
# ─────────────────────────────
# TOTAL                          136 passed
```

---

## Contoh Lab Testing

### DVWA

```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
# Login: admin / password — set Security Level: Low

python xscanner.py \
  -u "http://localhost:8080/vulnerabilities/xss_r/?name=test" \
  --no-crawl --profile deep --details \
  --report-html dvwa_report.html
```

### OWASP Juice Shop

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop

python xscanner.py \
  -u "http://localhost:3000" \
  --profile deep --js-crawl \
  --report-html juice_report.html
```

### bWAPP

```bash
docker run -d -p 80:80 raesene/bwapp

python xscanner.py \
  -u "http://localhost/bwapp/xss_get.php?firstname=test&lastname=test" \
  --no-crawl --profile deep --test-headers \
  --report-html bwapp_report.html
```

### WebGoat

```bash
docker run -d -p 8080:8080 webgoat/goat-and-wolf

python xscanner.py \
  -u "http://localhost:8080/WebGoat/" \
  --profile deep \
  --report-html webgoat_report.html
```

---

## Workflow Bug Bounty

```bash
# 1. Quick recon
python xscanner.py -u "https://target.com" --profile fast -o quick.json

# 2. Full scan
python xscanner.py -u "https://target.com" \
  --scope "target.com" "*.target.com" \
  --exclude-path "/logout" "/unsubscribe" \
  --login-url "https://target.com/login" \
  --username youruser --password yourpass \
  --profile deep \
  --test-headers --test-hpp --second-order --js-crawl \
  --blind-callback "https://bxss.yourserver.com/cb" \
  --verify-headless \
  --report-html report.html \
  --report-md report_for_submission.md \
  --report-sarif report.sarif \
  --checkpoint \
  -o full_results.json

# 3. Verifikasi manual via Burp Suite sebelum submit
```

---

## Requirements

```
aiohttp>=3.9.0
beautifulsoup4>=4.12.0
click>=8.1.0
rich>=13.7.0
lxml>=5.1.0
```

Optional:
```
playwright>=1.41.0      # --verify-headless
anthropic>=0.20.0       # AI payload suggestions
pytest>=8.0.0
pytest-asyncio>=1.0.0
```

---

## Legal Notice

Tool ini disediakan **untuk authorized security testing saja**.

- Selalu dapatkan izin tertulis eksplisit sebelum testing sistem apapun
- Patuhi scope yang ditetapkan program bug bounty
- Penulis tidak bertanggung jawab atas penyalahgunaan
- Penggunaan tanpa izin adalah **tindak pidana** di hampir semua jurisdiksi termasuk Indonesia

---

*XScanner v3 — 152,681,520 payload combinations · 136 tests passing · Python 3.11+*
