"""
utils/config.py
Global configuration, constants, and shared data structures.
"""

from dataclasses import dataclass, field
from typing import Optional


# ─── Scan Profiles ────────────────────────────────────────────────────────────

SCAN_PROFILES = {
    "fast":    {"depth": 1, "threads": 20, "timeout": 5,  "payloads_per_ctx": 10},
    "normal":  {"depth": 2, "threads": 10, "timeout": 10, "payloads_per_ctx": 30},
    "deep":    {"depth": 4, "threads":  5, "timeout": 20, "payloads_per_ctx": 80},
    "stealth": {"depth": 2, "threads":  2, "timeout": 15, "payloads_per_ctx": 25},
}


# ─── Injection Context Tags ────────────────────────────────────────────────────

class Context:
    HTML        = "html"
    ATTRIBUTE   = "attribute"
    JS          = "javascript"
    JS_STRING   = "js_string"
    JS_TEMPLATE = "js_template"
    URL         = "url"
    CSS         = "css"
    COMMENT     = "comment"
    SCRIPT_SRC  = "script_src"
    UNKNOWN     = "unknown"


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class ScanTarget:
    url:       str
    method:    str  = "GET"
    params:    dict = field(default_factory=dict)
    headers:   dict = field(default_factory=dict)
    cookies:   dict = field(default_factory=dict)
    data:      dict = field(default_factory=dict)
    context:   str  = Context.UNKNOWN
    param_key: str  = ""


@dataclass
class Finding:
    url:            str
    param:          str
    payload:        str
    context:        str
    xss_type:       str          # reflected | stored | dom
    evidence:       str
    waf_bypassed:   bool = False
    severity:       str  = "High"
    confidence:     str  = "High"
    encoding_used:  str  = "none"
    verified:       bool = False


@dataclass
class ScanConfig:
    # ── Core ────────────────────────────────────────────────────────────────
    targets:        list       = field(default_factory=list)
    threads:        int        = 10
    timeout:        int        = 10
    depth:          int        = 2
    profile:        str        = "normal"
    headers:        dict       = field(default_factory=dict)
    cookies:        dict       = field(default_factory=dict)
    proxy:          Optional[str] = None
    output:         str        = "report.json"
    crawl:          bool       = True
    deep:           bool       = False
    blind_callback: Optional[str] = None
    verify_headless:bool       = False
    waf_bypass:     bool       = True
    verbose:        bool       = False
    rate_limit:     float      = 0.0   # seconds between requests (0 = no limit)

    # ── Auth ─────────────────────────────────────────────────────────────────
    login_url:      Optional[str] = None
    username:       Optional[str] = None
    password:       Optional[str] = None

    # ── Scope ────────────────────────────────────────────────────────────────
    scope:          list       = field(default_factory=list)
    exclude_scope:  list       = field(default_factory=list)
    exclude_path:   list       = field(default_factory=list)

    # ── Extended test flags ──────────────────────────────────────────────────
    test_headers:   bool       = False   # inject XSS into HTTP headers
    test_hpp:       bool       = False   # HTTP parameter pollution
    test_json:      bool       = False   # JSON API endpoints
    second_order:   bool       = False   # track + verify stored/second-order XSS
    js_crawl:       bool       = False   # extract params from JavaScript files

    # ── Report formats ───────────────────────────────────────────────────────
    report_html:    Optional[str] = None
    report_csv:     Optional[str] = None
    report_md:      Optional[str] = None
    report_sarif:   Optional[str] = None

    # ── Checkpoint (save/resume) ─────────────────────────────────────────────
    checkpoint:     bool       = False


# ─── Common Headers ───────────────────────────────────────────────────────────

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
}


# ─── DOM Sink Patterns ────────────────────────────────────────────────────────

DOM_SINKS = [
    "document.write", "document.writeln", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "eval(", "setTimeout(", "setInterval(",
    "location.href", "location.replace", "location.assign",
    "window.location", "document.location", "document.URL",
    "document.referrer", "document.cookie", "window.name",
    "element.src", "element.action", "element.formAction",
    "execScript", "msSetImmediate",
]

DOM_SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.URL", "document.referrer", "window.name",
    "document.cookie", "localStorage", "sessionStorage",
    "postMessage", "URLSearchParams",
]


# ─── WAF Fingerprints ─────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare":    ["cloudflare", "cf-ray", "__cfduid"],
    "ModSecurity":   ["mod_security", "modsecurity", "NOYB"],
    "Akamai":        ["akamai", "ak_bmsc", "AkamaiGHost"],
    "Imperva":       ["imperva", "incap_ses", "_incap_"],
    "F5 BIG-IP":     ["BigIP", "F5", "TS0"],
    "Sucuri":        ["sucuri", "x-sucuri-id"],
    "AWS WAF":       ["awswaf", "x-amzn-requestid"],
    "Barracuda":     ["barracuda_", "barra_counter_session"],
    "Wordfence":     ["wordfence"],
    "Nginx":         ["nginx"],
}
