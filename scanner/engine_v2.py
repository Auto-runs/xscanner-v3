"""
scanner/engine_v2.py — Revolutionary Scan Engine with Combinatorial Payload Space
"""

import asyncio
import copy
from typing import List, Optional, Dict

from utils.config import ScanConfig, ScanTarget, Finding, Context, SCAN_PROFILES
from utils.http_client import HttpClient
from utils.logger import debug, info, progress, finding as log_finding, warn, success
from crawler.spider import Spider, ContextDetector
from payloads.generator import PayloadGenerator
from payloads.smart_generator import SmartGenerator, AdaptiveSequencer
from payloads.combinatorial_engine import CombinatorialEngine
from detection.analyzer import DetectionEngine
from detection.fuzzy import FuzzyDetector, ResponseDiffer
from waf_bypass.detector import WAFDetector, EvasionEngine
from scanner.filter_probe import FilterProbe, SmartPayloadFilter

COMBO_TOP_N = {"fast": 200, "normal": 500, "deep": 2000, "stealth": 300}


class ScanEngineV2:
    def __init__(self, config: ScanConfig):
        self.config   = config
        self.http     = HttpClient(config)
        self._profile = SCAN_PROFILES.get(config.profile, SCAN_PROFILES["normal"])
        self.findings: List[Finding] = []
        self._lock    = asyncio.Lock()
        self._stats   = {"requests_sent": 0, "requests_saved": 0,
                         "payloads_tested": 0, "combo_space": 0}

        self.payload_gen  = PayloadGenerator(
            max_per_ctx=self._profile["payloads_per_ctx"], waf_bypass=config.waf_bypass)
        self.smart_gen    = SmartGenerator(max_payloads=self._profile["payloads_per_ctx"])
        self.combo_engine = CombinatorialEngine()
        self.detector     = DetectionEngine()
        self.fuzzy        = FuzzyDetector()
        self.differ       = ResponseDiffer()
        self.evasion      = EvasionEngine()
        self.ctx_detector = ContextDetector()
        self.waf_detector = WAFDetector()
        self.filter_probe = FilterProbe(self.http)
        self.smart_filter = SmartPayloadFilter()
        self.sequencer    = AdaptiveSequencer()
        self._waf_cache: Dict[str, Optional[str]] = {}

        stats = self.combo_engine.stats()
        info(f"CombinatorialEngine: {stats['total_combinations']:,} combinations available")

    async def run(self) -> List[Finding]:
        await asyncio.gather(*[self._scan_url(u) for u in self.config.targets],
                             return_exceptions=True)
        self._print_stats()
        return self.findings

    async def _scan_url(self, url: str):
        info(f"Scanning: {url}")
        targets = await Spider(self.config, self.http).crawl(url) \
                  if self.config.crawl else self._url_to_targets(url)
        if not targets:
            warn(f"No injection points: {url}"); return

        info(f"Found {len(targets)} injection points")
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        if host not in self._waf_cache:
            r = await self.http.get(url)
            self._waf_cache[host] = self.waf_detector.detect(r)
            if self._waf_cache[host]:
                warn(f"WAF: {self._waf_cache[host]}")

        waf = self._waf_cache.get(host)
        sem = asyncio.Semaphore(self.config.threads)
        await asyncio.gather(*[self._scan_one_sem(t, sem, waf) for t in targets],
                             return_exceptions=True)

    async def _scan_one_sem(self, t, sem, waf):
        async with sem:
            await self._scan_one(t, waf)

    async def _scan_one(self, target: ScanTarget, waf: Optional[str] = None):
        context = await self.ctx_detector.detect(target, self.http)
        target.context = context

        baseline_resp = await self._send(target)
        if baseline_resp is None: return
        baseline_body = baseline_resp.text

        matrix = await self.filter_probe.analyze(target)
        self._stats["combo_space"] = self.combo_engine.total

        top_n = COMBO_TOP_N.get(self.config.profile, 500)
        info(f"Generating top-{top_n} from {self.combo_engine.total:,} combos [param={target.param_key}]")

        combo_payloads = self.combo_engine.generate(
            context=context, matrix=matrix if matrix.exploitable else None, top_n=top_n)
        combo_list = [(p, label) for p, score, label in combo_payloads]

        smart_list    = [(p, l) for p, l, _ in self.smart_gen.generate(matrix, context)] \
                        if matrix.exploitable else []
        standard_list = self.payload_gen.for_context(context)

        if matrix.exploitable:
            scored = self.smart_filter.filter_payloads(standard_list, matrix)
            standard_list = [(p, e) for p, e, _ in scored]

        blind_list   = self.payload_gen.for_blind_xss(self.config.blind_callback) \
                       if self.config.blind_callback else []
        evasion_list = []
        if waf and self.config.waf_bypass:
            for p, enc in combo_list[:20]:
                evasion_list += [(ep, f"evasion:{t}") for ep, t in self.evasion.apply(p, waf)]

        all_payloads = combo_list + smart_list + standard_list + evasion_list + blind_list
        ranked = self.sequencer.rerank([(p, e, 1.0) for p, e in all_payloads])
        all_payloads = [(p, e) for p, e, _ in ranked]

        info(f"Testing {len(all_payloads):,} payloads on '{target.param_key}'")

        found = False
        for payload, encoding in all_payloads:
            if found and "blind" not in encoding and "evasion" not in encoding:
                continue
            result = await self._test_payload(target, payload, encoding, context, waf, baseline_body)
            self._stats["payloads_tested"] += 1
            self._stats["requests_sent"]   += 1
            self.sequencer.feedback(payload, encoding, result)
            if result and result.get("reflected"):
                found = True

    async def _test_payload(self, target, payload, encoding, context, waf, baseline_body):
        injected = self._inject(target, payload)
        resp = await self._send(injected)
        if resp is None: return None
        if self.waf_detector.is_blocked(len(baseline_body), len(resp.text), resp.status):
            return None

        standard     = self.detector.analyze(payload, resp.text, context, waf is not None)
        fuzzy_result = self.fuzzy.analyze(payload, baseline_body, resp.text)
        diff         = self.differ.diff(baseline_body, resp.text)

        reflected = (standard is not None) or fuzzy_result["reflected"] or diff["suspicious"]
        if not reflected: return None

        scores = []
        if standard:
            scores.append({"High": 0.9, "Medium": 0.6, "Low": 0.3}.get(
                standard.get("confidence", "Low"), 0.3))
        if fuzzy_result["reflected"]: scores.append(fuzzy_result["confidence"])
        if diff["suspicious"]: scores.append(0.5)

        final_conf = max(scores) if scores else 0.0
        if final_conf < 0.3: return None

        severity   = "High" if final_conf >= 0.8 else "Medium" if final_conf >= 0.5 else "Low"
        evidence   = (standard or {}).get("evidence", "") or \
                     (f"new_tags={fuzzy_result['new_tags']}" if fuzzy_result.get("new_tags") else "") or \
                     resp.text[100:300]
        xss_type   = "dom" if (standard and standard.get("dom_vuln") and not standard.get("executable")) \
                     else "stored" if target.method == "POST" else "reflected"

        f = Finding(url=target.url, param=target.param_key, payload=payload,
                    context=context, xss_type=xss_type, evidence=evidence[:300],
                    waf_bypassed=waf is not None, severity=severity,
                    confidence=severity, encoding_used=encoding)

        async with self._lock:
            if not any(e.url == f.url and e.param == f.param and e.context == f.context
                       for e in self.findings):
                self.findings.append(f)
                log_finding(f.url, f.param, f.payload, f.xss_type, f.context)

        return {"reflected": True, "confidence": final_conf}

    def _inject(self, target, payload):
        t = copy.deepcopy(target)
        if t.method == "GET": t.params[t.param_key] = payload
        else: t.data[t.param_key] = payload
        return t

    async def _send(self, target):
        if target.method == "GET":
            return await self.http.get(target.url, params=target.params)
        return await self.http.post(target.url, data=target.data)

    def _url_to_targets(self, url):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params: return []
        base = {k: v[0] for k, v in params.items()}
        return [ScanTarget(url=url, method="GET", params=base.copy(), param_key=k) for k in params]

    def _print_stats(self):
        sent  = self._stats["requests_sent"]
        saved = self._stats["requests_saved"]
        total = sent + saved
        pct   = (saved / total * 100) if total > 0 else 0
        info(f"Stats: {sent:,} sent | {saved:,} saved ({pct:.0f}% reduction) | "
             f"combo space: {self._stats['combo_space']:,}")

    async def close(self):
        await self.http.close()
