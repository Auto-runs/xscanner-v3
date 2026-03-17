"""
cli/interface.py
Command-line interface for XScanner.
"""

import asyncio
import time
import sys
import os
from typing import Optional

import click
from rich.console import Console

from utils.config import ScanConfig
from utils.logger import banner, info, warn, error, success, set_verbose, section
from scanner.engine import ScanEngine
from reports.reporter import Reporter

console = Console()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("-u", "--url",       multiple=True, help="Target URL(s). Can specify multiple: -u url1 -u url2")
@click.option("-l", "--list",      "url_file",    type=click.Path(exists=True), help="File with target URLs (one per line)")
@click.option("--threads",         default=10,    show_default=True, help="Concurrent threads")
@click.option("--timeout",         default=10,    show_default=True, help="Request timeout in seconds")
@click.option("--depth",           default=2,     show_default=True, help="Crawl depth")
@click.option("--profile",         default="normal", type=click.Choice(["fast","normal","deep","stealth"]), show_default=True)
@click.option("--deep",            is_flag=True,  help="Shorthand for --profile deep")
@click.option("--no-crawl",        is_flag=True,  help="Don't crawl — only test provided URL params")
@click.option("--no-waf-bypass",   is_flag=True,  help="Disable WAF evasion techniques")
@click.option("-H", "--header",    multiple=True, help="Custom header(s): 'Name: Value'")
@click.option("-c", "--cookie",    multiple=True, help="Cookie(s): 'name=value'")
@click.option("--proxy",           default=None,  help="Proxy URL: http://127.0.0.1:8080")
@click.option("--rate-limit",      default=0.0,   help="Seconds between requests (0 = unlimited)")
@click.option("--blind-callback",  default=None,  help="Blind XSS callback URL (e.g. http://your-server.com/xss)")
@click.option("--start-blind-server", is_flag=True, help="Start local blind XSS listener on port 8765")
@click.option("-o", "--output",    default="xscanner_report.json", show_default=True, help="JSON report output path")
@click.option("-v", "--verbose",   is_flag=True,  help="Verbose output")
@click.option("--details",         is_flag=True,  help="Print full payload + evidence for each finding")
def main(
    url, url_file, threads, timeout, depth, profile, deep, no_crawl,
    no_waf_bypass, header, cookie, proxy, rate_limit,
    blind_callback, start_blind_server, output, verbose, details,
    login_url, username, password, scope, exclude_scope,
    test_headers, test_hpp, test_json, second_order, js_crawl,
    report_html, report_csv, report_md, report_sarif,
    checkpoint, exclude_path,
):
    """
    \b
    XScanner — Next-Generation XSS Detection Framework
    ────────────────────────────────────────────────────
    ⚠ For authorized penetration testing ONLY.
    Usage on systems without explicit permission is illegal.

    \b
    Examples:
      python xscanner.py -u "https://example.com/search?q=test"
      python xscanner.py -u "https://site.com" --deep --threads 5
      python xscanner.py -l targets.txt --profile stealth --proxy http://127.0.0.1:8080
      python xscanner.py -u "https://site.com" --blind-callback "http://your.server.com/cb"
    """
    banner()

    # ─── Collect targets ─────────────────────────────────────────────────────
    targets = list(url)
    if url_file:
        with open(url_file) as f:
            targets += [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not targets:
        error("No targets specified. Use -u <url> or -l <file>")
        sys.exit(1)

    # ─── Parse headers ───────────────────────────────────────────────────────
    parsed_headers = {}
    for h in header:
        if ":" in h:
            k, v = h.split(":", 1)
            parsed_headers[k.strip()] = v.strip()

    # ─── Parse cookies ───────────────────────────────────────────────────────
    parsed_cookies = {}
    for c in cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            parsed_cookies[k.strip()] = v.strip()

    # ─── Build config ────────────────────────────────────────────────────────
    if deep:
        profile = "deep"

    config = ScanConfig(
        targets         = targets,
        threads         = threads,
        timeout         = timeout,
        depth           = depth,
        profile         = profile,
        headers         = parsed_headers,
        cookies         = parsed_cookies,
        proxy           = proxy,
        output          = output,
        crawl           = not no_crawl,
        deep            = deep,
        blind_callback  = blind_callback,
        waf_bypass      = not no_waf_bypass,
        verbose         = verbose,
        rate_limit      = rate_limit,
    )

    set_verbose(verbose)

    # ─── Print scan config ───────────────────────────────────────────────────
    section("Scan Configuration")
    info(f"Targets:     {len(targets)}")
    info(f"Profile:     {profile}")
    info(f"Threads:     {threads}")
    info(f"Crawl depth: {depth}")
    info(f"WAF bypass:  {'Enabled' if config.waf_bypass else 'Disabled'}")
    if proxy:
        info(f"Proxy:       {proxy}")
    if blind_callback:
        info(f"Blind XSS:   {blind_callback}")

    # ─── Run ─────────────────────────────────────────────────────────────────
    asyncio.run(_run(config, output, details, start_blind_server,
                    login_url=login_url, username=username, password=password,
                    scope=list(scope), exclude_scope=list(exclude_scope),
                    test_headers=test_headers, test_hpp=test_hpp, test_json=test_json,
                    second_order=second_order, js_crawl=js_crawl,
                    report_html=report_html, report_csv=report_csv,
                    report_md=report_md, report_sarif=report_sarif,
                    checkpoint=checkpoint, exclude_path=list(exclude_path)))


async def _run(
    config: ScanConfig, output: str, print_details: bool, blind_server: bool,
    login_url=None, username=None, password=None,
    scope=None, exclude_scope=None,
    test_headers=False, test_hpp=False, test_json=False,
    second_order=False, js_crawl=False,
    report_html=None, report_csv=None, report_md=None, report_sarif=None,
    checkpoint=False, exclude_path=None,
):
    from scanner.engine_v2 import ScanEngineV2 as ScanEngine
    from scanner.blind_server import BlindXSSServer

    # Optionally start blind XSS listener
    bserver = None
    if blind_server:
        bserver = BlindXSSServer(port=8765)
        await bserver.start()
        if not config.blind_callback:
            config.blind_callback = "http://127.0.0.1:8765"

    section("Scanning")
    engine = ScanEngine(config)
    start  = time.monotonic()

    try:
        findings = await engine.run()
    finally:
        await engine.close()
        if bserver:
            await bserver.stop()

    elapsed = time.monotonic() - start

    # ─── Report ──────────────────────────────────────────────────────────────
    section("Results")
    reporter = Reporter(findings, config.targets, elapsed)
    reporter.print_summary()

    if print_details and findings:
        reporter.print_finding_details()

    saved = reporter.save_json(output)
    success(f"Report saved → {saved}")
