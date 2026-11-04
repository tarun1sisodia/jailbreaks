"""
Web crawler, HTML/form extractor, and parameter point builder.
"""

import html
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

from webprobe.core.http import HttpClient, ensure_scheme, strip_fragment
from webprobe.core.logger import log
from webprobe.core.models import Point


LINK_RE = re.compile(r"""<a\b[^>]*?\bhref=["']([^"'#\s>]+)""", re.I)
SCRIPT_RE = re.compile(r"""<script\b[^>]*?\bsrc=["']([^"'\s>]+)""", re.I)
FORM_RE = re.compile(r"""<form\b([^>]*)>(.*?)</form>""", re.I | re.DOTALL)
ATTR_RE = re.compile(r"""\b([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*["']([^"']*)["']""", re.I)
INPUT_RE = re.compile(r"""<(?:input|textarea|select)\b([^>]*)>""", re.I)


def parse_page(html_text: str, base_url: str) -> Tuple[List[str], List[Dict[str, Any]], List[str]]:
    """
    Parse an HTML page and extract:
    - links: absolute URLs
    - forms: list of form dicts {action, method, enctype, inputs: {name: value}}
    - scripts: absolute URLs of script tags
    """
    links: List[str] = []
    scripts: List[str] = []
    forms: List[Dict[str, Any]] = []

    # Links
    for m in LINK_RE.finditer(html_text):
        raw_href = m.group(1).strip()
        if raw_href and not raw_href.lower().startswith(("javascript:", "mailto:", "tel:")):
            links.append(urllib.parse.urljoin(base_url, raw_href))

    # Scripts
    for m in SCRIPT_RE.finditer(html_text):
        raw_src = m.group(1).strip()
        if raw_src:
            scripts.append(urllib.parse.urljoin(base_url, raw_src))

    # Forms
    for fm in FORM_RE.finditer(html_text):
        form_attrs_raw, form_body = fm.group(1), fm.group(2)
        attrs = {k.lower(): html.unescape(v) for k, v in ATTR_RE.findall(form_attrs_raw)}
        action = attrs.get("action", "")
        resolved_action = urllib.parse.urljoin(base_url, action) if action else base_url
        method = attrs.get("method", "GET").upper()
        enctype = attrs.get("enctype", "application/x-www-form-urlencoded").lower()

        inputs: Dict[str, str] = {}
        for inp in INPUT_RE.finditer(form_body):
            inp_attrs = {k.lower(): html.unescape(v) for k, v in ATTR_RE.findall(inp.group(1))}
            name = inp_attrs.get("name")
            if name:
                inputs[name] = inp_attrs.get("value", "")

        forms.append({
            "action": resolved_action,
            "method": method,
            "enctype": enctype,
            "inputs": inputs,
            "attrs": attrs,
        })

    return list(dict.fromkeys(links)), forms, list(dict.fromkeys(scripts))


def crawl(
    http: HttpClient,
    start: str,
    extra_seeds: Optional[List[str]] = None,
    max_depth: int = 2,
    max_pages: int = 40,
    ctx: Optional[Any] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Bounded breadth-first web crawler:
    - Seeds from start URL and extra seeds (from robots/sitemap/wayback).
    - Extracts links, forms, and scripts.
    - Stays within the target domain/host.
    """
    start = strip_fragment(ensure_scheme(start))
    host = urllib.parse.urlsplit(start).netloc
    seen: Set[str] = set()
    queue: List[Tuple[str, int]] = [(start, 0)]

    for seed in (extra_seeds or []):
        seed = strip_fragment(ensure_scheme(seed))
        sp = urllib.parse.urlsplit(seed)
        if sp.netloc and sp.netloc != host:
            continue
        queue.append((seed, 0))

    discovered: Set[str] = {start}
    pages: List[Dict[str, Any]] = []

    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        if http.verbose:
            log(f"[crawl] {url}", dim=True)

        resp = http.fetch(url, follow=True)
        if resp is None:
            continue

        head = resp.text[:4000].lower()
        if "html" not in resp.content_type and "<html" not in head and "<form" not in head:
            continue

        links, forms, scripts = parse_page(resp.text, resp.url)
        pages.append({
            "url": url,
            "links": links,
            "forms": forms,
            "scripts": scripts,
            "html": resp.text,
        })

        if depth >= max_depth:
            continue

        for link in links:
            sp = urllib.parse.urlsplit(link)
            if sp.scheme not in ("http", "https") or sp.netloc != host:
                continue
            clean_link = strip_fragment(link)
            discovered.add(clean_link)
            if clean_link not in seen:
                queue.append((clean_link, depth + 1))

    # CDP headless crawl merge and manifest route extraction if ctx is provided
    if ctx is not None:
        args = getattr(ctx, "args", None)
        if getattr(args, "headless", False):
            try:
                from webprobe.core import cdp
                port = getattr(args, "cdp_port", 9222)
                if cdp.headless_available(port=port):
                    extra_pages = cdp.auto_crawl(ctx)
                    pages.extend(extra_pages)
            except Exception:
                pass
        try:
            from webprobe.core import manifest
            m_res = manifest.extract_all(ctx)
            for r in m_res.get("routes", []):
                full = urllib.parse.urljoin(start, r)
                discovered.add(full)
        except Exception:
            pass

    return pages, sorted(discovered)


def build_points(
    pages: List[Dict[str, Any]],
    discovered: List[str],
    max_points: int = 50,
) -> List[Point]:
    """
    Build injection points from crawled pages, forms, and discovered URLs.
    Extracts query parameters and form parameters with formfiller synthesis.
    """
    points: List[Point] = []
    seen: Set[Tuple[str, str, str]] = set()

    all_urls = list(dict.fromkeys([p["url"] for p in pages] + list(discovered)))

    # 1. Query parameters
    for u in all_urls:
        sp = urllib.parse.urlsplit(u)
        if not sp.query:
            continue
        qs = urllib.parse.parse_qs(sp.query, keep_blank_values=True)
        base = urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, "", ""))
        for param, values in qs.items():
            key = (base, "GET", param)
            if key not in seen:
                seen.add(key)
                val = values[0] if values else ""
                points.append(
                    Point(
                        url=base,
                        method="GET",
                        param=param,
                        param_type="query",
                        orig_value=val,
                    )
                )

    # 2. Form parameters
    for page in pages:
        for form in page.get("forms", []):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", {})
            try:
                from webprobe.core import formfiller
                filled = formfiller.fill_form(form)
            except Exception:
                filled = {}
            for param, val in inputs.items():
                synth_val = filled.get(param, val) or val
                key = (action, method, param)
                if key not in seen:
                    seen.add(key)
                    points.append(
                        Point(
                            url=action,
                            method=method,
                            param=param,
                            param_type="body" if method == "POST" else "query",
                            orig_value=synth_val,
                            form_meta=form,
                        )
                    )

    return points[:max_points]
