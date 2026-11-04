"""Decompile Next.js, Webpack, and Vite client build manifests into the full route tree."""

import json
import re
import urllib.parse
from typing import Any, Dict, List, Set, Tuple


NEXT_MANIFEST_PATHS = [
    "/_next/static/{buildId}/_buildManifest.js",
    "/_next/static/{buildId}/_ssgManifest.js",
    "/_next/static/{buildId}/_middlewareManifest.js",
    "/_next/static/{buildId}/_clientMiddlewareManifest.js",
]

VITE_MANIFEST_CANDIDATES = [
    "/.vite/manifest.json", "/assets/.vite/manifest.json",
    "/manifest.json", "/dist/manifest.json",
]

WEBPACK_RUNTIME_RE = re.compile(r"webpackJsonp|__webpack_require__\.u\s*=\s*function")
BUILD_ID_RE = re.compile(r'"buildId"\s*:\s*"([^"]+)"|/_next/static/([A-Za-z0-9_\-]+)/')
NEXT_ROUTE_RE = re.compile(r"\"(/[A-Za-z0-9_\-/\[\]]*)\"\s*:\s*\[")


def _get_build_id(ctx: Any) -> str:
    for page in ctx.pages[:5]:
        html = page.get("html", "")
        m = BUILD_ID_RE.search(html)
        if m:
            return m.group(1) or m.group(2)
    return ""


def extract_nextjs_routes(ctx: Any) -> Tuple[List[str], Set[str]]:
    """Fetch build manifests and extract every client-side route."""
    routes: Set[str] = set()
    manifest_urls: List[str] = []

    build_id = _get_build_id(ctx)
    if build_id:
        for tmpl in NEXT_MANIFEST_PATHS:
            manifest_urls.append(ctx.root + tmpl.format(buildId=build_id))

    for url in manifest_urls:
        r = ctx.http.fetch(url, follow=True)
        if r is None or r.status != 200:
            continue
        for m in NEXT_ROUTE_RE.finditer(r.text):
            route = m.group(1).rstrip("/") or "/"
            routes.add(route)
        # SSG manifest: JSON body with paths
        if "_ssgManifest" in url:
            try:
                data = json.loads(r.text)
                if isinstance(data, dict):
                    for k in data:
                        if isinstance(k, str) and k.startswith("/"):
                            routes.add(k)
            except Exception:
                pass

    return list(routes), set(manifest_urls)


def extract_vite_routes(ctx: Any) -> Tuple[List[str], Set[str]]:
    routes: Set[str] = set()
    fetched: Set[str] = set()
    for path in VITE_MANIFEST_CANDIDATES:
        url = ctx.root + path
        r = ctx.http.fetch(url, follow=True)
        if r is None or r.status != 200 or "json" not in r.content_type:
            continue
        try:
            data = json.loads(r.text)
        except Exception:
            continue
        fetched.add(url)
        # Vite manifest: { <input>: { file, src, ... } }
        for key, meta in data.items():
            if isinstance(key, str):
                routes.add(key if key.startswith("/") else "/" + key)
            if isinstance(meta, dict):
                for f in ("src", "file"):
                    v = meta.get(f)
                    if isinstance(v, str):
                        routes.add(v)
        break
    return list(routes), fetched


def extract_js_referenced_routes(ctx: Any) -> Tuple[List[str], Set[str]]:
    """Fallback: mine JS bundles for route-like strings."""
    routes: Set[str] = set()
    fetched: Set[str] = set()
    js_urls = [s for p in ctx.pages for s in p.get("scripts", []) if s.startswith("http")][:20]
    route_re = re.compile(r"""["'`](/(?:en/)?[a-z][A-Za-z0-9_\-/]{1,80})["'`]""")
    skip_exts = (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".map", ".json")
    for src in js_urls:
        r = ctx.http.fetch(src, follow=True)
        if r is None or r.status != 200:
            continue
        fetched.add(src)
        for m in route_re.finditer(r.text):
            path = m.group(1)
            if any(path.lower().endswith(e) for e in skip_exts):
                continue
            if "node_modules" in path or "/_next/static" in path:
                continue
            routes.add(path.rstrip("/") or "/")
    return list(routes), fetched


def extract_all(ctx: Any) -> Dict[str, Any]:
    next_routes, next_sources = extract_nextjs_routes(ctx)
    vite_routes, vite_sources = extract_vite_routes(ctx)
    js_routes, js_sources = extract_js_referenced_routes(ctx)

    all_routes = sorted(set(next_routes) | set(vite_routes) | set(js_routes))
    sources = sorted(next_sources | vite_sources | js_sources)

    return {
        "routes": all_routes,
        "sources": sources,
        "framework": (
            "nextjs" if next_sources
            else "vite" if vite_sources
            else "unknown"
        ),
        "count": len(all_routes),
    }
