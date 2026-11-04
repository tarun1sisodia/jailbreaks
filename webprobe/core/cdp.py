"""Minimal Chrome DevTools Protocol client. Talks to Chrome via --remote-debugging-port.

Zero external dependencies: implements a bare WebSocket client on stdlib sockets.

Usage:
    chrome --remote-debugging-port=9222 --headless=new about:blank &
    cdp = CDP(port=9222).connect()
    html = cdp.navigate_and_extract(url)
"""

import base64
import hashlib
import json
import os
import socket
import struct
import time
import urllib.request
from typing import Any, Dict, List, Optional


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class CDPError(Exception):
    pass


class _WSClient:
    """Bare WebSocket client sufficient for CDP JSON-RPC."""

    def __init__(self, host: str, port: int, path: str, timeout: float = 30.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(handshake.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise CDPError("WebSocket handshake failed")
            resp += chunk
        if b"101" not in resp.split(b"\r\n", 1)[0]:
            raise CDPError(f"WebSocket upgrade rejected: {resp[:100]!r}")

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise CDPError("socket closed mid-frame")
            buf += chunk
        return buf

    def _recv_frame(self) -> bytes:
        header = self._recv_exact(2)
        fin_opcode = header[0]
        masked_len = header[1]
        opcode = fin_opcode & 0x0F
        masked = (masked_len & 0x80) != 0
        length = masked_len & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else b"\x00\x00\x00\x00"
        payload = self._recv_exact(length)
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if opcode == 0x8:  # close
            raise CDPError("server closed WebSocket")
        if opcode == 0x9:  # ping
            self._send_frame(0xA, payload)
            return self._recv_frame()
        return payload

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < (1 << 16):
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(header + masked)

    def send_text(self, text: str) -> None:
        self._send_frame(0x1, text.encode())

    def recv_text(self) -> str:
        return self._recv_frame().decode("utf-8", errors="replace")

    def close(self) -> None:
        try:
            self._send_frame(0x8, b"")
            self.sock.close()
        except Exception:
            pass


class CDP:
    def __init__(self, host: str = "127.0.0.1", port: int = 9222,
                 timeout: float = 30.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ws: Optional[_WSClient] = None
        self.next_id = 1

    def connect(self) -> "CDP":
        try:
            with urllib.request.urlopen(
                    f"http://{self.host}:{self.port}/json/new", timeout=5) as r:
                tab = json.loads(r.read())
                ws_url = tab["webSocketDebuggerUrl"]
        except Exception:
            with urllib.request.urlopen(
                    f"http://{self.host}:{self.port}/json", timeout=5) as r:
                tabs = json.loads(r.read())
                if not tabs:
                    raise CDPError("no Chrome tabs available")
                ws_url = tabs[0]["webSocketDebuggerUrl"]

        path = ws_url.split("/", 3)[3]
        self.ws = _WSClient(self.host, self.port, "/" + path, self.timeout)
        return self

    def _rpc(self, method: str, params: Optional[Dict] = None) -> Dict:
        if self.ws is None:
            raise CDPError("not connected")
        msg_id = self.next_id
        self.next_id += 1
        self.ws.send_text(json.dumps({"id": msg_id, "method": method,
                                      "params": params or {}}))
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            raw = self.ws.recv_text()
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if obj.get("id") == msg_id:
                if "error" in obj:
                    raise CDPError(obj["error"].get("message", "CDP error"))
                return obj.get("result", {})
        raise CDPError(f"timeout waiting for {method}")

    def enable_domains(self) -> None:
        self._rpc("Page.enable")
        self._rpc("Runtime.enable")
        self._rpc("DOM.enable")
        self._rpc("Network.enable")

    def navigate(self, url: str, wait_ms: int = 1500) -> None:
        self._rpc("Page.navigate", {"url": url})
        time.sleep(wait_ms / 1000.0)

    def evaluate(self, expression: str) -> Any:
        result = self._rpc("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True,
        })
        return result.get("result", {}).get("value")

    def extract_dom(self) -> Dict[str, Any]:
        return {
            "html": self.evaluate("document.documentElement.outerHTML"),
            "links": self.evaluate(
                "Array.from(document.querySelectorAll('a[href]'))"
                ".map(a => a.href)"),
            "forms": self.evaluate(
                "Array.from(document.forms).map(f => ({"
                "  action: f.action,"
                "  method: (f.method||'GET').toUpperCase(),"
                "  inputs: Object.fromEntries("
                "    Array.from(f.elements).filter(e=>e.name)"
                "      .map(e=>[e.name, e.value||'']))"
                "}))"),
            "scripts": self.evaluate(
                "Array.from(document.querySelectorAll('script[src]'))"
                ".map(s => s.src)"),
            "xhr_log": getattr(self, "_xhr_log", []),
        }

    def click_all(self) -> None:
        self.evaluate("""
            (() => {
              const seen = new Set();
              document.querySelectorAll('a,button,[role=button],[onclick]')
                .forEach(el => {
                  const key = (el.tagName||'') + (el.textContent||'').slice(0,30);
                  if (seen.has(key)) return;
                  seen.add(key);
                  try { el.click(); } catch (e) {}
                });
            })()
        """)

    def close(self) -> None:
        if self.ws:
            self.ws.close()


def headless_available(host: str = "127.0.0.1", port: int = 9222) -> bool:
    try:
        with urllib.request.urlopen(
                f"http://{host}:{port}/json/version", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def auto_crawl(ctx: Any, max_pages: int = 20) -> List[Dict[str, Any]]:
    """Headless crawl driver. Falls back to regex crawler if Chrome is unavailable."""
    if not headless_available():
        return []

    cdp = CDP().connect()
    cdp.enable_domains()
    seen = set()
    queue = [ctx.base_url]
    pages: List[Dict[str, Any]] = []

    try:
        while queue and len(pages) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                cdp.navigate(url, wait_ms=1200)
                cdp.click_all()
                time.sleep(0.3)
                data = cdp.extract_dom()
                data["url"] = url
                pages.append(data)
                for link in data.get("links", [])[:200]:
                    if isinstance(link, str) and link.startswith(("http://", "https://")):
                        if ctx.root in link and link not in seen:
                            queue.append(link)
            except CDPError:
                continue
    finally:
        cdp.close()

    return pages
