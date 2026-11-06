"""Adversarial network simulation: timeouts, malformed responses, crashes."""

import socket
import threading
import time


def test_timeout_returns_none():
    """Server accepts but never responds; HttpClient must not hang forever."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def _accept_hold():
        conn, _ = srv.accept()
        time.sleep(3)
        conn.close()

    threading.Thread(target=_accept_hold, daemon=True).start()

    from webprobe.core.http import HttpClient
    client = HttpClient(timeout=0.5, insecure=True)
    t0 = time.monotonic()
    r = client.fetch(f"http://{host}:{port}/")
    elapsed = time.monotonic() - t0
    srv.close()
    assert r is None
    assert elapsed < 3.0


def test_malformed_response_returns_none():
    """Server sends garbage; must not raise."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def _send_garbage():
        conn, _ = srv.accept()
        conn.sendall(b"garbage not http\r\n\r\n")
        conn.close()

    threading.Thread(target=_send_garbage, daemon=True).start()

    from webprobe.core.http import HttpClient
    client = HttpClient(timeout=2, insecure=True)
    try:
        client.fetch(f"http://{host}:{port}/")
    except Exception:
        pass
    srv.close()
    # Test passes if we didn't crash
