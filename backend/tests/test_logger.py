"""Phase 3 tests: Logger validation (TSV + Ledger co-write and verify)."""

import os
from webprobe.core.ledger import Ledger
from webprobe.core.logger import ActivityLog


def test_activity_log_ledger_cowrite_and_verify(tmp_path):
    tsv_path = str(tmp_path / "activity.tsv")
    ledger_path = str(tmp_path / "activity.ledger")

    ledger = Ledger(ledger_path)
    activity = ActivityLog(tsv_path, ledger=ledger)

    activity.record("test_01", "PASS", "Initial check complete", "No vuln detected", url="http://127.0.0.1/")
    activity.record("test_02", "FAIL", "Found vulnerability", "Reflected payload alert(1)", url="http://127.0.0.1/search")

    assert os.path.exists(tsv_path)
    assert os.path.exists(ledger_path)

    # Check replay
    replayed = activity.replay(limit=5)
    assert len(replayed) == 2
    assert replayed[0]["test_id"] == "test_01"

    # Verify ledger integrity via activity.verify()
    assert activity.verify() is True

    # Test tampering detection: alter payload in an existing ledger entry
    with open(ledger_path, "r", encoding="utf-8") as f:
        content = f.read()
    with open(ledger_path, "w", encoding="utf-8") as f:
        f.write(content.replace("Found vulnerability", "Tampered vulnerability"))

    # verify() detects the mismatch and returns False
    assert activity.verify() is False
