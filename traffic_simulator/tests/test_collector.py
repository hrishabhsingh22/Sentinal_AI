"""
SENTINEL AI — Stage 2D Collector Security, Reliability & Regression Tests

Verifies:
1. Raw session ID never appears in parsed_events.jsonl.
2. Stable session fingerprint generation (keyed HMAC-SHA256).
3. Different sessions produce different fingerprints.
4. Restart after output persistence but before checkpoint advancement (idempotency / deduplication).
5. Duplicate request IDs are skipped.
6. More than 50,000 events without unbounded memory growth (BoundedDeduplicationCache limit).
7. Partial final line during log rotation.
8. Corrupt checkpoint recovery.
9. File replacement and truncation handling.
10. Bounded batch processing.
11. New collector starts at correct offset (normal mode -> EOF).
12. New log entries are detected when appended.
13. Multiple entries are processed in order.
14. Partial lines are not processed prematurely.
15. Malformed lines do not crash the collector.
16. Replay mode processes the full file from byte 0.
17. Normal mode does not replay old entries without a checkpoint.
18. Parser state is maintained across events.
19. Session history remains chronological for LSTM.
20. Sensitive data is not written to parsed_events.jsonl.
21. Clean shutdown on stop / signal.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Ensure writable cache paths for sandboxed environment
os.environ.setdefault("KERAS_HOME", "/tmp")
os.environ.setdefault("MPLCONFIGDIR", "/tmp")

from traffic_simulator.collector import (
    LogCollector,
    CollectorConfig,
    CheckpointManager,
    SessionFingerprinter,
    BoundedDeduplicationCache,
)
from traffic_simulator.parser import TrafficFeatureParser


# ---------------------------------------------------------------------------
# Test Helpers & Fixtures
# ---------------------------------------------------------------------------
def _make_log_line(
    request_id: str,
    path: str = "/products",
    method: str = "GET",
    timestamp: float = 100.0,
    status_code: int = 200,
    client_ip: str = "127.0.0.1",
    session_id: str | None = None,
    session_verified: bool = False,
    query_params: dict | None = None,
    body_size_bytes: int = 0,
    body_indicators: dict | None = None,
) -> str:
    """Generate a clean JSON line matching access.log schema."""
    entry = {
        "timestamp": timestamp,
        "request_id": request_id,
        "method": method,
        "path": path,
        "query_params": query_params or {},
        "status_code": status_code,
        "client_ip": client_ip,
        "user_agent": "pytest-agent/1.0",
        "response_size_bytes": 128,
        "duration_ms": 1.25,
    }
    if session_id:
        entry["session_id"] = session_id
        entry["session_verified"] = session_verified
    if body_size_bytes > 0:
        entry["body_size_bytes"] = body_size_bytes
    if body_indicators:
        entry["body_indicators"] = body_indicators

    return json.dumps(entry) + "\n"


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    """Read all lines from a JSONL file."""
    if not path.exists():
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
    return records


@pytest.fixture
def collector_env(tmp_path: Path):
    """Provides isolated test log, checkpoint, HMAC key, and output paths."""
    log_file = tmp_path / "access.log"
    checkpoint_file = tmp_path / ".collector_offset.json"
    output_file = tmp_path / "parsed_events.jsonl"
    hmac_key_file = tmp_path / ".session_hmac.key"

    config = CollectorConfig(
        log_file=log_file,
        checkpoint_file=checkpoint_file,
        output_file=output_file,
        hmac_key_file=hmac_key_file,
        replay=False,
        batch_size=10,
        poll_interval=0.05,
        stats_interval=0,  # disable auto printing during tests
    )
    return {
        "tmp_path": tmp_path,
        "log_file": log_file,
        "checkpoint_file": checkpoint_file,
        "output_file": output_file,
        "hmac_key_file": hmac_key_file,
        "config": config,
    }


# ---------------------------------------------------------------------------
# Test 1: Raw session ID never appears in parsed_events.jsonl
# ---------------------------------------------------------------------------
def test_1_raw_session_id_never_appears_in_parsed_events(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    raw_token = "sess_VERY_SECRET_RAW_TOKEN_99999_DO_NOT_LEAK"
    line = _make_log_line(
        "sec-req-1",
        session_id=raw_token,
        session_verified=True,
    )
    log_file.write_text(line, encoding="utf-8")

    collector = LogCollector(config=config)
    collector.run_once()

    output_path: Path = collector_env["output_file"]
    assert output_path.exists()
    raw_output_text = output_path.read_text(encoding="utf-8")

    # Critical security check: raw session cookie/token must NOT appear anywhere in the output!
    assert raw_token not in raw_output_text
    assert "VERY_SECRET" not in raw_output_text

    parsed = _read_jsonl(output_path)
    assert len(parsed) == 1
    rec = parsed[0]
    # Raw session_id key must not exist or be exposed
    assert "session_id" not in rec or rec.get("session_id") is None
    # Keyed session_fingerprint must be present
    assert "session_fingerprint" in rec
    assert rec["session_fingerprint"] is not None
    assert rec["session_fingerprint"].startswith("sf_")
    assert rec["session_verified"] is True


# ---------------------------------------------------------------------------
# Test 2: Stable session fingerprint generation
# ---------------------------------------------------------------------------
def test_2_stable_session_fingerprint_generation(collector_env):
    key_path: Path = collector_env["hmac_key_file"]
    fp1 = SessionFingerprinter(key_path=key_path)
    fp2 = SessionFingerprinter(key_path=key_path)

    sid = "sess_constant_user_session_42"
    h1 = fp1.fingerprint(sid)
    h2 = fp2.fingerprint(sid)

    # Identical session IDs with same key produce strictly identical fingerprints
    assert h1 is not None
    assert h1.startswith("sf_")
    assert h1 == h2

    # None or blank input returns None
    assert fp1.fingerprint(None) is None
    assert fp1.fingerprint("") is None
    assert fp1.fingerprint("   ") is None


# ---------------------------------------------------------------------------
# Test 3: Different sessions produce different fingerprints
# ---------------------------------------------------------------------------
def test_3_different_sessions_produce_different_fingerprints(collector_env):
    key_path: Path = collector_env["hmac_key_file"]
    fp = SessionFingerprinter(key_path=key_path)

    sid_a = "sess_alice_token_111"
    sid_b = "sess_bob_token_222"

    ha = fp.fingerprint(sid_a)
    hb = fp.fingerprint(sid_b)

    assert ha is not None
    assert hb is not None
    assert ha != hb


# ---------------------------------------------------------------------------
# Test 4: Restart after output persistence but before checkpoint advancement
#         (Idempotent Deduplication Guarantee)
# ---------------------------------------------------------------------------
def test_4_restart_idempotent_deduplication(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    # Write 2 lines
    lines = [
        _make_log_line("idem-1", path="/step1"),
        _make_log_line("idem-2", path="/step2"),
    ]
    log_file.write_text("".join(lines), encoding="utf-8")

    # Instance 1 processes both events
    c1 = LogCollector(config=config)
    c1.run_once()
    assert c1.stats.events_parsed == 2

    parsed_initial = _read_jsonl(collector_env["output_file"])
    assert len(parsed_initial) == 2

    # SIMULATE CRASH:
    # Checkpoint was not updated for event 2 (rewind checkpoint offset back to after event 1)
    len_line1 = len(lines[0].encode("utf-8"))
    c1.checkpoint_mgr.save_checkpoint(
        log_file=log_file,
        offset=len_line1,  # pointing to start of event 2!
        last_request_id="idem-1",
        events_processed=1,
    )

    # Instance 2 starts up in normal mode (config.replay = False)
    config.replay = False
    c2 = LogCollector(config=config)
    # Deduplication cache loads already written request IDs from output file on startup!
    assert c2.dedup_cache.contains("idem-2") is True

    # Run instance 2: It will re-read line 2 from the old checkpoint offset
    count = c2.run_once()

    # Event 2 was already in output file, so it must be deduplicated (not appended again)
    assert count == 0  # 0 new writes
    assert c2.stats.duplicate_events_skipped == 1

    # Output file must STILL have exactly 2 records! (Idempotent output)
    parsed_after = _read_jsonl(collector_env["output_file"])
    assert len(parsed_after) == 2
    assert [p["request_id"] for p in parsed_after] == ["idem-1", "idem-2"]


# ---------------------------------------------------------------------------
# Test 5: Duplicate request IDs are skipped
# ---------------------------------------------------------------------------
def test_5_duplicate_request_ids(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    lines = [
        _make_log_line("duplicate-id", path="/first"),
        _make_log_line("duplicate-id", path="/second"),
    ]
    log_file.write_text("".join(lines), encoding="utf-8")

    collector = LogCollector(config=config)
    count = collector.run_once()

    assert count == 1
    assert collector.stats.duplicate_events_skipped == 1

    parsed = _read_jsonl(collector_env["output_file"])
    assert len(parsed) == 1
    assert parsed[0]["request_id"] == "duplicate-id"


# ---------------------------------------------------------------------------
# Test 6: More than 50,000 events without unbounded memory growth
# ---------------------------------------------------------------------------
def test_6_more_than_50k_events_without_unbounded_memory():
    cache = BoundedDeduplicationCache(capacity=50000)

    # Insert 60,000 unique request IDs
    for i in range(60000):
        cache.add(f"req-load-{i}")

    # Strict memory bound: length must not exceed capacity (50,000)
    assert len(cache) == 50000

    # Oldest 10,000 entries (0 to 9,999) must be evicted in O(1)
    assert cache.contains("req-load-0") is False
    assert cache.contains("req-load-5000") is False
    assert cache.contains("req-load-9999") is False

    # Newest 50,000 entries (10,000 to 59,999) must be retained
    assert cache.contains("req-load-10000") is True
    assert cache.contains("req-load-35000") is True
    assert cache.contains("req-load-59999") is True


# ---------------------------------------------------------------------------
# Test 7: Partial final line during log rotation
# ---------------------------------------------------------------------------
def test_7_partial_final_line_during_rotation(collector_env):
    log_file: Path = collector_env["log_file"]
    tmp_path: Path = collector_env["tmp_path"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    # Initial file has 1 complete line + 1 partial line at EOF (no newline)
    complete_line = _make_log_line("complete-1")
    partial_line = '{"timestamp": 100.0, "request_id": "partial-at-rot"'
    log_file.write_text(complete_line + partial_line, encoding="utf-8")

    c = LogCollector(config=config)
    # Process the complete line
    c.run_once()
    assert c.stats.events_parsed == 1

    # Now rotate log file: rename to access.log.old and create new access.log with complete-2
    old_file = tmp_path / "access.log.old"
    log_file.rename(old_file)
    log_file.write_text(_make_log_line("complete-2"), encoding="utf-8")

    # Simulate rotation handling directly
    config.replay = False
    c2 = LogCollector(config=config)
    c2.run_once()

    # Collector handles rotation cleanly without crashing
    assert c2.stats.rotations_detected >= 1
    assert c2.stats.events_parsed == 1

    parsed = _read_jsonl(collector_env["output_file"])
    # Contains complete-1 and complete-2
    assert len(parsed) >= 2
    req_ids = [p["request_id"] for p in parsed]
    assert "complete-1" in req_ids
    assert "complete-2" in req_ids


# ---------------------------------------------------------------------------
# Test 8: Corrupt checkpoint recovery
# ---------------------------------------------------------------------------
def test_8_corrupt_checkpoint_recovery(collector_env):
    log_file: Path = collector_env["log_file"]
    checkpoint_file: Path = collector_env["checkpoint_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    # 3 lines
    lines = [
        _make_log_line("corrupt-step-1"),
        _make_log_line("corrupt-step-2"),
        _make_log_line("corrupt-step-3"),
    ]
    log_file.write_text("".join(lines), encoding="utf-8")

    # Process first 2 lines
    c1 = LogCollector(config=config)
    c1.run_once(max_events=2)
    assert c1.stats.events_parsed == 2

    # Intentionally corrupt the checkpoint file with invalid JSON
    checkpoint_file.write_text("THIS IS TOTALLY CORRUPTED AND NOT JSON", encoding="utf-8")

    # Start new collector in normal mode
    config.replay = False
    c2 = LogCollector(config=config)

    # Verify corrupt checkpoint status
    status, _ = c2.checkpoint_mgr.check_checkpoint_status(log_file)
    assert status == "corrupt"

    # Initial offset should recover from output history (offset after corrupt-step-2)
    recovered_offset = c2.resolve_initial_offset()
    expected_offset = len((lines[0] + lines[1]).encode("utf-8"))
    assert recovered_offset == expected_offset

    # Run c2: It should process corrupt-step-3 without skipping or replaying
    count = c2.run_once()
    assert count == 1

    parsed = _read_jsonl(collector_env["output_file"])
    assert len(parsed) == 3
    assert parsed[-1]["request_id"] == "corrupt-step-3"


# ---------------------------------------------------------------------------
# Test 9: File replacement and truncation handling
# ---------------------------------------------------------------------------
def test_9_file_replacement_and_truncation(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    tmp_path: Path = collector_env["tmp_path"]
    config.replay = True

    # 1. Truncation test
    long_content = "".join([_make_log_line(f"trunc-{i}") for i in range(5)])
    log_file.write_text(long_content, encoding="utf-8")
    c1 = LogCollector(config=config)
    c1.run_once()
    old_offset = c1.stats.current_byte_offset
    assert old_offset > 300

    # Truncate file smaller than old offset
    log_file.write_text(_make_log_line("after-trunc"), encoding="utf-8")
    config.replay = False
    c2 = LogCollector(config=config)
    c2.run_once()

    assert c2.stats.truncations_detected >= 1
    parsed = _read_jsonl(collector_env["output_file"])
    assert parsed[-1]["request_id"] == "after-trunc"

    # 2. File replacement test (new inode)
    log_file.rename(tmp_path / "archived.log")
    log_file.write_text(_make_log_line("after-replace"), encoding="utf-8")
    c3 = LogCollector(config=config)
    c3.run_once()

    assert c3.stats.rotations_detected >= 1
    parsed = _read_jsonl(collector_env["output_file"])
    assert parsed[-1]["request_id"] == "after-replace"


# ---------------------------------------------------------------------------
# Test 10: Bounded batch processing
# ---------------------------------------------------------------------------
def test_10_bounded_batch_processing(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True
    config.batch_size = 5  # Commit every 5 events

    # Write 12 lines
    lines = "".join([_make_log_line(f"batch-{i}") for i in range(12)])
    log_file.write_text(lines, encoding="utf-8")

    collector = LogCollector(config=config)
    count = collector.run_once()

    assert count == 12
    assert collector.stats.events_parsed == 12

    # Checkpoint and output must be fully committed
    assert config.checkpoint_file.exists()
    parsed = _read_jsonl(collector_env["output_file"])
    assert len(parsed) == 12


# ---------------------------------------------------------------------------
# Test 11: New collector starts at correct offset (normal mode -> EOF)
# ---------------------------------------------------------------------------
def test_11_new_collector_starts_at_correct_offset(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]

    lines = "".join([_make_log_line(f"pre-{i}") for i in range(3)])
    log_file.write_text(lines, encoding="utf-8")
    expected_eof = log_file.stat().st_size

    collector = LogCollector(config=config)
    offset = collector.resolve_initial_offset()

    assert offset == expected_eof
    count = collector.run_once()
    assert count == 0
    assert collector.stats.events_parsed == 0


# ---------------------------------------------------------------------------
# Test 12: New log entries are detected when appended
# ---------------------------------------------------------------------------
def test_12_new_log_entries_detected(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]

    log_file.write_text(_make_log_line("existing-1"), encoding="utf-8")
    c = LogCollector(config=config)
    c.run_once()  # Commits EOF

    # Append new entry
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(_make_log_line("newly-appended-1"))

    count = c.run_once()
    assert count == 1
    assert c.stats.events_parsed == 1

    parsed = _read_jsonl(collector_env["output_file"])
    assert len(parsed) == 1
    assert parsed[0]["request_id"] == "newly-appended-1"


# ---------------------------------------------------------------------------
# Test 13: Multiple entries are processed in order
# ---------------------------------------------------------------------------
def test_13_multiple_entries_processed_in_order(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    req_ids = [f"req-seq-{i}" for i in range(5)]
    lines = "".join([_make_log_line(rid, timestamp=10.0 + i) for i, rid in enumerate(req_ids)])
    log_file.write_text(lines, encoding="utf-8")

    collector = LogCollector(config=config)
    collector.run_once()

    parsed = _read_jsonl(collector_env["output_file"])
    assert len(parsed) == 5
    assert [p["request_id"] for p in parsed] == req_ids


# ---------------------------------------------------------------------------
# Test 14: Partial lines are not processed prematurely
# ---------------------------------------------------------------------------
def test_14_partial_lines_not_processed_prematurely(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    partial = '{"timestamp": 1.0, "request_id": "part-1"'
    log_file.write_text(partial, encoding="utf-8")

    collector = LogCollector(config=config)
    assert collector.run_once() == 0

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(', "method": "GET", "path": "/", "status_code": 200, "client_ip": "1.1.1.1"}\n')

    assert collector.run_once() == 1
    parsed = _read_jsonl(collector_env["output_file"])
    assert len(parsed) == 1
    assert parsed[0]["request_id"] == "part-1"


# ---------------------------------------------------------------------------
# Test 15: Malformed lines do not crash the collector
# ---------------------------------------------------------------------------
def test_15_malformed_lines_do_not_crash(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    content = "INVALID_JSON\n" + _make_log_line("valid-after-bad")
    log_file.write_text(content, encoding="utf-8")

    collector = LogCollector(config=config)
    count = collector.run_once()

    assert count == 1
    assert collector.stats.malformed_lines == 1
    parsed = _read_jsonl(collector_env["output_file"])
    assert len(parsed) == 2
    assert parsed[0]["processing_status"] == "malformed"
    assert parsed[1]["request_id"] == "valid-after-bad"


# ---------------------------------------------------------------------------
# Test 16: Replay mode processes the full file from byte 0
# ---------------------------------------------------------------------------
def test_16_replay_mode_processes_full_file(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]

    lines = "".join([_make_log_line(f"rep-{i}") for i in range(4)])
    log_file.write_text(lines, encoding="utf-8")

    # Put checkpoint at EOF
    ckpt = CheckpointManager(config.checkpoint_file)
    ckpt.save_checkpoint(log_file, offset=log_file.stat().st_size, last_request_id="rep-3")

    config.replay = True
    c = LogCollector(config=config)
    assert c.resolve_initial_offset() == 0

    count = c.run_once()
    assert count == 4
    assert c.stats.events_parsed == 4


# ---------------------------------------------------------------------------
# Test 17: Normal mode does not replay old entries without a checkpoint
# ---------------------------------------------------------------------------
def test_17_normal_mode_does_not_replay_old_entries(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = False

    log_file.write_text("".join([_make_log_line(f"old-{i}") for i in range(5)]), encoding="utf-8")

    c = LogCollector(config=config)
    assert c.run_once() == 0

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(_make_log_line("new-single"))

    assert c.run_once() == 1
    parsed = _read_jsonl(collector_env["output_file"])
    assert len(parsed) == 1
    assert parsed[0]["request_id"] == "new-single"


# ---------------------------------------------------------------------------
# Test 18: Parser state is maintained across events
# ---------------------------------------------------------------------------
def test_18_parser_state_maintained_across_events(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    lines = [
        _make_log_line("p-1", timestamp=10.0, client_ip="192.168.1.1"),
        _make_log_line("p-2", timestamp=11.0, client_ip="192.168.1.1"),
        _make_log_line("p-3", timestamp=12.0, client_ip="192.168.1.1"),
    ]
    log_file.write_text("".join(lines), encoding="utf-8")

    c = LogCollector(config=config)
    c.run_once()

    parsed = _read_jsonl(collector_env["output_file"])
    assert len(parsed) == 3
    assert parsed[0]["extracted_features"]["f_req_count_10s"] == 1
    assert parsed[1]["extracted_features"]["f_req_count_10s"] == 2
    assert parsed[2]["extracted_features"]["f_req_count_10s"] == 3


# ---------------------------------------------------------------------------
# Test 19: Session history remains chronological for LSTM
# ---------------------------------------------------------------------------
def test_19_session_history_remains_chronological(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    sid = "sess_lstm_chrono"
    lines = [
        _make_log_line("l-1", timestamp=100.0, session_id=sid, session_verified=True),
        _make_log_line("l-2", timestamp=105.0, session_id=sid, session_verified=True),
        _make_log_line("l-3", timestamp=110.0, session_id=sid, session_verified=True),
    ]
    log_file.write_text("".join(lines), encoding="utf-8")

    c = LogCollector(config=config)
    c.run_once()

    session_history = c.parser.session_tracker._sessions[sid]["history"]
    assert len(session_history) == 3
    timestamps = [h["timestamp"] for h in session_history]
    assert timestamps == [100.0, 105.0, 110.0]


# ---------------------------------------------------------------------------
# Test 20: Sensitive data is not written to parsed_events.jsonl
# ---------------------------------------------------------------------------
def test_20_sensitive_data_not_written_to_parsed_events(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    raw_pass = "MySecretAdminPass#2026!"
    raw_token = "Bearer_secret_access_token_xyz"
    entry = {
        "timestamp": 100.0,
        "request_id": "sec-check-1",
        "method": "POST",
        "path": "/login",
        "query_params": {"token": "***REDACTED***"},
        "status_code": 200,
        "client_ip": "127.0.0.1",
        "user_agent": "secret-agent",
        "session_id": "sess_secret_cookie_token",
        "session_verified": True,
        "body_size_bytes": 50,
        "body_indicators": {"has_sqli": 1, "has_xss": 0, "has_cmd": 0, "has_lfi": 0, "has_traversal": 0},
    }
    log_file.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    c = LogCollector(config=config)
    c.run_once()

    output_text = collector_env["output_file"].read_text(encoding="utf-8")
    assert raw_pass not in output_text
    assert raw_token not in output_text
    assert "sess_secret_cookie_token" not in output_text

    parsed = _read_jsonl(collector_env["output_file"])
    assert len(parsed) == 1
    assert parsed[0]["session_fingerprint"].startswith("sf_")


# ---------------------------------------------------------------------------
# Test 21: Clean shutdown on stop signal
# ---------------------------------------------------------------------------
def test_21_clean_shutdown_on_stop(collector_env):
    log_file: Path = collector_env["log_file"]
    config: CollectorConfig = collector_env["config"]
    config.replay = True

    log_file.write_text(_make_log_line("stop-req"), encoding="utf-8")

    c = LogCollector(config=config)
    c.stop()
    assert c._stop_requested is True

    # run() exits cleanly
    c.run()
    assert c._running is False
    assert config.checkpoint_file.exists()
