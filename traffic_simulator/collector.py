"""
SENTINEL AI — Continuous Access Log Collector (Stage 2D)

Security & Reliability Architecture:
1. Session Privacy: Raw session IDs are NEVER written to parsed_events.jsonl.
   A stable, non-reversible session fingerprint is generated using a keyed HMAC-SHA256.
   The secret key is stored with restricted permissions (.session_hmac.key) or loaded from env.
2. Idempotent Output: Recoverable at-least-once log reading coupled with request_id
   deduplication ensures strictly exactly-once diagnostic records in parsed_events.jsonl.
   Interrupted writes (partial lines) are detected and cleaned on startup.
3. Bounded Deduplication: Uses an O(1) FIFO/LRU cache capped at 50,000 entries.
   Prevents unbounded memory growth while ensuring restart-safety by restoring recent IDs.
4. Robust Log Rotation: Flushes and drains old file, checks for pending partial trailing
   lines, independently opens the new file, and updates checkpoint without data loss.
5. Checkpoint Robustness: Explicitly handles valid, missing, corrupt, truncated, and rotated
   states. Corrupt checkpoints trigger safe recovery via output index rather than silent skip.
6. Bounded Batch Processing: Configurable batch_size commits checkpoint and syncs I/O
   in bounded chunks, balancing disk throughput with crash resilience.
"""

from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import secrets
import signal
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from traffic_simulator.parser import TrafficFeatureParser, ParsedTrafficRecord
except ImportError:
    from parser import TrafficFeatureParser, ParsedTrafficRecord

logger = logging.getLogger("sentinel.collector")


# ---------------------------------------------------------------------------
# Session Fingerprinting (Keyed HMAC-SHA256)
# ---------------------------------------------------------------------------
class SessionFingerprinter:
    """Generates stable, non-reversible session fingerprints using keyed HMAC-SHA256.

    Guarantees:
    - Raw session cookies / tokens are never exposed in diagnostic output.
    - The secret HMAC key is stored with restricted permissions (0o600) or loaded from env.
    - Different verified sessions receive strictly different fingerprints.
    - Identical sessions produce identical fingerprints across restarts with the same key.
    """

    def __init__(self, key_path: Optional[Path] = None, secret_key: Optional[bytes] = None):
        if secret_key is not None:
            self._key = secret_key
        else:
            self._key = self._load_or_create_key(key_path)

    @staticmethod
    def _load_or_create_key(key_path: Optional[Path]) -> bytes:
        # 1. Environment variable override
        env_key = os.environ.get("COLLECTOR_HMAC_KEY")
        if env_key:
            return env_key.encode("utf-8")

        if key_path is None:
            return secrets.token_bytes(32)

        key_file = Path(key_path).resolve()
        if key_file.exists():
            try:
                data = key_file.read_bytes()
                if len(data) >= 16:
                    return data
            except Exception as exc:
                logger.warning("Could not read HMAC key from %s: %s", key_file, exc)

        # Generate fresh 32-byte cryptographically secure random key
        new_key = secrets.token_bytes(32)
        try:
            key_file.parent.mkdir(parents=True, exist_ok=True)
            # Create with restricted 0o600 permissions
            fd = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with open(fd, "wb") as f:
                f.write(new_key)
        except Exception as exc:
            logger.warning("Could not persist HMAC key to %s: %s", key_file, exc)

        return new_key

    def fingerprint(self, session_id: Optional[str]) -> Optional[str]:
        """Generate a stable, non-reversible fingerprint string (sf_<16_hex_chars>)."""
        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            return None
        mac = hmac.new(self._key, session_id.strip().encode("utf-8"), hashlib.sha256).hexdigest()
        return f"sf_{mac[:16]}"


# ---------------------------------------------------------------------------
# Bounded Deduplication Cache
# ---------------------------------------------------------------------------
class BoundedDeduplicationCache:
    """Bounded, restart-safe FIFO deduplication cache for request IDs.

    Guarantees O(1) containment checks, strict memory bounding via LRU/FIFO
    eviction at max_size (default 50,000), and avoids bulk-clearing memory drops.
    """

    def __init__(self, capacity: int = 50000):
        self.capacity = max(100, capacity)
        self._cache: OrderedDict[str, None] = OrderedDict()

    def contains(self, key: str) -> bool:
        return key in self._cache

    def add(self, key: str) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
            return
        if len(self._cache) >= self.capacity:
            self._cache.popitem(last=False)  # Evict oldest entry in O(1)
        self._cache[key] = None

    def update(self, keys: Any) -> None:
        for k in keys:
            if k:
                self.add(str(k))

    def __len__(self) -> int:
        return len(self._cache)

    def to_recent_list(self, max_items: int = 1000) -> List[str]:
        """Return the most recent keys for checkpoint persistence."""
        items = list(self._cache.keys())
        return items[-max_items:]


# ---------------------------------------------------------------------------
# Configuration & Statistics Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class CollectorConfig:
    """Runtime configuration for the continuous log collector."""

    log_file: Path
    checkpoint_file: Path
    output_file: Path
    hmac_key_file: Optional[Path] = None
    replay: bool = False
    poll_interval: float = 0.2
    stats_interval: float = 5.0
    batch_size: int = 100


@dataclass
class CollectorStats:
    """Runtime operational metrics tracked by the collector."""

    lines_read: int = 0
    events_parsed: int = 0
    malformed_lines: int = 0
    duplicate_events_skipped: int = 0
    current_byte_offset: int = 0
    rotations_detected: int = 0
    truncations_detected: int = 0
    start_time: float = field(default_factory=time.time)
    last_event_time: Optional[float] = None
    available_detectors_counts: Dict[str, int] = field(
        default_factory=lambda: {
            "http": 0,
            "session": 0,
            "sequence": 0,
            "network": 0,
            "autoencoder": 0,
        }
    )

    def to_dict(self, active_sessions: int = 0) -> Dict[str, Any]:
        """Convert metrics to serializable dictionary."""
        uptime = max(0.0, time.time() - self.start_time)
        return {
            "uptime_seconds": round(uptime, 2),
            "lines_read": self.lines_read,
            "events_parsed": self.events_parsed,
            "malformed_lines": self.malformed_lines,
            "duplicate_events_skipped": self.duplicate_events_skipped,
            "current_byte_offset": self.current_byte_offset,
            "rotations_detected": self.rotations_detected,
            "truncations_detected": self.truncations_detected,
            "active_sessions": active_sessions,
            "available_detectors_counts": dict(self.available_detectors_counts),
        }


# ---------------------------------------------------------------------------
# Checkpoint Manager
# ---------------------------------------------------------------------------
class CheckpointManager:
    """Manages persistent, atomic checkpointing for the log collector."""

    def __init__(self, checkpoint_file: Path):
        self.checkpoint_file = Path(checkpoint_file).resolve()

    def check_checkpoint_status(self, log_file: Path) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Check status of checkpoint relative to current log file.

        Returns:
          ("valid", data): checkpoint matches current file on disk
          ("rotated", data): checkpoint exists, but inode changed (file was rotated/recreated)
          ("truncated", data): checkpoint exists, but file size < offset
          ("missing", None): checkpoint file does not exist
          ("corrupt", None): checkpoint file exists but is corrupt or invalid
        """
        if not self.checkpoint_file.exists():
            return ("missing", None)

        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            logger.warning("Checkpoint file %s failed to parse: %s", self.checkpoint_file, exc)
            return ("corrupt", None)

        if not isinstance(data, dict):
            return ("corrupt", None)

        if "offset" not in data or "inode" not in data:
            return ("corrupt", None)

        try:
            offset = int(data["offset"])
            if offset < 0:
                return ("corrupt", None)
        except (ValueError, TypeError):
            return ("corrupt", None)

        if log_file.exists():
            try:
                st = os.stat(log_file)
                if st.st_ino != data.get("inode"):
                    return ("rotated", data)
                if st.st_size < offset:
                    return ("truncated", data)
            except OSError:
                return ("corrupt", None)

        return ("valid", data)

    def load_checkpoint(self, log_file: Path) -> Optional[Dict[str, Any]]:
        """Load checkpoint if valid for the current log file."""
        status, data = self.check_checkpoint_status(log_file)
        if status == "valid":
            return data
        return None

    def save_checkpoint(
        self,
        log_file: Path,
        offset: int,
        last_request_id: Optional[str] = None,
        events_processed: int = 0,
        recent_request_ids: Optional[List[str]] = None,
    ) -> None:
        """Atomically commit current offset and metadata to disk."""
        self.checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
        inode = 0
        device = 0
        if log_file.exists():
            try:
                st = os.stat(log_file)
                inode = st.st_ino
                device = st.st_dev
            except OSError:
                pass

        payload = {
            "inode": inode,
            "device": device,
            "offset": int(offset),
            "last_request_id": last_request_id,
            "events_processed": events_processed,
            "recent_request_ids": recent_request_ids or [],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        tmp_file = self.checkpoint_file.with_suffix(f".tmp.{os.getpid()}")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, self.checkpoint_file)
        except Exception as exc:
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except OSError:
                    pass
            logger.error("Failed to commit checkpoint atomically: %s", exc)
            raise


# ---------------------------------------------------------------------------
# Continuous Log Collector
# ---------------------------------------------------------------------------
class LogCollector:
    """Monitors access.log, reads appended lines, and pipes through TrafficFeatureParser.

    Processing Model:
    Uses recoverable at-least-once file reads combined with idempotent request_id
    deduplication to guarantee strictly exactly-once output records in parsed_events.jsonl.
    """

    def __init__(
        self,
        config: Optional[CollectorConfig] = None,
        parser: Optional[TrafficFeatureParser] = None,
    ):
        base_logs = Path(__file__).resolve().parent / "logs"
        self.config = config or CollectorConfig(
            log_file=base_logs / "access.log",
            checkpoint_file=base_logs / ".collector_offset.json",
            output_file=base_logs / "parsed_events.jsonl",
            hmac_key_file=base_logs / ".session_hmac.key",
        )
        self.parser = parser or TrafficFeatureParser()
        self.checkpoint_mgr = CheckpointManager(self.config.checkpoint_file)
        self.stats = CollectorStats()

        # Session privacy: keyed HMAC fingerprinter
        hmac_key_path = self.config.hmac_key_file or (self.config.checkpoint_file.parent / ".session_hmac.key")
        self.fingerprinter = SessionFingerprinter(key_path=hmac_key_path)

        # Bounded deduplication cache
        self.dedup_cache = BoundedDeduplicationCache(capacity=50000)

        self._running = False
        self._stop_requested = False
        self._last_request_id: Optional[str] = None
        self._output_fh = None
        self._uncommitted_events: int = 0

    def stop(self) -> None:
        """Signal the collector to halt its loop gracefully."""
        self._stop_requested = True

    def _recover_corrupt_checkpoint(self) -> int:
        """Safe recovery strategy when checkpoint file is corrupt.

        Inspects parsed_events.jsonl to find the last successfully committed request_id,
        locates it in access.log, and recovers the exact byte offset without dropping events.
        If output is empty/missing, falls back to byte 0 to guarantee zero data loss.
        """
        logger.warning(
            "CRITICAL: Checkpoint file %s is corrupt. Initiating safe recovery strategy.",
            self.config.checkpoint_file,
        )

        last_id = None
        if self.config.output_file.exists():
            try:
                with open(self.config.output_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        s = line.strip()
                        if s:
                            try:
                                d = json.loads(s)
                                rid = d.get("request_id")
                                if rid and not str(rid).startswith("malformed-"):
                                    last_id = rid
                            except Exception:
                                pass
            except Exception as exc:
                logger.warning("Could not read output file during corrupt checkpoint recovery: %s", exc)

        if last_id and self.config.log_file.exists():
            # Scan access.log to find the byte offset immediately following last_id
            try:
                with open(self.config.log_file, "rb") as f:
                    while True:
                        line = f.readline()
                        if not line:
                            break
                        if not line.endswith(b"\n"):
                            break
                        try:
                            rec = json.loads(line.decode("utf-8", errors="replace").strip())
                            if rec.get("request_id") == last_id:
                                recovered_offset = f.tell()
                                logger.info(
                                    "Successfully recovered offset %d from output history (request_id=%s).",
                                    recovered_offset,
                                    last_id,
                                )
                                self._last_request_id = last_id
                                self._save_checkpoint()
                                return recovered_offset
                        except Exception:
                            continue
            except Exception as exc:
                logger.warning("Error scanning log file for last request ID: %s", exc)

        # Fallback: start from byte 0 to guarantee no data loss
        logger.warning(
            "Could not determine last committed request from output. "
            "Safe recovery defaulting to byte 0 to guarantee zero data loss."
        )
        return 0

    def resolve_initial_offset(self) -> int:
        """Determine starting byte offset based on mode (normal vs replay) and checkpoint."""
        if self.config.replay:
            # Replay mode: explicitly start from beginning
            return 0

        status, ckpt = self.checkpoint_mgr.check_checkpoint_status(self.config.log_file)

        if status == "valid" and ckpt is not None:
            self._last_request_id = ckpt.get("last_request_id")
            # Restore recent request IDs into dedup cache
            recent_ids = ckpt.get("recent_request_ids")
            if recent_ids and isinstance(recent_ids, list):
                self.dedup_cache.update(recent_ids)
            return int(ckpt.get("offset", 0))

        if status == "rotated":
            logger.info("Log rotation detected (inode changed). Starting new file at byte 0.")
            self.stats.rotations_detected += 1
            return 0

        if status == "truncated":
            logger.warning("Log truncation detected (file size < offset). Resetting offset to byte 0.")
            self.stats.truncations_detected += 1
            return 0

        if status == "corrupt":
            return self._recover_corrupt_checkpoint()

        # Normal mode without checkpoint (missing):
        # Start at current end of file to avoid replaying old benchmark/test traffic
        if self.config.log_file.exists():
            try:
                return os.path.getsize(self.config.log_file)
            except OSError:
                return 0
        return 0

    def _save_checkpoint(self) -> None:
        """Helper to save current offset and metadata to checkpoint file."""
        recent_ids = self.dedup_cache.to_recent_list(max_items=1000)
        self.checkpoint_mgr.save_checkpoint(
            log_file=self.config.log_file,
            offset=self.stats.current_byte_offset,
            last_request_id=self._last_request_id,
            events_processed=self.stats.events_parsed,
            recent_request_ids=recent_ids,
        )
        self._uncommitted_events = 0

    def _clean_output_file_trailing_partial(self) -> None:
        """Clean any incomplete trailing line in parsed_events.jsonl from an interrupted crash."""
        if not self.config.output_file.exists() or self.config.output_file.stat().st_size == 0:
            return
        try:
            with open(self.config.output_file, "rb+") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                check_size = min(size, 4096)
                f.seek(size - check_size)
                chunk = f.read(check_size)
                if chunk and not chunk.endswith(b"\n"):
                    last_nl = chunk.rfind(b"\n")
                    if last_nl != -1:
                        new_size = (size - check_size) + last_nl + 1
                        f.seek(new_size)
                        f.truncate()
                    else:
                        f.seek(0)
                        f.truncate()
        except Exception as exc:
            logger.warning("Error cleaning trailing partial line in output file: %s", exc)

    def _populate_dedup_cache_from_output(self, max_items: int = 50000) -> None:
        """Populate deduplication cache from existing parsed_events.jsonl records."""
        if not self.config.output_file.exists():
            return
        try:
            with open(self.config.output_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if s:
                        try:
                            d = json.loads(s)
                            rid = d.get("request_id")
                            if rid:
                                self.dedup_cache.add(str(rid))
                        except Exception:
                            pass
        except Exception as exc:
            logger.warning("Error reading existing request IDs from output file: %s", exc)

    def _write_parsed_event(self, raw_record: Dict[str, Any], parsed: ParsedTrafficRecord) -> None:
        """Format and append a successfully parsed record to parsed_events.jsonl.

        Security: Raw session IDs are NEVER logged. Only session_fingerprint is written.
        """
        if self._output_fh is None:
            return

        extracted_features = {
            **parsed.payload_features,
            **parsed.time_window_features,
        }
        if parsed.session_features:
            extracted_features.update(parsed.session_features)

        # Verified session check & fingerprinting
        session_id = raw_record.get("session_id")
        has_verified = bool(
            session_id
            and raw_record.get("session_verified", False) is True
        )
        session_fp = self.fingerprinter.fingerprint(session_id) if has_verified else None

        out_entry: Dict[str, Any] = {
            "request_id": parsed.request_id,
            "timestamp": parsed.raw_timestamp or str(parsed.timestamp),
            "session_fingerprint": session_fp,
            "session_verified": has_verified,
            "extracted_features": extracted_features,
            "detector_availability": parsed.detector_availability,
            "unavailable_reasons": parsed.unavailable_reasons,
            "processing_status": "success" if parsed.is_valid else "invalid",
            "validation_errors": parsed.validation_errors,
            "is_valid": parsed.is_valid,
        }

        line = json.dumps(out_entry, default=str) + "\n"
        self._output_fh.write(line)

    def _write_malformed_event(self, raw_line: str, error_msg: str) -> None:
        """Record malformed line error without saving sensitive raw content."""
        if self._output_fh is None:
            return

        out_entry: Dict[str, Any] = {
            "request_id": f"malformed-{self.stats.lines_read}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_fingerprint": None,
            "session_verified": False,
            "extracted_features": {},
            "detector_availability": {
                "http": False,
                "session": False,
                "sequence": False,
                "network": False,
                "autoencoder": False,
            },
            "unavailable_reasons": {"all": f"Malformed log entry: {error_msg}"},
            "processing_status": "malformed",
            "validation_errors": [error_msg],
            "is_valid": False,
        }

        line = json.dumps(out_entry, default=str) + "\n"
        self._output_fh.write(line)

    def _sync_output(self) -> None:
        """Flush and sync output file descriptor to physical disk."""
        if self._output_fh is not None and not self._output_fh.closed:
            self._output_fh.flush()
            try:
                os.fsync(self._output_fh.fileno())
            except OSError:
                pass

    def _process_stream(self, file_obj, max_events: Optional[int] = None) -> int:
        """Read and process newly available complete lines from file stream."""
        processed_count = 0
        batch_limit = max(1, self.config.batch_size)

        while not self._stop_requested:
            if max_events is not None and processed_count >= max_events:
                break

            line_start_pos = file_obj.tell()
            line_bytes = file_obj.readline()

            if not line_bytes:
                # EOF reached
                break

            if not line_bytes.endswith(b"\n"):
                # Partial line! Roll back so next poll re-reads when complete
                file_obj.seek(line_start_pos)
                break

            self.stats.lines_read += 1
            line_str = line_bytes.decode("utf-8", errors="replace").strip()

            if not line_str:
                self.stats.current_byte_offset = file_obj.tell()
                continue

            # Parse JSON
            try:
                record = json.loads(line_str)
            except Exception as exc:
                self.stats.malformed_lines += 1
                self._write_malformed_event(line_str, str(exc))
                self.stats.current_byte_offset = file_obj.tell()
                self._sync_output()
                self._save_checkpoint()
                continue

            if not isinstance(record, dict):
                self.stats.malformed_lines += 1
                self._write_malformed_event(line_str, "Record must be a JSON dictionary")
                self.stats.current_byte_offset = file_obj.tell()
                self._sync_output()
                self._save_checkpoint()
                continue

            req_id = record.get("request_id")

            # Idempotent deduplication check
            if req_id and self.dedup_cache.contains(str(req_id)):
                self.stats.duplicate_events_skipped += 1
                self.stats.current_byte_offset = file_obj.tell()
                # Advance checkpoint without duplicate write
                self._save_checkpoint()
                continue

            # Pass to stateful parser
            parsed = self.parser.parse_log_entry(record)
            self.stats.events_parsed += 1
            self.stats.last_event_time = parsed.timestamp

            if req_id:
                self.dedup_cache.add(str(req_id))
                self._last_request_id = str(req_id)

            # Update detector availability counts
            for det_name, is_avail in parsed.detector_availability.items():
                if is_avail:
                    self.stats.available_detectors_counts[det_name] = (
                        self.stats.available_detectors_counts.get(det_name, 0) + 1
                    )

            # Write parsed record to diagnostic file
            self._write_parsed_event(record, parsed)
            self.stats.current_byte_offset = file_obj.tell()
            self._uncommitted_events += 1
            processed_count += 1

            # Bounded batch processing: sync output and checkpoint every batch_size events
            if self._uncommitted_events >= batch_limit:
                self._sync_output()
                self._save_checkpoint()

        # Flush any remaining uncommitted events at EOF
        if self._uncommitted_events > 0:
            self._sync_output()
            self._save_checkpoint()

        return processed_count

    def _handle_rotation(self, old_file_obj) -> Tuple[Any, Any]:
        """Safely drain the rotated old file, check for trailing partial line, and switch to new file."""
        # 1. Drain complete lines from old file
        self._process_stream(old_file_obj)

        # 2. Check for trailing partial line
        line_start = old_file_obj.tell()
        remaining = old_file_obj.readline()
        if remaining and not remaining.endswith(b"\n"):
            # Wait briefly up to 0.3s in case writer was mid-flush
            deadline = time.time() + 0.3
            while time.time() < deadline:
                time.sleep(0.05)
                more = old_file_obj.readline()
                if more:
                    remaining += more
                    if remaining.endswith(b"\n"):
                        break
            if remaining.endswith(b"\n"):
                self.stats.lines_read += 1
                line_str = remaining.decode("utf-8", errors="replace").strip()
                try:
                    rec = json.loads(line_str)
                    if isinstance(rec, dict):
                        rid = rec.get("request_id")
                        if not (rid and self.dedup_cache.contains(str(rid))):
                            parsed = self.parser.parse_log_entry(rec)
                            self.stats.events_parsed += 1
                            if rid:
                                self.dedup_cache.add(str(rid))
                            self._write_parsed_event(rec, parsed)
                except Exception:
                    pass
            else:
                logger.warning(
                    "Rotated log file ended with an incomplete line at offset %d: %r. Cannot parse partial record.",
                    line_start,
                    remaining[:60],
                )
                self._write_malformed_event(
                    remaining.decode("utf-8", errors="replace"),
                    "Incomplete line at EOF during log rotation",
                )

        self._sync_output()
        old_file_obj.close()

        # 3. Open new file from byte 0
        new_file = open(self.config.log_file, "rb")
        new_stat = os.fstat(new_file.fileno())
        new_file.seek(0)
        self.stats.current_byte_offset = 0
        self.stats.rotations_detected += 1
        self._save_checkpoint()
        return new_file, new_stat

    def run_once(self, max_events: Optional[int] = None) -> int:
        """Process all currently available log entries up to EOF and return count."""
        self.config.output_file.parent.mkdir(parents=True, exist_ok=True)
        self._clean_output_file_trailing_partial()
        self._populate_dedup_cache_from_output()

        with open(self.config.output_file, "a", encoding="utf-8") as out_fh:
            self._output_fh = out_fh

            if not self.config.log_file.exists():
                return 0

            initial_offset = self.resolve_initial_offset()
            self.stats.current_byte_offset = initial_offset

            with open(self.config.log_file, "rb") as log_fh:
                file_size = os.fstat(log_fh.fileno()).st_size
                if file_size < initial_offset:
                    self.stats.truncations_detected += 1
                    initial_offset = 0

                log_fh.seek(initial_offset)
                count = self._process_stream(log_fh, max_events=max_events)

            self._sync_output()
            self._save_checkpoint()
            self._output_fh = None
            return count

    def run(self) -> None:
        """Execute continuous tailing loop until stopped via SIGINT/SIGTERM or stop()."""
        self._running = True
        self._stop_requested = False

        def _signal_handler(signum, frame):
            logger.info("Signal %s received. Stopping collector...", signum)
            self._stop_requested = True

        prev_sigint = signal.signal(signal.SIGINT, _signal_handler)
        prev_sigterm = signal.signal(signal.SIGTERM, _signal_handler)

        current_file = None
        try:
            self.config.output_file.parent.mkdir(parents=True, exist_ok=True)
            self._clean_output_file_trailing_partial()
            self._populate_dedup_cache_from_output()

            self._output_fh = open(self.config.output_file, "a", encoding="utf-8")

            initial_offset = self.resolve_initial_offset()
            self.stats.current_byte_offset = initial_offset
            self._save_checkpoint()

            last_stats_time = time.time()

            while not self.config.log_file.exists() and not self._stop_requested:
                time.sleep(self.config.poll_interval)

            if self._stop_requested:
                return

            current_file = open(self.config.log_file, "rb")
            current_stat = os.fstat(current_file.fileno())
            current_file.seek(initial_offset)

            while not self._stop_requested:
                # Check log file metadata on disk
                try:
                    disk_stat = os.stat(self.config.log_file)
                except OSError:
                    disk_stat = None

                if disk_stat is not None:
                    # 1. Log Rotation Detection
                    if (disk_stat.st_ino != current_stat.st_ino or
                        disk_stat.st_dev != current_stat.st_dev):
                        current_file, current_stat = self._handle_rotation(current_file)
                        continue

                    # 2. Log Truncation Detection
                    if disk_stat.st_size < current_file.tell():
                        self.stats.truncations_detected += 1
                        logger.warning(
                            "Log truncation detected (size %s < offset %s). Resetting to 0.",
                            disk_stat.st_size,
                            current_file.tell(),
                        )
                        current_file.seek(0, os.SEEK_SET)
                        self.stats.current_byte_offset = 0
                        self._save_checkpoint()
                        continue

                # Read available complete lines
                processed = self._process_stream(current_file)

                # Periodic stats printing
                now = time.time()
                if self.config.stats_interval > 0 and (now - last_stats_time) >= self.config.stats_interval:
                    self.print_stats()
                    last_stats_time = now

                if processed == 0:
                    time.sleep(self.config.poll_interval)

        finally:
            if current_file is not None and not current_file.closed:
                current_file.close()
            if self._output_fh is not None and not self._output_fh.closed:
                self._sync_output()
                self._output_fh.close()
            self._save_checkpoint()
            self._running = False
            signal.signal(signal.SIGINT, prev_sigint)
            signal.signal(signal.SIGTERM, prev_sigterm)

    def print_stats(self) -> None:
        """Display operational statistics in human-readable console format."""
        active_sessions = len(self.parser.session_tracker._sessions)
        stats = self.stats.to_dict(active_sessions=active_sessions)
        time_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"\n--- SENTINEL AI Collector Stats [{time_str} UTC] ---")
        print(f"  Lines read:                 {stats['lines_read']}")
        print(f"  Events parsed:              {stats['events_parsed']}")
        print(f"  Malformed entries:          {stats['malformed_lines']}")
        print(f"  Duplicate events skipped:   {stats['duplicate_events_skipped']}")
        print(f"  Current byte offset:        {stats['current_byte_offset']}")
        print(f"  Active verified sessions:   {stats['active_sessions']}")
        print(f"  Rotations detected:         {stats['rotations_detected']}")
        print(f"  Truncations detected:       {stats['truncations_detected']}")
        print(f"  Available detectors:        {stats['available_detectors_counts']}")
        print("----------------------------------------------------\n")


# ---------------------------------------------------------------------------
# CLI Command Interface
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SENTINEL AI — Continuous Access Log Collector (Stage 2D)"
    )
    base_logs = Path(__file__).resolve().parent / "logs"
    parser.add_argument(
        "--log-file",
        type=Path,
        default=base_logs / "access.log",
        help="Path to simulator access.log file",
    )
    parser.add_argument(
        "--checkpoint-file",
        type=Path,
        default=base_logs / ".collector_offset.json",
        help="Path to persistent checkpoint JSON file",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=base_logs / "parsed_events.jsonl",
        help="Path to output parsed events JSON Lines file",
    )
    parser.add_argument(
        "--hmac-key-file",
        type=Path,
        default=base_logs / ".session_hmac.key",
        help="Path to session fingerprint HMAC secret key file",
    )
    parser.add_argument(
        "--replay",
        action="store_true",
        help="Replay log from byte 0 instead of resuming from checkpoint or current EOF",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Number of events per sync/checkpoint batch (default: 100)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.2,
        help="Seconds to sleep while waiting for new log entries (default: 0.2)",
    )
    parser.add_argument(
        "--stats-interval",
        type=float,
        default=5.0,
        help="Seconds between stats display (default: 5.0, set 0 to disable periodic print)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process newly appended events up to EOF once and exit",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print summary statistics on exit",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    config = CollectorConfig(
        log_file=args.log_file.resolve(),
        checkpoint_file=args.checkpoint_file.resolve(),
        output_file=args.output_file.resolve(),
        hmac_key_file=args.hmac_key_file.resolve() if args.hmac_key_file else None,
        replay=args.replay,
        batch_size=args.batch_size,
        poll_interval=args.poll_interval,
        stats_interval=args.stats_interval,
    )
    collector = LogCollector(config=config)

    mode_str = "REPLAY (from byte 0)" if config.replay else "NORMAL (from checkpoint or EOF)"
    print("Starting SENTINEL AI Log Collector:")
    print(f"  Log file:       {config.log_file}")
    print(f"  Checkpoint:     {config.checkpoint_file}")
    print(f"  Output:         {config.output_file}")
    print(f"  Batch size:     {config.batch_size}")
    print(f"  Mode:           {mode_str}")

    if args.once:
        count = collector.run_once()
        print(f"Batch completed: processed {count} events.")
    else:
        print("Monitoring access.log continuously. Press Ctrl+C to stop.")
        try:
            collector.run()
        except KeyboardInterrupt:
            print("\nShutting down collector...")

    if args.stats or args.once:
        collector.print_stats()

    return 0


if __name__ == "__main__":
    sys.exit(main())
