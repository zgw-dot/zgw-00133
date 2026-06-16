from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from .models import (
    AuditBatch,
    Issue,
    IssueSeverity,
    IssueType,
    Manifest,
    ManifestFile,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
_TIMEZONE_PATTERN = re.compile(r"^([+-])(\d{2}):(\d{2})$")


class ManifestValidationError(Exception):
    def __init__(self, errors: List[dict]) -> None:
        self.errors = errors
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        lines = ["Manifest 格式校验失败:"]
        for e in self.errors:
            lines.append(f"  files[{e['index']}].{e['field']} ({e['path']}): {e['message']}")
        return "\n".join(lines)


def validate_manifest_format(data: dict) -> List[dict]:
    errors: List[dict] = []
    files = data.get("files", [])
    for i, entry in enumerate(files):
        path = entry.get("path", f"<unknown-{i}>")
        sha = entry.get("sha256", "")
        if not isinstance(sha, str) or not _SHA256_PATTERN.match(sha):
            errors.append({
                "index": i,
                "field": "sha256",
                "path": path,
                "value": repr(sha),
                "message": f"sha256 必须为 64 位十六进制字符串，当前值: {repr(sha)}",
            })
        size = entry.get("size")
        if not isinstance(size, int) or size < 0:
            errors.append({
                "index": i,
                "field": "size",
                "path": path,
                "value": repr(size),
                "message": f"size 必须为非负整数，当前值: {repr(size)}",
            })
        p = entry.get("path", "")
        if not isinstance(p, str) or not p.strip():
            errors.append({
                "index": i,
                "field": "path",
                "path": p or f"<unknown-{i}>",
                "value": repr(p),
                "message": "path 不能为空",
            })
    return errors


def load_manifest(manifest_path: str) -> Manifest:
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    format_errors = validate_manifest_format(data)
    if format_errors:
        raise ManifestValidationError(format_errors)
    return Manifest.from_dict(data)


def sha256_file(file_path: str, chunk_size: int = 8192) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def validate_file_path(
    backup_dir: str, manifest_file: ManifestFile
) -> Tuple[bool, str]:
    full_path = os.path.join(backup_dir, manifest_file.path)
    if not os.path.isabs(manifest_file.path):
        return True, ""
    return False, f"Path must be relative, got absolute: {manifest_file.path}"


def check_file_exists(backup_dir: str, manifest_file: ManifestFile) -> Tuple[bool, str]:
    full_path = os.path.join(backup_dir, manifest_file.path)
    if not os.path.exists(full_path):
        return False, f"File not found: {manifest_file.path}"
    if not os.path.isfile(full_path):
        return False, f"Not a regular file: {manifest_file.path}"
    return True, ""


def check_file_size(backup_dir: str, manifest_file: ManifestFile) -> Tuple[bool, str]:
    full_path = os.path.join(backup_dir, manifest_file.path)
    actual_size = os.path.getsize(full_path)
    if actual_size != manifest_file.size:
        return False, f"Size mismatch: expected {manifest_file.size}, got {actual_size}"
    return True, ""


def check_sha256(backup_dir: str, manifest_file: ManifestFile) -> Tuple[bool, str]:
    full_path = os.path.join(backup_dir, manifest_file.path)
    actual_hash = sha256_file(full_path)
    if actual_hash.lower() != manifest_file.sha256.lower():
        return False, f"SHA256 mismatch: expected {manifest_file.sha256}, got {actual_hash}"
    return True, ""


def parse_timezone_offset(tz: str) -> Optional[timezone]:
    if tz == "UTC" or tz == "Z":
        return timezone.utc
    match = _TIMEZONE_PATTERN.match(tz)
    if not match:
        return None
    sign = 1 if match.group(1) == "+" else -1
    hours = int(match.group(2))
    minutes = int(match.group(3))
    if hours > 14 or (hours == 14 and minutes != 0):
        return None
    if minutes > 59:
        return None
    delta = timedelta(hours=hours * sign, minutes=minutes * sign)
    return timezone(delta)


def check_backup_window(
    backup_dir: str,
    manifest_file: ManifestFile,
    window_start: str,
    window_end: str,
    tz: Optional[str] = None,
) -> Tuple[bool, str]:
    full_path = os.path.join(backup_dir, manifest_file.path)
    try:
        mtime_ts = os.path.getmtime(full_path)
        mtime_utc = datetime.fromtimestamp(mtime_ts, tz=timezone.utc)

        start_naive = datetime.fromisoformat(window_start)
        end_naive = datetime.fromisoformat(window_end)

        if tz:
            tz_offset = parse_timezone_offset(tz)
            if tz_offset is None:
                return False, f"Invalid timezone format: '{tz}'. Use UTC, Z, or ±HH:MM"
            start = start_naive.replace(tzinfo=tz_offset)
            end = end_naive.replace(tzinfo=tz_offset)
            mtime = mtime_utc.astimezone(tz_offset)
        else:
            start = start_naive
            end = end_naive
            mtime = datetime.fromtimestamp(mtime_ts)

        if mtime < start or mtime > end:
            tz_info = f" ({tz})" if tz else ""
            return False, (
                f"File mtime {mtime.isoformat()}{tz_info} outside backup window "
                f"[{window_start}, {window_end}]"
            )
        return True, ""
    except (ValueError, OSError) as e:
        return False, f"Failed to check backup window: {e}"


def check_business_line(
    manifest_file: ManifestFile, valid_lines: List[str]
) -> Tuple[bool, str]:
    if not manifest_file.business_line:
        return True, ""
    if manifest_file.business_line not in valid_lines:
        return False, (
            f"Unknown business line '{manifest_file.business_line}', "
            f"valid: {valid_lines}"
        )
    return True, ""


def check_duplicate_entries(manifest_files: List[ManifestFile]) -> List[Issue]:
    issues: List[Issue] = []
    seen: Dict[str, int] = {}
    for mf in manifest_files:
        seen[mf.path] = seen.get(mf.path, 0) + 1
    for path, count in seen.items():
        if count > 1:
            issues.append(
                Issue.create(
                    issue_type=IssueType.DUPLICATE_SCAN,
                    severity=IssueSeverity.BLOCKING,
                    file_path=path,
                    message=f"Duplicate manifest entry: {path} appears {count} times",
                    detail={"type": "duplicate_entry", "count": count},
                )
            )
    return issues


def check_empty_revocation(manifest: Manifest) -> List[Issue]:
    issues: List[Issue] = []
    revocation_list = manifest.revocation_list
    if revocation_list is not None and len(revocation_list) == 0:
        issues.append(
            Issue.create(
                issue_type=IssueType.EMPTY_REVOCATION,
                severity=IssueSeverity.CONFIRMABLE,
                file_path="<manifest>",
                message="Revocation list is present but empty - please confirm this is intentional",
                detail={"field": "revocation_list"},
            )
        )
    return issues


def run_precheck(batch: AuditBatch) -> List[Issue]:
    issues: List[Issue] = []
    manifest = batch.manifest
    backup_dir = batch.backup_dir

    tz = None
    if batch.window_profile_snapshot:
        tz = batch.window_profile_snapshot.get("timezone")

    dup_issues = check_duplicate_entries(manifest.files)
    issues.extend(dup_issues)

    for mf in manifest.files:
        if mf.path in batch.scanned_files:
            continue

        ok, msg = validate_file_path(backup_dir, mf)
        if not ok:
            issues.append(
                Issue.create(
                    issue_type=IssueType.INVALID_PATH,
                    severity=IssueSeverity.BLOCKING,
                    file_path=mf.path,
                    message=msg,
                    detail={"type": "invalid_path"},
                )
            )
            continue

        exists, msg = check_file_exists(backup_dir, mf)
        if not exists:
            issues.append(
                Issue.create(
                    issue_type=IssueType.MISSING_FILE,
                    severity=IssueSeverity.BLOCKING,
                    file_path=mf.path,
                    message=msg,
                    detail={"type": "missing_file"},
                )
            )
            batch.scanned_files.append(mf.path)
            continue

        size_ok, msg = check_file_size(backup_dir, mf)
        if not size_ok:
            issues.append(
                Issue.create(
                    issue_type=IssueType.SIZE_MISMATCH,
                    severity=IssueSeverity.BLOCKING,
                    file_path=mf.path,
                    message=msg,
                    detail={"type": "size_mismatch"},
                )
            )

        hash_ok, msg = check_sha256(backup_dir, mf)
        if not hash_ok:
            issues.append(
                Issue.create(
                    issue_type=IssueType.BAD_CHECKSUM,
                    severity=IssueSeverity.BLOCKING,
                    file_path=mf.path,
                    message=msg,
                    detail={"type": "bad_checksum"},
                )
            )

        window_ok, msg = check_backup_window(
            backup_dir, mf, manifest.backup_window.start, manifest.backup_window.end, tz
        )
        if not window_ok:
            issues.append(
                Issue.create(
                    issue_type=IssueType.OUTSIDE_WINDOW,
                    severity=IssueSeverity.CONFIRMABLE,
                    file_path=mf.path,
                    message=msg,
                    detail={"type": "outside_window", "timezone": tz},
                )
            )

        bl_ok, msg = check_business_line(mf, manifest.valid_business_lines)
        if not bl_ok:
            issues.append(
                Issue.create(
                    issue_type=IssueType.UNKNOWN_BUSINESS_LINE,
                    severity=IssueSeverity.CONFIRMABLE,
                    file_path=mf.path,
                    message=msg,
                    detail={"type": "unknown_business_line"},
                )
            )

        batch.scanned_files.append(mf.path)

    issues.extend(check_empty_revocation(manifest))

    new_issues: List[Issue] = []
    for issue in issues:
        if batch.add_issue(issue):
            new_issues.append(issue)

    return new_issues
