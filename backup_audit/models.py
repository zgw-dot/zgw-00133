from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class IssueStatus(str, Enum):
    PENDING_FIX = "pending_fix"
    CONFIRMED = "confirmed"
    IGNORED = "ignored"
    OPEN = "open"


class IssueSeverity(str, Enum):
    BLOCKING = "blocking"
    CONFIRMABLE = "confirmable"


class IssueType(str, Enum):
    MISSING_FILE = "missing_file"
    BAD_CHECKSUM = "bad_checksum"
    SIZE_MISMATCH = "size_mismatch"
    INVALID_PATH = "invalid_path"
    OUTSIDE_WINDOW = "outside_backup_window"
    UNKNOWN_BUSINESS_LINE = "unknown_business_line"
    DUPLICATE_SCAN = "duplicate_scan"
    EMPTY_REVOCATION = "empty_revocation"


@dataclass
class Issue:
    id: str
    type: IssueType
    severity: IssueSeverity
    file_path: str
    message: str
    status: IssueStatus = IssueStatus.OPEN
    assignee: Optional[str] = None
    notes: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    detail: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        issue_type: IssueType,
        severity: IssueSeverity,
        file_path: str,
        message: str,
        detail: Optional[Dict[str, Any]] = None,
    ) -> "Issue":
        issue_id = hashlib.sha1(
            f"{issue_type.value}:{file_path}:{message}".encode("utf-8")
        ).hexdigest()[:12]
        return cls(
            id=issue_id,
            type=issue_type,
            severity=severity,
            file_path=file_path,
            message=message,
            detail=detail or {},
        )

    def update(
        self,
        status: Optional[IssueStatus] = None,
        assignee: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        if status is not None:
            self.status = status
        if assignee is not None:
            self.assignee = assignee
        if notes is not None:
            self.notes = notes
        self.updated_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Issue":
        return cls(
            id=data["id"],
            type=IssueType(data["type"]),
            severity=IssueSeverity(data["severity"]),
            file_path=data["file_path"],
            message=data["message"],
            status=IssueStatus(data["status"]),
            assignee=data.get("assignee"),
            notes=data.get("notes"),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            detail=data.get("detail", {}),
        )


@dataclass
class ManifestFile:
    path: str
    sha256: str
    size: int
    business_line: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ManifestFile":
        return cls(
            path=data["path"],
            sha256=data["sha256"],
            size=data["size"],
            business_line=data.get("business_line"),
        )


@dataclass
class BackupWindow:
    start: str
    end: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BackupWindow":
        return cls(start=data["start"], end=data["end"])


@dataclass
class Manifest:
    batch_id: str
    backup_window: BackupWindow
    valid_business_lines: List[str]
    files: List[ManifestFile]
    revocation_list: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "backup_window": self.backup_window.to_dict(),
            "valid_business_lines": self.valid_business_lines,
            "files": [f.to_dict() for f in self.files],
            "revocation_list": self.revocation_list,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Manifest":
        return cls(
            batch_id=data["batch_id"],
            backup_window=BackupWindow.from_dict(data["backup_window"]),
            valid_business_lines=data.get("valid_business_lines", []),
            files=[ManifestFile.from_dict(f) for f in data.get("files", [])],
            revocation_list=data.get("revocation_list", []),
        )


@dataclass
class AuditBatch:
    id: str
    manifest_path: str
    backup_dir: str
    manifest: Manifest
    issues: List[Issue] = field(default_factory=list)
    scanned_files: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    storage_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "manifest_path": self.manifest_path,
            "backup_dir": self.backup_dir,
            "manifest": self.manifest.to_dict(),
            "issues": [i.to_dict() for i in self.issues],
            "scanned_files": self.scanned_files,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditBatch":
        return cls(
            id=data["id"],
            manifest_path=data["manifest_path"],
            backup_dir=data["backup_dir"],
            manifest=Manifest.from_dict(data["manifest"]),
            issues=[Issue.from_dict(i) for i in data.get("issues", [])],
            scanned_files=data.get("scanned_files", []),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

    def save(self, storage_dir: str) -> str:
        os.makedirs(storage_dir, exist_ok=True)
        path = os.path.join(storage_dir, f"batch_{self.id}.json")
        self.updated_at = datetime.now().isoformat()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
        self.storage_path = path
        return path

    @classmethod
    def load(cls, path: str) -> "AuditBatch":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        batch = cls.from_dict(data)
        batch.storage_path = path
        return batch

    def add_issue(self, issue: Issue) -> bool:
        for existing in self.issues:
            if existing.id == issue.id:
                return False
        self.issues.append(issue)
        self.updated_at = datetime.now().isoformat()
        return True

    def get_issue(self, issue_id: str) -> Optional[Issue]:
        for issue in self.issues:
            if issue.id == issue_id:
                return issue
        return None

    def count_by_severity(self) -> Dict[str, int]:
        result = {"blocking": 0, "confirmable": 0}
        for issue in self.issues:
            result[issue.severity.value] += 1
        return result

    def count_by_status(self) -> Dict[str, int]:
        result = {s.value: 0 for s in IssueStatus}
        for issue in self.issues:
            result[issue.status.value] += 1
        return result
