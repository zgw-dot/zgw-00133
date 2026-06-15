from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .models import Issue, IssueSeverity, IssueType, ManifestFile


GLOBAL_CONFIG_DIR_NAME = ".backup_audit_config"
WAIVER_RULES_FILENAME = "waiver_rules.json"
WAIVER_LOG_FILENAME = "waiver_audit_log.json"


class WaiverAction(str, Enum):
    ADD = "waiver_add"
    DELETE = "waiver_delete"
    IMPORT = "waiver_import"
    EXPORT = "waiver_export"


@dataclass
class WaiverRule:
    id: str
    path_prefix: Optional[str] = None
    business_line: Optional[str] = None
    issue_type: Optional[IssueType] = None
    severity: Optional[IssueSeverity] = None
    reason: str = ""
    description: str = ""
    actor: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    expires_at: Optional[str] = None
    active: bool = True

    @classmethod
    def create(
        cls,
        path_prefix: Optional[str] = None,
        business_line: Optional[str] = None,
        issue_type: Optional[IssueType] = None,
        severity: Optional[IssueSeverity] = None,
        reason: str = "",
        description: str = "",
        actor: str = "",
        expires_at: Optional[str] = None,
    ) -> "WaiverRule":
        raw = (
            f"{path_prefix or ''}|{business_line or ''}|"
            f"{issue_type.value if issue_type else ''}|"
            f"{severity.value if severity else ''}"
        )
        rule_id = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
        return cls(
            id=rule_id,
            path_prefix=path_prefix,
            business_line=business_line,
            issue_type=issue_type,
            severity=severity,
            reason=reason,
            description=description,
            actor=actor,
            expires_at=expires_at,
        )

    def matches(self, issue: Issue, manifest_file: Optional[ManifestFile] = None) -> bool:
        if not self.active:
            return False
        if self.expires_at:
            try:
                exp = datetime.fromisoformat(self.expires_at)
                if datetime.now() > exp:
                    return False
            except ValueError:
                pass
        if self.issue_type and issue.type != self.issue_type:
            return False
        if self.severity and issue.severity != self.severity:
            return False
        if self.path_prefix:
            if not issue.file_path.startswith(self.path_prefix):
                return False
        if self.business_line:
            if manifest_file and manifest_file.business_line != self.business_line:
                return False
            if not manifest_file:
                bl_from_detail = issue.detail.get("business_line")
                if bl_from_detail and bl_from_detail != self.business_line:
                    return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.issue_type:
            d["issue_type"] = self.issue_type.value
        if self.severity:
            d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WaiverRule":
        issue_type = IssueType(data["issue_type"]) if data.get("issue_type") else None
        severity = IssueSeverity(data["severity"]) if data.get("severity") else None
        return cls(
            id=data["id"],
            path_prefix=data.get("path_prefix"),
            business_line=data.get("business_line"),
            issue_type=issue_type,
            severity=severity,
            reason=data.get("reason", ""),
            description=data.get("description", ""),
            actor=data.get("actor", ""),
            created_at=data.get("created_at", datetime.now().isoformat()),
            expires_at=data.get("expires_at"),
            active=data.get("active", True),
        )


@dataclass
class WaiverAuditLogEntry:
    action: WaiverAction
    actor: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    rule_id: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WaiverAuditLogEntry":
        return cls(
            action=WaiverAction(data["action"]),
            actor=data.get("actor", ""),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            rule_id=data.get("rule_id"),
            detail=data.get("detail", {}),
        )


class WaiverConflictError(Exception):
    pass


class WaiverValidationError(Exception):
    pass


def get_global_config_dir() -> str:
    override = os.environ.get("BACKUP_AUDIT_CONFIG_DIR")
    if override:
        return os.path.abspath(override)
    home = os.path.expanduser("~")
    return os.path.join(home, GLOBAL_CONFIG_DIR_NAME)


def get_waiver_rules_path() -> str:
    override = os.environ.get("BACKUP_AUDIT_WAIVER_RULES")
    if override:
        return os.path.abspath(override)
    return os.path.join(get_global_config_dir(), WAIVER_RULES_FILENAME)


def get_waiver_log_path() -> str:
    override = os.environ.get("BACKUP_AUDIT_WAIVER_LOG")
    if override:
        return os.path.abspath(override)
    return os.path.join(get_global_config_dir(), WAIVER_LOG_FILENAME)


class WaiverStore:
    def __init__(self, rules_path: Optional[str] = None, log_path: Optional[str] = None):
        self.rules_path = rules_path or get_waiver_rules_path()
        self.log_path = log_path or get_waiver_log_path()
        self.rules: List[WaiverRule] = []
        self.audit_log: List[WaiverAuditLogEntry] = []
        self._load()

    def _load(self) -> None:
        os.makedirs(os.path.dirname(self.rules_path), exist_ok=True)
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.rules = [WaiverRule.from_dict(r) for r in data.get("rules", [])]
            except (json.JSONDecodeError, KeyError):
                self.rules = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.audit_log = [WaiverAuditLogEntry.from_dict(e) for e in data.get("log", [])]
            except (json.JSONDecodeError, KeyError):
                self.audit_log = []

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.rules_path), exist_ok=True)
        with open(self.rules_path, "w", encoding="utf-8") as f:
            json.dump(
                {"rules": [r.to_dict() for r in self.rules]},
                f,
                ensure_ascii=False,
                indent=2,
            )
        with open(self.log_path, "w", encoding="utf-8") as f:
            json.dump(
                {"log": [e.to_dict() for e in self.audit_log]},
                f,
                ensure_ascii=False,
                indent=2,
            )

    def _log_operation(
        self,
        action: WaiverAction,
        actor: str,
        rule_id: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.audit_log.append(WaiverAuditLogEntry(
            action=action,
            actor=actor,
            rule_id=rule_id,
            detail=detail or {},
        ))

    def list_rules(self, include_expired: bool = False) -> List[WaiverRule]:
        result = []
        for r in self.rules:
            if not include_expired and r.expires_at:
                try:
                    exp = datetime.fromisoformat(r.expires_at)
                    if datetime.now() > exp:
                        continue
                except ValueError:
                    pass
            result.append(r)
        return result

    def get_rule(self, rule_id: str) -> Optional[WaiverRule]:
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None

    def find_conflicts(self, new_rule: WaiverRule) -> List[WaiverRule]:
        conflicts = []
        for existing in self.rules:
            if not existing.active:
                continue
            if existing.id == new_rule.id:
                continue

            if self._is_subset_or_superset(new_rule, existing):
                conflicts.append(existing)
        return conflicts

    @classmethod
    def _is_subset_or_superset(cls, r1: WaiverRule, r2: WaiverRule) -> bool:
        r1_covers_r2 = cls._covers(r1, r2)
        r2_covers_r1 = cls._covers(r2, r1)
        return r1_covers_r2 or r2_covers_r1

    @staticmethod
    def _covers(outer: WaiverRule, inner: WaiverRule) -> bool:
        dims = [
            (outer.issue_type, inner.issue_type, lambda a, b: a == b),
            (outer.severity, inner.severity, lambda a, b: a == b),
            (outer.path_prefix, inner.path_prefix,
             lambda a, b: b.startswith(a)),
            (outer.business_line, inner.business_line, lambda a, b: a == b),
        ]
        for outer_val, inner_val, comp in dims:
            if outer_val is None:
                continue
            if inner_val is None:
                return False
            if not comp(outer_val, inner_val):
                return False
        return True

    def check_blocking_exemption_risk(
        self,
        new_rule: WaiverRule,
        existing_blocking_count: int = 0,
    ) -> Optional[str]:
        if new_rule.severity != IssueSeverity.BLOCKING:
            return None
        too_broad = (
            new_rule.path_prefix is None
            and new_rule.business_line is None
            and new_rule.issue_type is None
        )
        if too_broad:
            return (
                "该豁免规则过于宽泛：将豁免所有 BLOCKING 级别的问题。"
                "请至少指定 path_prefix、business_line 或 issue_type 之一来缩小范围。"
            )
        return None

    def add_rule(
        self,
        rule: WaiverRule,
        actor: str,
        allow_conflict: bool = False,
    ) -> WaiverRule:
        if not rule.reason or not rule.reason.strip():
            raise WaiverValidationError("豁免规则必须提供 reason（豁免理由）")
        if not actor or not actor.strip():
            raise WaiverValidationError("必须指定操作人 actor")
        conflicts = self.find_conflicts(rule)
        if conflicts and not allow_conflict:
            conflict_ids = ", ".join(c.id for c in conflicts)
            raise WaiverConflictError(
                f"新增规则与现有规则冲突: {conflict_ids}。"
                f"冲突规则可能覆盖相同范围的问题。如确认需添加，请使用 --force 强制添加。"
            )
        risk = self.check_blocking_exemption_risk(rule)
        if risk:
            raise WaiverValidationError(risk)
        if self.get_rule(rule.id):
            raise WaiverConflictError(f"规则已存在: {rule.id}")
        self.rules.append(rule)
        self._log_operation(
            action=WaiverAction.ADD,
            actor=actor,
            rule_id=rule.id,
            detail={"rule": rule.to_dict()},
        )
        self._save()
        return rule

    def delete_rule(self, rule_id: str, actor: str) -> bool:
        rule = self.get_rule(rule_id)
        if not rule:
            return False
        self.rules = [r for r in self.rules if r.id != rule_id]
        self._log_operation(
            action=WaiverAction.DELETE,
            actor=actor,
            rule_id=rule_id,
            detail={"deleted_rule": rule.to_dict()},
        )
        self._save()
        return True

    def export_rules(self, output_path: str, actor: str) -> str:
        data = {
            "exported_at": datetime.now().isoformat(),
            "exported_by": actor,
            "rules": [r.to_dict() for r in self.rules],
        }
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        self._log_operation(
            action=WaiverAction.EXPORT,
            actor=actor,
            detail={"output_path": output_path, "rule_count": len(self.rules)},
        )
        self._save()
        return output_path

    def import_rules(
        self,
        input_path: str,
        actor: str,
        mode: str = "merge",
    ) -> Dict[str, Any]:
        if not os.path.exists(input_path):
            raise WaiverValidationError(f"导入文件不存在: {input_path}")
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        imported_rules = [WaiverRule.from_dict(r) for r in data.get("rules", [])]
        added: List[str] = []
        skipped: List[str] = []
        conflicts: List[str] = []
        if mode == "replace":
            old_count = len(self.rules)
            self.rules = []
            for r in imported_rules:
                self.rules.append(r)
                added.append(r.id)
            self._log_operation(
                action=WaiverAction.IMPORT,
                actor=actor,
                detail={
                    "mode": "replace",
                    "imported_count": len(imported_rules),
                    "old_count": old_count,
                    "added": added,
                },
            )
        else:
            for r in imported_rules:
                if self.get_rule(r.id):
                    skipped.append(r.id)
                    continue
                conflict_list = self.find_conflicts(r)
                if conflict_list:
                    conflicts.append(r.id)
                    continue
                risk = self.check_blocking_exemption_risk(r)
                if risk:
                    conflicts.append(r.id)
                    continue
                self.rules.append(r)
                added.append(r.id)
            self._log_operation(
                action=WaiverAction.IMPORT,
                actor=actor,
                detail={
                    "mode": "merge",
                    "imported_count": len(imported_rules),
                    "added": added,
                    "skipped": skipped,
                    "conflicts": conflicts,
                },
            )
        self._save()
        return {
            "added": added,
            "skipped": skipped,
            "conflicts": conflicts,
            "total_imported": len(imported_rules),
        }

    def match_issue(
        self,
        issue: Issue,
        manifest_file: Optional[ManifestFile] = None,
    ) -> Optional[WaiverRule]:
        for rule in self.list_rules():
            if rule.matches(issue, manifest_file):
                return rule
        return None

    def get_audit_log(self) -> List[WaiverAuditLogEntry]:
        return list(self.audit_log)
