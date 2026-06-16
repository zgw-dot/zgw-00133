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
WAIVER_TRANSACTIONS_FILENAME = "waiver_transactions.json"


class WaiverSource(str, Enum):
    MANUAL = "manual"
    BATCH_IMPORT = "batch_import"


class WaiverTransactionStatus(str, Enum):
    PENDING = "pending"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"


class WaiverAction(str, Enum):
    ADD = "waiver_add"
    DELETE = "waiver_delete"
    IMPORT = "waiver_import"
    EXPORT = "waiver_export"
    ROLLBACK = "waiver_rollback"
    PRECHECK = "waiver_precheck"


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
    source: WaiverSource = WaiverSource.MANUAL
    transaction_id: Optional[str] = None

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
        source: WaiverSource = WaiverSource.MANUAL,
        transaction_id: Optional[str] = None,
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
            source=source,
            transaction_id=transaction_id,
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
        if self.source:
            d["source"] = self.source.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WaiverRule":
        issue_type = IssueType(data["issue_type"]) if data.get("issue_type") else None
        severity = IssueSeverity(data["severity"]) if data.get("severity") else None
        source = WaiverSource(data["source"]) if data.get("source") else WaiverSource.MANUAL
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
            source=source,
            transaction_id=data.get("transaction_id"),
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


class WaiverTransactionError(Exception):
    pass


@dataclass
class WaiverPrecheckResult:
    total_rules: int = 0
    new_rules: List[WaiverRule] = field(default_factory=list)
    existing_rules: List[WaiverRule] = field(default_factory=list)
    conflicting_rules: List[Dict[str, Any]] = field(default_factory=list)
    expired_rules: List[WaiverRule] = field(default_factory=list)
    invalid_rules: List[Dict[str, Any]] = field(default_factory=list)
    affected_batches: List[str] = field(default_factory=list)
    file_errors: List[str] = field(default_factory=list)
    source_file: str = ""
    mode: str = "merge"

    @property
    def can_commit(self) -> bool:
        return len(self.file_errors) == 0 and len(self.invalid_rules) == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_rules": self.total_rules,
            "new_count": len(self.new_rules),
            "new_rules": [r.to_dict() for r in self.new_rules],
            "existing_count": len(self.existing_rules),
            "existing_rules": [r.to_dict() for r in self.existing_rules],
            "conflicting_count": len(self.conflicting_rules),
            "conflicting_rules": self.conflicting_rules,
            "expired_count": len(self.expired_rules),
            "expired_rules": [r.to_dict() for r in self.expired_rules],
            "invalid_count": len(self.invalid_rules),
            "invalid_rules": self.invalid_rules,
            "affected_batches": self.affected_batches,
            "file_errors": self.file_errors,
            "source_file": self.source_file,
            "mode": self.mode,
            "can_commit": self.can_commit,
        }


@dataclass
class WaiverTransaction:
    id: str
    actor: str
    timestamp: str
    status: WaiverTransactionStatus
    mode: str
    source_file: str
    rules_before: List[Dict[str, Any]] = field(default_factory=list)
    rules_after: List[Dict[str, Any]] = field(default_factory=list)
    imported_rule_ids: List[str] = field(default_factory=list)
    precheck_result: Optional[Dict[str, Any]] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "status": self.status.value,
            "mode": self.mode,
            "source_file": self.source_file,
            "rules_before": self.rules_before,
            "rules_after": self.rules_after,
            "imported_rule_ids": self.imported_rule_ids,
            "precheck_result": self.precheck_result,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WaiverTransaction":
        return cls(
            id=data["id"],
            actor=data["actor"],
            timestamp=data["timestamp"],
            status=WaiverTransactionStatus(data["status"]),
            mode=data["mode"],
            source_file=data["source_file"],
            rules_before=data.get("rules_before", []),
            rules_after=data.get("rules_after", []),
            imported_rule_ids=data.get("imported_rule_ids", []),
            precheck_result=data.get("precheck_result"),
            detail=data.get("detail", {}),
        )


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


def get_waiver_transactions_path() -> str:
    override = os.environ.get("BACKUP_AUDIT_WAIVER_TRANSACTIONS")
    if override:
        return os.path.abspath(override)
    return os.path.join(get_global_config_dir(), WAIVER_TRANSACTIONS_FILENAME)


class WaiverStore:
    def __init__(self, rules_path: Optional[str] = None, log_path: Optional[str] = None,
                 transactions_path: Optional[str] = None):
        self.rules_path = rules_path or get_waiver_rules_path()
        self.log_path = log_path or get_waiver_log_path()
        self.transactions_path = transactions_path or get_waiver_transactions_path()
        self.rules: List[WaiverRule] = []
        self.audit_log: List[WaiverAuditLogEntry] = []
        self.transactions: List[WaiverTransaction] = []
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
        if os.path.exists(self.transactions_path):
            try:
                with open(self.transactions_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.transactions = [WaiverTransaction.from_dict(t) for t in data.get("transactions", [])]
            except (json.JSONDecodeError, KeyError):
                self.transactions = []

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
        with open(self.transactions_path, "w", encoding="utf-8") as f:
            json.dump(
                {"transactions": [t.to_dict() for t in self.transactions]},
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
        rule.source = WaiverSource.MANUAL
        rule.transaction_id = None
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

    def validate_import_file(self, input_path: str) -> List[str]:
        errors: List[str] = []
        if not os.path.exists(input_path):
            errors.append(f"导入文件不存在: {input_path}")
            return errors
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"JSON 格式错误: {e}")
            return errors
        except UnicodeDecodeError as e:
            errors.append(f"文件编码错误: {e}")
            return errors

        if not isinstance(data, dict):
            errors.append("文件根节点必须是对象 (dict)")
            return errors

        if "rules" not in data:
            errors.append("缺少必填字段 'rules'")
            return errors

        if not isinstance(data["rules"], list):
            errors.append("'rules' 必须是数组类型")
            return errors

        for idx, rule_data in enumerate(data["rules"]):
            if not isinstance(rule_data, dict):
                errors.append(f"rules[{idx}]: 必须是对象类型")
                continue
            if "id" not in rule_data:
                errors.append(f"rules[{idx}]: 缺少必填字段 'id'")
            if "reason" not in rule_data or not str(rule_data.get("reason", "")).strip():
                errors.append(f"rules[{idx}]: 缺少必填字段 'reason' 或为空")
            if rule_data.get("expires_at"):
                try:
                    datetime.fromisoformat(str(rule_data["expires_at"]))
                except (ValueError, TypeError):
                    errors.append(f"rules[{idx}]: expires_at 格式无效，应为 ISO 格式")
            if rule_data.get("issue_type"):
                try:
                    IssueType(str(rule_data["issue_type"]))
                except (ValueError, TypeError):
                    errors.append(f"rules[{idx}]: issue_type '{rule_data['issue_type']}' 不是有效值")
            if rule_data.get("severity"):
                try:
                    IssueSeverity(str(rule_data["severity"]))
                except (ValueError, TypeError):
                    errors.append(f"rules[{idx}]: severity '{rule_data['severity']}' 不是有效值")
        return errors

    def _is_rule_expired(self, rule: WaiverRule) -> bool:
        if not rule.expires_at:
            return False
        try:
            exp = datetime.fromisoformat(rule.expires_at)
            return datetime.now() > exp
        except ValueError:
            return False

    def precheck_import(self, input_path: str, mode: str = "merge") -> WaiverPrecheckResult:
        result = WaiverPrecheckResult(source_file=os.path.abspath(input_path), mode=mode)

        file_errors = self.validate_import_file(input_path)
        if file_errors:
            result.file_errors = file_errors
            return result

        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        imported_rules_data = data.get("rules", [])
        result.total_rules = len(imported_rules_data)

        for idx, rule_data in enumerate(imported_rules_data):
            try:
                rule = WaiverRule.from_dict(rule_data)
            except Exception as e:
                result.invalid_rules.append({
                    "index": idx,
                    "error": str(e),
                    "data": rule_data,
                })
                continue

            if self._is_rule_expired(rule):
                result.expired_rules.append(rule)
                continue

            existing = self.get_rule(rule.id)
            if existing:
                result.existing_rules.append(rule)
                continue

            conflicts = self.find_conflicts(rule)
            if conflicts:
                result.conflicting_rules.append({
                    "rule": rule.to_dict(),
                    "conflict_ids": [c.id for c in conflicts],
                    "conflict_reasons": [
                        f"与规则 {c.id} 存在范围重叠" for c in conflicts
                    ],
                })
                continue

            risk = self.check_blocking_exemption_risk(rule)
            if risk:
                result.conflicting_rules.append({
                    "rule": rule.to_dict(),
                    "conflict_ids": [],
                    "conflict_reasons": [risk],
                })
                continue

            result.new_rules.append(rule)

        return result

    def get_last_committed_transaction(self) -> Optional[WaiverTransaction]:
        for tx in reversed(self.transactions):
            if tx.status == WaiverTransactionStatus.COMMITTED:
                return tx
        return None

    def list_transactions(self, limit: int = 10) -> List[WaiverTransaction]:
        return list(reversed(self.transactions[-limit:]))

    def _generate_transaction_id(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_part = uuid.uuid4().hex[:8]
        return f"TX-{timestamp}-{random_part}"

    def commit_import(
        self,
        precheck_result: WaiverPrecheckResult,
        actor: str,
        mode: str = "merge",
    ) -> Dict[str, Any]:
        if not precheck_result.can_commit:
            raise WaiverTransactionError(
                "预演未通过，存在文件错误或无效规则，无法执行导入。"
                "请先修复问题后重新预演。"
            )

        transaction_id = self._generate_transaction_id()
        rules_before = [r.to_dict() for r in self.rules]

        added: List[str] = []
        skipped: List[str] = []
        conflicts: List[str] = []
        imported_rule_ids: List[str] = []

        if mode == "replace":
            self.rules = []
            for r in precheck_result.new_rules + precheck_result.existing_rules:
                rule = WaiverRule.from_dict(r.to_dict())
                rule.source = WaiverSource.BATCH_IMPORT
                rule.transaction_id = transaction_id
                self.rules.append(rule)
                added.append(rule.id)
                imported_rule_ids.append(rule.id)
        else:
            for r in precheck_result.existing_rules:
                skipped.append(r.id)
            for r in precheck_result.conflicting_rules:
                conflicts.append(r["rule"]["id"])
            for r in precheck_result.new_rules:
                rule = WaiverRule.from_dict(r.to_dict())
                rule.source = WaiverSource.BATCH_IMPORT
                rule.transaction_id = transaction_id
                self.rules.append(rule)
                added.append(rule.id)
                imported_rule_ids.append(rule.id)

        rules_after = [r.to_dict() for r in self.rules]

        transaction = WaiverTransaction(
            id=transaction_id,
            actor=actor,
            timestamp=datetime.now().isoformat(),
            status=WaiverTransactionStatus.COMMITTED,
            mode=mode,
            source_file=precheck_result.source_file,
            rules_before=rules_before,
            rules_after=rules_after,
            imported_rule_ids=imported_rule_ids,
            precheck_result=precheck_result.to_dict(),
            detail={
                "added": added,
                "skipped": skipped,
                "conflicts": conflicts,
            },
        )
        self.transactions.append(transaction)

        self._log_operation(
            action=WaiverAction.IMPORT,
            actor=actor,
            detail={
                "transaction_id": transaction_id,
                "mode": mode,
                "imported_count": len(imported_rule_ids),
                "added": added,
                "skipped": skipped,
                "conflicts": conflicts,
            },
        )

        self._save()

        return {
            "transaction_id": transaction_id,
            "added": added,
            "skipped": skipped,
            "conflicts": conflicts,
            "total_imported": len(imported_rule_ids),
        }

    def rollback_last_import(self, actor: str) -> Dict[str, Any]:
        last_tx = self.get_last_committed_transaction()
        if not last_tx:
            raise WaiverTransactionError("没有可回滚的导入事务。")

        imported_ids = set(last_tx.imported_rule_ids)

        manual_rules = [
            r for r in self.rules
            if r.source == WaiverSource.MANUAL
        ]

        other_batch_rules = [
            r for r in self.rules
            if r.source == WaiverSource.BATCH_IMPORT
            and r.transaction_id != last_tx.id
        ]

        removed_ids = [
            r.id for r in self.rules
            if r.id in imported_ids
        ]

        preserved_manual_count = len(manual_rules)
        removed_count = len(removed_ids)

        self.rules = manual_rules + other_batch_rules

        last_tx.status = WaiverTransactionStatus.ROLLED_BACK

        self._log_operation(
            action=WaiverAction.ROLLBACK,
            actor=actor,
            detail={
                "transaction_id": last_tx.id,
                "removed_count": removed_count,
                "removed_ids": removed_ids,
                "manual_rules_preserved": preserved_manual_count,
                "other_batch_rules_preserved": len(other_batch_rules),
            },
        )

        self._save()

        return {
            "transaction_id": last_tx.id,
            "removed_count": removed_count,
            "removed_ids": removed_ids,
            "manual_rules_preserved": preserved_manual_count,
        }

    def import_rules(
        self,
        input_path: str,
        actor: str,
        mode: str = "merge",
        replace_confirm_manual_delete: bool = False,
    ) -> Dict[str, Any]:
        precheck_result = self.precheck_import(input_path, mode=mode)
        if not precheck_result.can_commit:
            error_msg = "导入文件校验失败：\n"
            for err in precheck_result.file_errors:
                error_msg += f"  - {err}\n"
            for inv in precheck_result.invalid_rules:
                error_msg += f"  - rules[{inv['index']}]: {inv['error']}\n"
            raise WaiverValidationError(error_msg.strip())

        if mode == "replace":
            manual_rules = [
                r for r in self.rules
                if r.source == WaiverSource.MANUAL
            ]
            if manual_rules and not replace_confirm_manual_delete:
                raise WaiverTransactionError(
                    f"replace 模式下检测到 {len(manual_rules)} 条手工创建的规则。"
                    "为避免误删手工规则，replace 模式需要确认将删除所有手工规则。"
                    "请使用 --replace-confirm-manual-delete 参数确认此操作。"
                )

        return self.commit_import(precheck_result, actor, mode=mode)

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
