from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .waiver import WaiverStore, get_global_config_dir

SNAPSHOTS_DIR_NAME = "waiver_snapshots"
SNAPSHOT_AUDIT_LOG_FILENAME = "snapshot_audit_log.json"


class SnapshotAction(str, Enum):
    CREATE = "snapshot_create"
    SEAL = "snapshot_seal"
    FORK = "snapshot_fork"
    APPEND = "snapshot_append"
    EXPORT = "snapshot_export"
    SHOW = "snapshot_show"


class SnapshotStatus(str, Enum):
    DRAFT = "draft"
    SEALED = "sealed"
    FORKED = "forked"


@dataclass
class SnapshotAuditLogEntry:
    action: SnapshotAction
    actor: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    snapshot_name: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "snapshot_name": self.snapshot_name,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SnapshotAuditLogEntry":
        return cls(
            action=SnapshotAction(data["action"]),
            actor=data.get("actor", ""),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            snapshot_name=data.get("snapshot_name"),
            detail=data.get("detail", {}),
        )


class SnapshotSealedError(Exception):
    pass


class SnapshotNameConflictError(Exception):
    pass


def _get_snapshots_dir() -> str:
    return os.path.join(get_global_config_dir(), SNAPSHOTS_DIR_NAME)


def _config_dir_fingerprint() -> str:
    config_dir = get_global_config_dir()
    return hashlib.sha256(config_dir.encode("utf-8")).hexdigest()[:16]


@dataclass
class SnapshotRecord:
    command: str
    timestamp: str
    success: bool
    output_summary: str
    transaction_id: Optional[str] = None
    affected_batches: List[Dict[str, Any]] = field(default_factory=list)
    config_summary: Optional[Dict[str, Any]] = None
    gap_warning: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "command": self.command,
            "timestamp": self.timestamp,
            "success": self.success,
            "output_summary": self.output_summary,
        }
        if self.transaction_id:
            d["transaction_id"] = self.transaction_id
        if self.affected_batches:
            d["affected_batches"] = self.affected_batches
        if self.config_summary:
            d["config_summary"] = self.config_summary
        if self.gap_warning:
            d["gap_warning"] = self.gap_warning
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SnapshotRecord":
        return cls(
            command=data["command"],
            timestamp=data["timestamp"],
            success=data["success"],
            output_summary=data["output_summary"],
            transaction_id=data.get("transaction_id"),
            affected_batches=data.get("affected_batches", []),
            config_summary=data.get("config_summary"),
            gap_warning=data.get("gap_warning"),
        )


@dataclass
class OperationSnapshot:
    name: str
    created_at: str
    updated_at: str
    records: List[SnapshotRecord] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    sealed: bool = False
    sealed_at: Optional[str] = None
    forked_from: Optional[str] = None
    config_dir_fingerprint: Optional[str] = None
    export_history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "records": [r.to_dict() for r in self.records],
            "meta": self.meta,
            "sealed": self.sealed,
            "sealed_at": self.sealed_at,
            "forked_from": self.forked_from,
            "config_dir_fingerprint": self.config_dir_fingerprint,
            "export_history": self.export_history,
        }
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OperationSnapshot":
        return cls(
            name=data["name"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            records=[SnapshotRecord.from_dict(r) for r in data.get("records", [])],
            meta=data.get("meta", {}),
            sealed=data.get("sealed", False),
            sealed_at=data.get("sealed_at"),
            forked_from=data.get("forked_from"),
            config_dir_fingerprint=data.get("config_dir_fingerprint"),
            export_history=data.get("export_history", []),
        )

    def add_record(self, record: SnapshotRecord) -> None:
        if self.sealed:
            raise SnapshotSealedError(
                f"快照 '{self.name}' 已于 {self.sealed_at} 封版，"
                f"不能追加记录。如需续写，请使用 --append 参数；"
                f"如需从该快照分叉，请使用 --fork-from 参数。"
            )
        self.records.append(record)
        self.updated_at = datetime.now().isoformat()

    def add_record_forced(self, record: SnapshotRecord) -> None:
        self.records.append(record)
        self.updated_at = datetime.now().isoformat()

    def seal(self, actor: str = "") -> None:
        if self.sealed:
            return
        self.sealed = True
        self.sealed_at = datetime.now().isoformat()
        self.meta["sealed_by"] = actor
        self.updated_at = self.sealed_at

    def get_linked_transaction_ids(self) -> List[str]:
        return [r.transaction_id for r in self.records if r.transaction_id]


class SnapshotStore:
    def __init__(self, snapshots_dir: Optional[str] = None):
        self.snapshots_dir = snapshots_dir or _get_snapshots_dir()
        os.makedirs(self.snapshots_dir, exist_ok=True)
        self.audit_log_path = os.path.join(self.snapshots_dir, SNAPSHOT_AUDIT_LOG_FILENAME)
        self.audit_log: List[SnapshotAuditLogEntry] = []
        self._load_audit_log()

    def _snapshot_path(self, name: str) -> str:
        safe_name = name.replace("/", "_").replace("\\", "_").replace("..", "_")
        return os.path.join(self.snapshots_dir, f"{safe_name}.json")

    def _load_audit_log(self) -> None:
        if os.path.exists(self.audit_log_path):
            try:
                with open(self.audit_log_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.audit_log = [SnapshotAuditLogEntry.from_dict(e) for e in data.get("log", [])]
            except (json.JSONDecodeError, KeyError):
                self.audit_log = []

    def _save_audit_log(self) -> None:
        with open(self.audit_log_path, "w", encoding="utf-8") as f:
            json.dump(
                {"log": [e.to_dict() for e in self.audit_log]},
                f,
                ensure_ascii=False,
                indent=2,
            )

    def _log_operation(
        self,
        action: SnapshotAction,
        actor: str,
        snapshot_name: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.audit_log.append(SnapshotAuditLogEntry(
            action=action,
            actor=actor,
            snapshot_name=snapshot_name,
            detail=detail or {},
        ))
        self._save_audit_log()

    def get_snapshot_status_detail(self, name: str) -> Optional[Dict[str, Any]]:
        snapshot = self.load(name)
        if snapshot is None:
            return None
        status = self._classify_status(snapshot)
        next_steps = self._suggest_next_steps(snapshot)
        return {
            "name": snapshot.name,
            "status": status.value,
            "status_label": self._get_status_label(snapshot),
            "sealed": snapshot.sealed,
            "sealed_at": snapshot.sealed_at,
            "forked_from": snapshot.forked_from,
            "record_count": len(snapshot.records),
            "created_at": snapshot.created_at,
            "updated_at": snapshot.updated_at,
            "config_dir_fingerprint": snapshot.config_dir_fingerprint,
            "export_count": len(snapshot.export_history),
            "next_steps": next_steps,
            "stuck_at": self._get_stuck_stage(snapshot),
        }

    @staticmethod
    def _classify_status(snapshot: OperationSnapshot) -> SnapshotStatus:
        if snapshot.forked_from:
            return SnapshotStatus.FORKED
        if snapshot.sealed:
            return SnapshotStatus.SEALED
        return SnapshotStatus.DRAFT

    def _get_status_label(self, snapshot: OperationSnapshot) -> str:
        status = self._classify_status(snapshot)
        if status == SnapshotStatus.SEALED:
            return "已封版"
        if status == SnapshotStatus.FORKED:
            if snapshot.sealed:
                return "已分叉且已封版"
            return "已分叉 (未封版，仍可追加)"
        return "草稿（未封版，仍可追加）"

    @staticmethod
    def _get_stuck_stage(snapshot: OperationSnapshot) -> str:
        if snapshot.sealed:
            if snapshot.export_history:
                return "封版且已导出，可用于对账归档"
            return "已封版但尚未导出，建议导出后归档"
        if len(snapshot.records) == 0:
            return "空草稿，尚未写入任何操作记录"
        if snapshot.forked_from:
            return "分叉后的草稿，可继续追加操作或封版"
        return "草稿状态，已有操作记录，建议封版前核对"

    @staticmethod
    def _suggest_next_steps(snapshot: OperationSnapshot) -> List[str]:
        steps = []
        if snapshot.sealed:
            steps.append(f"使用 --append 续写封版快照（仅在确认需要补充时使用）")
            steps.append(f"使用 --fork-from {snapshot.name} 从该快照分叉出新快照")
            steps.append(f"使用 waiver snapshot export {snapshot.name} 导出快照用于归档对账")
        else:
            steps.append(f"使用 --append 向已有快照追加记录")
            steps.append(f"使用 waiver snapshot seal {snapshot.name} 封版快照")
            steps.append(f"使用 --fork-from {snapshot.name} 从该快照分叉出新快照")
        return steps

    def get_audit_log(self, limit: Optional[int] = None) -> List[SnapshotAuditLogEntry]:
        if limit and limit > 0:
            return list(reversed(self.audit_log[-limit:]))
        return list(self.audit_log)

    def create(self, name: str, record: Optional[SnapshotRecord] = None, actor: str = "") -> OperationSnapshot:
        path = self._snapshot_path(name)
        if os.path.exists(path):
            detail = self.get_snapshot_status_detail(name)
            if detail is not None:
                status_label = detail["status_label"]
                stuck_at = detail["stuck_at"]
                next_steps = detail["next_steps"]
                lines = [
                    f"快照名称 '{name}' 已存在。",
                    f"  当前状态: {status_label}",
                    f"  记录条数: {detail['record_count']}",
                    f"  创建时间: {detail['created_at']}",
                    f"  最后更新: {detail['updated_at']}",
                ]
                if detail["sealed"]:
                    lines.append(f"  封版时间: {detail['sealed_at']}")
                if detail["forked_from"]:
                    lines.append(f"  分叉自: {detail['forked_from']}")
                lines.append(f"  当前阶段: {stuck_at}")
                lines.append("")
                lines.append("建议操作:")
                for i, step in enumerate(next_steps, 1):
                    lines.append(f"  {i}. {step}")
                lines.append(f"  {len(next_steps) + 1}. 使用不同的名称创建新快照")
                raise SnapshotNameConflictError("\n".join(lines))
        now = datetime.now().isoformat()
        snapshot = OperationSnapshot(
            name=name,
            created_at=now,
            updated_at=now,
            records=[record] if record else [],
            config_dir_fingerprint=_config_dir_fingerprint(),
        )
        self._save(snapshot)
        self._log_operation(
            action=SnapshotAction.CREATE,
            actor=actor,
            snapshot_name=name,
            detail={
                "record_count": len(snapshot.records),
                "config_dir_fingerprint": snapshot.config_dir_fingerprint,
            },
        )
        return snapshot

    def append(self, name: str, record: SnapshotRecord, allow_sealed: bool = False, actor: str = "") -> OperationSnapshot:
        snapshot = self.load(name)
        if snapshot is None:
            raise ValueError(f"快照 '{name}' 不存在，请先使用 'waiver snapshot create {name}' 创建。")
        if snapshot.sealed and not allow_sealed:
            raise SnapshotSealedError(
                f"快照 '{name}' 已于 {snapshot.sealed_at} 封版，不能追加记录。\n"
                f"如需续写封版快照，必须使用 --snapshot-append 参数；\n"
                f"如需分叉出新快照，请使用 --snapshot-fork-from 参数。"
            )
        snapshot.add_record_forced(record)
        self._save(snapshot)
        self._log_operation(
            action=SnapshotAction.APPEND,
            actor=actor,
            snapshot_name=name,
            detail={
                "record_command": record.command,
                "success": record.success,
                "total_records": len(snapshot.records),
                "sealed_before_append": snapshot.sealed,
            },
        )
        return snapshot

    def seal(self, name: str, actor: str = "") -> OperationSnapshot:
        snapshot = self.load(name)
        if snapshot is None:
            raise ValueError(f"快照 '{name}' 不存在。")
        if snapshot.sealed:
            detail = self.get_snapshot_status_detail(name)
            raise ValueError(
                f"快照 '{name}' 已于 {snapshot.sealed_at} 封版，不能重复封版。\n"
                f"当前阶段: {detail['stuck_at'] if detail else '未知'}\n"
                f"建议: 使用 --snapshot-append 续写，或使用 --fork-from 分叉。"
            )
        snapshot.seal(actor)
        self._save(snapshot)
        self._log_operation(
            action=SnapshotAction.SEAL,
            actor=actor,
            snapshot_name=name,
            detail={
                "record_count": len(snapshot.records),
                "sealed_at": snapshot.sealed_at,
            },
        )
        return snapshot

    def fork_from(self, source_name: str, new_name: str, record: Optional[SnapshotRecord] = None, actor: str = "") -> OperationSnapshot:
        source = self.load(source_name)
        if source is None:
            raise ValueError(f"源快照 '{source_name}' 不存在，无法分叉。请先创建或使用其他源快照。")
        new_path = self._snapshot_path(new_name)
        if os.path.exists(new_path):
            detail = self.get_snapshot_status_detail(new_name)
            if detail is not None:
                raise SnapshotNameConflictError(
                    f"目标快照名称 '{new_name}' 已存在。\n"
                    f"  当前状态: {detail['status_label']}\n"
                    f"  记录条数: {detail['record_count']}\n"
                    f"  当前阶段: {detail['stuck_at']}\n"
                    f"建议: 使用其他名称分叉，或直接向已有快照追加记录。"
                )
        now = datetime.now().isoformat()
        import copy
        new_records = copy.deepcopy(source.records)
        if record:
            new_records.append(record)
        new_snapshot = OperationSnapshot(
            name=new_name,
            created_at=now,
            updated_at=now,
            records=new_records,
            meta={"forked_from": source_name, "forked_at": now},
            forked_from=source_name,
            config_dir_fingerprint=_config_dir_fingerprint(),
        )
        self._save(new_snapshot)
        self._log_operation(
            action=SnapshotAction.FORK,
            actor=actor,
            snapshot_name=new_name,
            detail={
                "forked_from": source_name,
                "inherited_record_count": len(source.records),
                "new_record_added": record is not None,
            },
        )
        return new_snapshot

    def load(self, name: str) -> Optional[OperationSnapshot]:
        path = self._snapshot_path(name)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return OperationSnapshot.from_dict(data)

    def list_snapshots(self) -> List[Dict[str, Any]]:
        results = []
        if not os.path.isdir(self.snapshots_dir):
            return results
        for fname in sorted(os.listdir(self.snapshots_dir)):
            if not fname.endswith(".json"):
                continue
            path = os.path.join(self.snapshots_dir, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                results.append({
                    "name": data["name"],
                    "created_at": data["created_at"],
                    "updated_at": data["updated_at"],
                    "record_count": len(data.get("records", [])),
                    "sealed": data.get("sealed", False),
                    "sealed_at": data.get("sealed_at"),
                    "forked_from": data.get("forked_from"),
                })
            except Exception:
                continue
        return results

    def _save(self, snapshot: OperationSnapshot) -> None:
        path = self._snapshot_path(snapshot.name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snapshot.to_dict(), f, ensure_ascii=False, indent=2)

    def check_staleness(self, name: str, store: Optional[WaiverStore] = None) -> List[Dict[str, Any]]:
        snapshot = self.load(name)
        if snapshot is None:
            return [{"type": "missing", "message": f"快照 '{name}' 不存在。"}]

        warnings: List[Dict[str, Any]] = []

        current_fingerprint = _config_dir_fingerprint()
        if snapshot.config_dir_fingerprint and snapshot.config_dir_fingerprint != current_fingerprint:
            warnings.append({
                "type": "config_dir_changed",
                "message": (
                    f"快照创建时的配置目录指纹为 {snapshot.config_dir_fingerprint}，"
                    f"当前为 {current_fingerprint}，配置目录可能已变更，"
                    f"快照中的配置摘要和事务引用可能不再准确。"
                ),
                "snapshot_fingerprint": snapshot.config_dir_fingerprint,
                "current_fingerprint": current_fingerprint,
            })

        if store is not None:
            tx_warnings = self.validate_transactions(name, store)
            for w in tx_warnings:
                if "回滚" in w or "rolled_back" in w.lower():
                    warnings.append({
                        "type": "transaction_rolled_back",
                        "message": w,
                    })
                elif "不存在" in w:
                    warnings.append({
                        "type": "transaction_missing",
                        "message": w,
                    })
                else:
                    warnings.append({
                        "type": "transaction_inconsistent",
                        "message": w,
                    })

        if snapshot.export_history:
            last_export = snapshot.export_history[-1]
            last_export_at = last_export.get("timestamp", "")
            last_record_at = snapshot.updated_at
            try:
                if last_export_at and last_record_at:
                    export_dt = datetime.fromisoformat(last_export_at)
                    record_dt = datetime.fromisoformat(last_record_at)
                    if record_dt > export_dt:
                        warnings.append({
                            "type": "export_stale",
                            "message": (
                                f"快照在最后一次导出 ({last_export_at}) 后有新记录 ({last_record_at})，"
                                f"已导出的文件可能已过期，建议重新导出。"
                            ),
                            "last_export_at": last_export_at,
                            "last_record_at": last_record_at,
                        })
            except (ValueError, TypeError):
                pass

        return warnings

    def record_export(self, name: str, export_format: str, output_path: str, actor: str = "") -> None:
        snapshot = self.load(name)
        if snapshot is None:
            return
        export_ts = datetime.now().isoformat()
        snapshot.export_history.append({
            "format": export_format,
            "output_path": output_path,
            "timestamp": export_ts,
        })
        self._save(snapshot)
        self._log_operation(
            action=SnapshotAction.EXPORT,
            actor=actor,
            snapshot_name=name,
            detail={
                "format": export_format,
                "output_path": output_path,
                "timestamp": export_ts,
                "total_export_count": len(snapshot.export_history),
            },
        )

    def export_markdown(self, name: str, store: Optional[WaiverStore] = None) -> str:
        snapshot = self.load(name)
        if snapshot is None:
            raise ValueError(f"快照 '{name}' 不存在。")

        staleness = self.check_staleness(name, store)
        tx_validations = self.validate_transactions(name, store) if store else []
        fail_validations = self.validate_failed_records(name)

        lines = [
            f"# 操作快照: {snapshot.name}",
            "",
            f"- 创建时间: {snapshot.created_at}",
            f"- 最后更新: {snapshot.updated_at}",
            f"- 记录条数: {len(snapshot.records)}",
        ]

        if snapshot.sealed:
            lines.append(f"- **已封版**: {snapshot.sealed_at}")
            lines.append(f"- 封版人: {snapshot.meta.get('sealed_by', '未知')}")
        else:
            lines.append(f"- 状态: 未封版 (可追加)")

        if snapshot.forked_from:
            lines.append(f"- 分叉自: {snapshot.forked_from}")

        if snapshot.config_dir_fingerprint:
            lines.append(f"- 配置目录指纹: {snapshot.config_dir_fingerprint}")

        lines.append("")

        if staleness:
            lines.append("## ⚠ 失效提示")
            for sw in staleness:
                lines.append(f"- **[{sw['type']}]** {sw['message']}")
            lines.append("")

        if tx_validations:
            lines.append("## 事务校验结果")
            for w in tx_validations:
                lines.append(f"- [WARN] {w}")
            lines.append("")

        if fail_validations:
            lines.append("## 失败记录校验")
            for w in fail_validations:
                lines.append(f"- [WARN] {w}")
            lines.append("")

        config_summaries = [r.config_summary for r in snapshot.records if r.config_summary]
        if config_summaries:
            lines.append("## 配置摘要")
            latest_config = config_summaries[-1]
            for k, v in latest_config.items():
                lines.append(f"- {k}: {v}")
            lines.append("")

        lines.append("## 操作记录")
        lines.append("")

        for i, rec in enumerate(snapshot.records, 1):
            status = "[OK]" if rec.success else "[FAIL]"
            lines.append(f"### {i}. {status} {rec.command}")
            lines.append(f"- 时间: {rec.timestamp}")
            if rec.transaction_id:
                lines.append(f"- 事务ID: {rec.transaction_id}")
            lines.append(f"- 输出摘要: {rec.output_summary}")
            if rec.affected_batches:
                lines.append(f"- 受影响批次:")
                for ab in rec.affected_batches:
                    lines.append(f"  - 批次 {ab['batch_id']}: {ab['affected_count']} 个问题")
            if rec.config_summary:
                lines.append(f"- 配置摘要:")
                for k, v in rec.config_summary.items():
                    lines.append(f"  - {k}: {v}")
            if rec.gap_warning:
                lines.append(f"- **缺口警告**: {rec.gap_warning}")
            lines.append("")

        if snapshot.export_history:
            lines.append("## 导出历史")
            for eh in snapshot.export_history:
                lines.append(f"- {eh['timestamp']}: {eh['format']} → {eh['output_path']}")
            lines.append("")

        return "\n".join(lines)

    def export_json(self, name: str, store: Optional[WaiverStore] = None) -> str:
        snapshot = self.load(name)
        if snapshot is None:
            raise ValueError(f"快照 '{name}' 不存在。")

        staleness = self.check_staleness(name, store)
        tx_validations = self.validate_transactions(name, store) if store else []
        fail_validations = self.validate_failed_records(name)

        export_data = snapshot.to_dict()
        export_data["_staleness_warnings"] = staleness
        export_data["_transaction_validations"] = tx_validations
        export_data["_failed_record_validations"] = fail_validations

        return json.dumps(export_data, ensure_ascii=False, indent=2)

    def validate_transactions(self, name: str, store: Optional[WaiverStore] = None) -> List[str]:
        snapshot = self.load(name)
        if snapshot is None:
            return [f"快照 '{name}' 不存在。"]
        if store is None:
            return []

        warnings: List[str] = []
        tx_map = {tx.id: tx for tx in store.transactions}
        linked_ids = list(dict.fromkeys(snapshot.get_linked_transaction_ids()))

        for tx_id in linked_ids:
            if tx_id not in tx_map:
                warnings.append(
                    f"事务 {tx_id} 在当前事务历史中已不存在，"
                    f"可能已被清理或快照来自其他配置目录。"
                )
                continue
            tx = tx_map[tx_id]
            if tx.status.value == "rolled_back":
                warnings.append(
                    f"事务 {tx_id} 已被回滚，"
                    f"快照记录的受影响批次可能已不反映当前状态。"
                )
            for later_tx in store.transactions:
                if later_tx.timestamp > tx.timestamp and later_tx.status.value == "committed":
                    if tx.status.value == "rolled_back":
                        pass
                    break

        return warnings

    def validate_failed_records(self, name: str) -> List[str]:
        snapshot = self.load(name)
        if snapshot is None:
            return [f"快照 '{name}' 不存在。"]

        warnings: List[str] = []
        for rec in snapshot.records:
            if not rec.success:
                has_verifiable = bool(rec.transaction_id) or bool(rec.output_summary.strip())
                if not has_verifiable:
                    warnings.append(
                        f"失败命令 '{rec.command}' (时间: {rec.timestamp}) "
                        f"缺少事务ID和输出摘要，无法核对结果。"
                    )
        return warnings


def build_config_summary(store: WaiverStore) -> Dict[str, Any]:
    active = [r for r in store.rules if r.active]
    expired = [r for r in store.rules if not r.active]
    return {
        "total_rules": len(store.rules),
        "active_rules": len(active),
        "expired_rules": len(expired),
        "manual_rules": len([r for r in store.rules if r.source.value == "manual"]),
        "imported_rules": len([r for r in store.rules if r.source.value == "batch_import"]),
        "transaction_count": len(store.transactions),
        "config_dir_fingerprint": _config_dir_fingerprint(),
    }
