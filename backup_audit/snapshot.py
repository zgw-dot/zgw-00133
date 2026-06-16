from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .waiver import WaiverStore, get_global_config_dir

SNAPSHOTS_DIR_NAME = "waiver_snapshots"


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

    def _snapshot_path(self, name: str) -> str:
        safe_name = name.replace("/", "_").replace("\\", "_").replace("..", "_")
        return os.path.join(self.snapshots_dir, f"{safe_name}.json")

    def create(self, name: str, record: Optional[SnapshotRecord] = None) -> OperationSnapshot:
        path = self._snapshot_path(name)
        if os.path.exists(path):
            existing = self.load(name)
            if existing is not None:
                status_parts = []
                if existing.sealed:
                    status_parts.append(f"已封版 (封版时间: {existing.sealed_at})")
                else:
                    status_parts.append("未封版 (仍可追加)")
                status_parts.append(f"记录条数: {len(existing.records)}")
                status_parts.append(f"创建时间: {existing.created_at}")
                status_parts.append(f"最后更新: {existing.updated_at}")
                if existing.forked_from:
                    status_parts.append(f"分叉自: {existing.forked_from}")
                status_str = "；".join(status_parts)
                raise SnapshotNameConflictError(
                    f"快照名称 '{name}' 已存在，当前状态: {status_str}。\n"
                    f"可选操作:\n"
                    f"  1. 使用 --append 向已有快照追加记录\n"
                    f"  2. 使用 --fork-from {name} 从该快照分叉出新快照\n"
                    f"  3. 使用不同的名称创建新快照"
                )
        now = datetime.now().isoformat()
        snapshot = OperationSnapshot(
            name=name,
            created_at=now,
            updated_at=now,
            records=[record] if record else [],
            config_dir_fingerprint=_config_dir_fingerprint(),
        )
        self._save(snapshot)
        return snapshot

    def append(self, name: str, record: SnapshotRecord, allow_sealed: bool = False) -> OperationSnapshot:
        snapshot = self.load(name)
        if snapshot is None:
            raise ValueError(f"快照 '{name}' 不存在，请先创建。")
        if snapshot.sealed and not allow_sealed:
            raise SnapshotSealedError(
                f"快照 '{name}' 已于 {snapshot.sealed_at} 封版，不能追加记录。"
                f"如需续写封版快照，必须使用 --append 参数。"
            )
        snapshot.add_record_forced(record)
        self._save(snapshot)
        return snapshot

    def seal(self, name: str, actor: str = "") -> OperationSnapshot:
        snapshot = self.load(name)
        if snapshot is None:
            raise ValueError(f"快照 '{name}' 不存在。")
        if snapshot.sealed:
            raise ValueError(
                f"快照 '{name}' 已于 {snapshot.sealed_at} 封版，不能重复封版。"
            )
        snapshot.seal(actor)
        self._save(snapshot)
        return snapshot

    def fork_from(self, source_name: str, new_name: str, record: Optional[SnapshotRecord] = None) -> OperationSnapshot:
        source = self.load(source_name)
        if source is None:
            raise ValueError(f"源快照 '{source_name}' 不存在，无法分叉。")
        new_path = self._snapshot_path(new_name)
        if os.path.exists(new_path):
            existing = self.load(new_name)
            if existing is not None:
                raise SnapshotNameConflictError(
                    f"目标快照名称 '{new_name}' 已存在，请使用其他名称。"
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

    def record_export(self, name: str, export_format: str, output_path: str) -> None:
        snapshot = self.load(name)
        if snapshot is None:
            return
        snapshot.export_history.append({
            "format": export_format,
            "output_path": output_path,
            "timestamp": datetime.now().isoformat(),
        })
        self._save(snapshot)

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
