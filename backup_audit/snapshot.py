from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .waiver import WaiverStore, get_global_config_dir

SNAPSHOTS_DIR_NAME = "waiver_snapshots"


def _get_snapshots_dir() -> str:
    return os.path.join(get_global_config_dir(), SNAPSHOTS_DIR_NAME)


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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "records": [r.to_dict() for r in self.records],
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OperationSnapshot":
        return cls(
            name=data["name"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            records=[SnapshotRecord.from_dict(r) for r in data.get("records", [])],
            meta=data.get("meta", {}),
        )

    def add_record(self, record: SnapshotRecord) -> None:
        self.records.append(record)
        self.updated_at = datetime.now().isoformat()

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
            raise ValueError(f"快照 '{name}' 已存在，请使用其他名称或用 append 追加记录。")
        now = datetime.now().isoformat()
        snapshot = OperationSnapshot(
            name=name,
            created_at=now,
            updated_at=now,
            records=[record] if record else [],
        )
        self._save(snapshot)
        return snapshot

    def append(self, name: str, record: SnapshotRecord) -> OperationSnapshot:
        snapshot = self.load(name)
        if snapshot is None:
            raise ValueError(f"快照 '{name}' 不存在，请先创建。")
        snapshot.add_record(record)
        self._save(snapshot)
        return snapshot

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
                })
            except Exception:
                continue
        return results

    def _save(self, snapshot: OperationSnapshot) -> None:
        path = self._snapshot_path(snapshot.name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snapshot.to_dict(), f, ensure_ascii=False, indent=2)

    def export_markdown(self, name: str) -> str:
        snapshot = self.load(name)
        if snapshot is None:
            raise ValueError(f"快照 '{name}' 不存在。")
        lines = [
            f"# 操作快照: {snapshot.name}",
            "",
            f"- 创建时间: {snapshot.created_at}",
            f"- 最后更新: {snapshot.updated_at}",
            f"- 记录条数: {len(snapshot.records)}",
            "",
        ]
        for i, rec in enumerate(snapshot.records, 1):
            status = "[OK]" if rec.success else "[FAIL]"
            lines.append(f"## {i}. {status} {rec.command}")
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

        return "\n".join(lines)

    def validate_transactions(self, name: str, store: WaiverStore) -> List[str]:
        snapshot = self.load(name)
        if snapshot is None:
            return [f"快照 '{name}' 不存在。"]

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
            for later_tx in store.transactions:
                if later_tx.timestamp > tx.timestamp and later_tx.status.value == "committed":
                    if tx.status.value == "rolled_back":
                        warnings.append(
                            f"事务 {tx_id} 已被回滚，之后有新事务 {later_tx.id} 提交，"
                            f"快照记录的受影响批次可能已不反映当前状态。"
                        )
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
    }
