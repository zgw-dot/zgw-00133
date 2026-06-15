from __future__ import annotations

import csv
import json
import os
from typing import Dict, List, Tuple

from .models import AuditBatch, Issue, IssueSeverity, IssueStatus
from .waiver import WaiverStore, WaiverRule


def group_issues_by_severity(batch: AuditBatch) -> Dict[str, List[Issue]]:
    grouped: Dict[str, List[Issue]] = {
        IssueSeverity.BLOCKING.value: [],
        IssueSeverity.CONFIRMABLE.value: [],
    }
    for issue in batch.issues:
        grouped[issue.severity.value].append(issue)
    return grouped


def group_issues_by_status(batch: AuditBatch) -> Dict[str, List[Issue]]:
    grouped: Dict[str, List[Issue]] = {s.value: [] for s in IssueStatus}
    for issue in batch.issues:
        grouped[issue.status.value].append(issue)
    return grouped


def group_issues_by_waiver(
    batch: AuditBatch,
    store: WaiverStore,
) -> Tuple[
    Dict[str, List[Issue]],
    Dict[str, List[Tuple[Issue, Optional[WaiverRule]]]],
]:
    active: Dict[str, List[Issue]] = {
        IssueSeverity.BLOCKING.value: [],
        IssueSeverity.CONFIRMABLE.value: [],
    }
    waived: Dict[str, List[Tuple[Issue, Optional[WaiverRule]]]] = {
        IssueSeverity.BLOCKING.value: [],
        IssueSeverity.CONFIRMABLE.value: [],
    }
    for issue in batch.issues:
        sev = issue.severity.value
        if issue.waived:
            rule = None
            if issue.waived_by_rule_id:
                rule = store.get_rule(issue.waived_by_rule_id)
            waived[sev].append((issue, rule))
        else:
            active[sev].append(issue)
    return active, waived


def export_json_report(batch: AuditBatch, output_path: str) -> str:
    store = WaiverStore()
    grouped_severity = group_issues_by_severity(batch)
    grouped_status = group_issues_by_status(batch)
    active_grouped, waived_grouped = group_issues_by_waiver(batch, store)

    active_blocking = [i.to_dict() for i in active_grouped[IssueSeverity.BLOCKING.value]]
    active_confirmable = [i.to_dict() for i in active_grouped[IssueSeverity.CONFIRMABLE.value]]
    waived_blocking = []
    waived_confirmable = []

    for issue, rule in waived_grouped[IssueSeverity.BLOCKING.value]:
        item = issue.to_dict()
        if rule:
            item["waived_by_rule"] = rule.to_dict()
        waived_blocking.append(item)
    for issue, rule in waived_grouped[IssueSeverity.CONFIRMABLE.value]:
        item = issue.to_dict()
        if rule:
            item["waived_by_rule"] = rule.to_dict()
        waived_confirmable.append(item)

    report = {
        "batch_id": batch.id,
        "manifest_path": batch.manifest_path,
        "backup_dir": batch.backup_dir,
        "created_at": batch.created_at,
        "generated_at": batch.updated_at,
        "status": batch.status.value,
        "summary": {
            "total_issues": len(batch.issues),
            "by_severity": {
                k: len(v) for k, v in grouped_severity.items()
            },
            "by_status": {
                k: len(v) for k, v in grouped_status.items()
            },
            "active_by_severity": {
                k: len(v) for k, v in active_grouped.items()
            },
            "waived_by_severity": {
                k: len(v) for k, v in waived_grouped.items()
            },
            "scanned_files": len(batch.scanned_files),
            "manifest_files": len(batch.manifest.files),
            "unresolved_blocking": batch.count_unresolved_blocking(),
            "unresolved_confirmable": batch.count_unresolved_confirmable(),
            "waived_total": batch.count_waived_issues(),
        },
        "signoff": batch.signoff.to_dict() if batch.signoff else None,
        "reopen_records": [r.to_dict() for r in batch.reopen_records],
        "operation_log": [l.to_dict() for l in batch.operation_log],
        "blocking_issues": active_blocking,
        "confirmable_issues": active_confirmable,
        "waived_blocking_issues": waived_blocking,
        "waived_confirmable_issues": waived_confirmable,
        "all_issues": [i.to_dict() for i in batch.issues],
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return output_path


def export_csv_report(batch: AuditBatch, output_path: str) -> str:
    store = WaiverStore()
    active_grouped, waived_grouped = group_issues_by_waiver(batch, store)
    all_grouped = group_issues_by_severity(batch)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)

        writer.writerow(["=== 离线备份包验收报告 ==="])
        writer.writerow(["批次ID", batch.id])
        writer.writerow(["批次状态", batch.status.value])
        writer.writerow(["Manifest路径", batch.manifest_path])
        writer.writerow(["备份目录", batch.backup_dir])
        writer.writerow(["创建时间", batch.created_at])
        writer.writerow(["报告时间", batch.updated_at])
        writer.writerow([])

        if batch.signoff:
            writer.writerow(["--- 签收摘要 ---"])
            writer.writerow(["签收状态", "强制放行" if batch.signoff.forced else "正常签收"])
            writer.writerow(["签收人", batch.signoff.signer])
            writer.writerow(["签收理由", batch.signoff.reason])
            writer.writerow(["签收时间", batch.signoff.timestamp])
            writer.writerow(["未处理阻断问题数", batch.signoff.unresolved_blocking_count])
            writer.writerow(["未处理可确认问题数", batch.signoff.unresolved_confirmable_count])
            writer.writerow([])

        if batch.reopen_records:
            writer.writerow(["--- 重开记录 ---"])
            writer.writerow(["序号", "重开人", "重开理由", "重开时间", "前次签收人", "前次签收时间"])
            for i, record in enumerate(batch.reopen_records, 1):
                writer.writerow([
                    i,
                    record.reopener,
                    record.reason,
                    record.timestamp,
                    record.previous_signoff.signer,
                    record.previous_signoff.timestamp,
                ])
            writer.writerow([])

        writer.writerow(["--- 概要统计 ---"])
        writer.writerow(["问题总数", len(batch.issues)])
        writer.writerow(["阻断问题 (Blocking)", len(all_grouped[IssueSeverity.BLOCKING.value])])
        writer.writerow(["  - 活跃阻断问题", len(active_grouped[IssueSeverity.BLOCKING.value])])
        writer.writerow(["  - 已豁免阻断问题", len(waived_grouped[IssueSeverity.BLOCKING.value])])
        writer.writerow(["可确认问题 (Confirmable)", len(all_grouped[IssueSeverity.CONFIRMABLE.value])])
        writer.writerow(["  - 活跃可确认问题", len(active_grouped[IssueSeverity.CONFIRMABLE.value])])
        writer.writerow(["  - 已豁免可确认问题", len(waived_grouped[IssueSeverity.CONFIRMABLE.value])])
        writer.writerow(["未处理阻断问题(不含豁免)", batch.count_unresolved_blocking()])
        writer.writerow(["未处理可确认问题(不含豁免)", batch.count_unresolved_confirmable()])
        writer.writerow(["已豁免问题总计", batch.count_waived_issues()])
        writer.writerow(["已扫描文件", len(batch.scanned_files)])
        writer.writerow(["Manifest文件总数", len(batch.manifest.files)])
        writer.writerow([])

        writer.writerow(["--- 阻断问题详情 (活跃, 必须修复) ---"])
        writer.writerow([
            "问题ID", "类型", "文件路径", "严重程度", "状态",
            "处理人", "备注", "消息", "创建时间", "更新时间"
        ])
        for issue in active_grouped[IssueSeverity.BLOCKING.value]:
            writer.writerow([
                issue.id,
                issue.type.value,
                issue.file_path,
                issue.severity.value,
                issue.status.value,
                issue.assignee or "",
                issue.notes or "",
                issue.message,
                issue.created_at,
                issue.updated_at,
            ])
        writer.writerow([])

        writer.writerow(["--- 可人工确认问题详情 (活跃) ---"])
        writer.writerow([
            "问题ID", "类型", "文件路径", "严重程度", "状态",
            "处理人", "备注", "消息", "创建时间", "更新时间"
        ])
        for issue in active_grouped[IssueSeverity.CONFIRMABLE.value]:
            writer.writerow([
                issue.id,
                issue.type.value,
                issue.file_path,
                issue.severity.value,
                issue.status.value,
                issue.assignee or "",
                issue.notes or "",
                issue.message,
                issue.created_at,
                issue.updated_at,
            ])
        writer.writerow([])

        if batch.count_waived_issues() > 0:
            writer.writerow(["--- 已豁免问题详情 (追踪规则) ---"])
            writer.writerow([
                "问题ID", "类型", "文件路径", "严重程度", "原状态",
                "豁免规则ID", "豁免理由", "生效人", "生效时间",
                "规则说明", "原始消息"
            ])
            for sev in [IssueSeverity.BLOCKING.value, IssueSeverity.CONFIRMABLE.value]:
                for issue, rule in waived_grouped[sev]:
                    writer.writerow([
                        issue.id,
                        issue.type.value,
                        issue.file_path,
                        issue.severity.value,
                        issue.status.value,
                        issue.waived_by_rule_id or "",
                        issue.waived_reason or "",
                        rule.actor if rule else "",
                        issue.waived_at or "",
                        rule.description if rule else "",
                        issue.message,
                    ])
            writer.writerow([])

        if batch.operation_log:
            writer.writerow(["--- 操作日志 ---"])
            writer.writerow(["序号", "操作类型", "操作人", "操作理由", "操作时间", "详情"])
            for i, entry in enumerate(batch.operation_log, 1):
                writer.writerow([
                    i,
                    entry.action.value,
                    entry.actor or "",
                    entry.reason or "",
                    entry.timestamp,
                    str(entry.detail),
                ])

    return output_path


def print_summary(batch: AuditBatch) -> None:
    grouped_severity = group_issues_by_severity(batch)
    grouped_status = group_issues_by_status(batch)
    waived_counts = batch.count_waived_by_severity()
    active_counts = batch.count_active_issues_by_severity()

    print(f"\n批次 ID: {batch.id}")
    print(f"批次状态: {batch.status.value}")
    if batch.signoff:
        print(f"签收状态: {'强制放行' if batch.signoff.forced else '正常签收'}")
        print(f"签收人: {batch.signoff.signer}")
        print(f"签收时间: {batch.signoff.timestamp}")
        if batch.signoff.forced:
            print(f"[!] 未处理阻断问题: {batch.signoff.unresolved_blocking_count} 个")
        if batch.signoff.unresolved_confirmable_count > 0:
            print(f"未处理可确认问题: {batch.signoff.unresolved_confirmable_count} 个")
    if batch.reopen_records:
        print(f"重开次数: {len(batch.reopen_records)}")
    print(f"备份目录: {batch.backup_dir}")
    print(f"Manifest: {batch.manifest_path}")
    print(f"\n=== 概要 ===")
    print(f"  问题总数:    {len(batch.issues)}")
    print(f"  阻断问题:    {len(grouped_severity[IssueSeverity.BLOCKING.value])} (活跃={active_counts['blocking']}, 已豁免={waived_counts['blocking']})")
    print(f"  可确认问题:  {len(grouped_severity[IssueSeverity.CONFIRMABLE.value])} (活跃={active_counts['confirmable']}, 已豁免={waived_counts['confirmable']})")
    print(f"  未处理阻断:  {batch.count_unresolved_blocking()} (不含豁免)")
    print(f"  未处理可确认:{batch.count_unresolved_confirmable()} (不含豁免)")
    print(f"  已豁免总计:  {batch.count_waived_issues()}")
    print(f"\n  按状态:")
    for status, issues in grouped_status.items():
        if len(issues) > 0:
            print(f"    {status}: {len(issues)}")
    print(f"  已扫描文件:  {len(batch.scanned_files)}/{len(batch.manifest.files)}")
    print(f"  操作日志:    {len(batch.operation_log)} 条")
