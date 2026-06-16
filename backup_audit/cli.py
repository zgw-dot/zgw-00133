from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .models import (
    AuditBatch,
    Issue,
    IssueSeverity,
    IssueStatus,
    IssueType,
    ManifestFile,
    OperationType,
)
from .reporter import (
    export_csv_report,
    export_json_report,
    group_issues_by_severity,
    print_summary,
)
from .validator import load_manifest, run_precheck, ManifestValidationError
from .waiver import (
    WaiverConflictError,
    WaiverRule,
    WaiverStore,
    WaiverTransactionError,
    WaiverValidationError,
    get_global_config_dir,
)
from .snapshot import (
    SnapshotStore,
    SnapshotRecord,
    OperationSnapshot,
    SnapshotSealedError,
    SnapshotNameConflictError,
    build_config_summary,
)


STORAGE_DIR_NAME = ".audit_state"


def safe_print(*args, **kwargs) -> None:
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        sep = kwargs.get("sep", " ")
        end = kwargs.get("end", "\n")
        file = kwargs.get("file", sys.stdout)
        text = sep.join(str(a) for a in args) + end
        file.buffer.write(text.encode(sys.stdout.encoding, errors="replace"))
        file.flush()


def analyze_affected_batches(
    backup_dir: str,
    store: WaiverStore,
    rules_to_analyze: Optional[List[WaiverRule]] = None,
) -> List[Dict[str, object]]:
    storage_dir = get_storage_dir(backup_dir)
    if not os.path.isdir(storage_dir):
        return []

    pattern = os.path.join(storage_dir, "batch_*.json")
    batch_files = sorted(glob.glob(pattern))
    if not batch_files:
        return []

    results: List[Dict[str, object]] = []
    effective_rules = rules_to_analyze or store.list_rules()

    for bf in batch_files:
        try:
            batch = AuditBatch.load(bf)
        except Exception:
            continue

        affected = 0
        affected_issue_ids: List[str] = []
        for issue in batch.issues:
            mf = get_manifest_file_for_issue(batch, issue)
            for rule in effective_rules:
                if rule.matches(issue, mf):
                    affected += 1
                    affected_issue_ids.append(issue.id)
                    break

        if affected > 0:
            results.append({
                "batch_id": batch.id,
                "affected_count": affected,
                "sample_issue_ids": affected_issue_ids[:5],
            })

    return results


def get_storage_dir(backup_dir: str) -> str:
    return os.path.join(backup_dir, STORAGE_DIR_NAME)


def _record_to_snapshot(
    snapshot_name: Optional[str],
    command: str,
    success: bool,
    output_summary: str,
    transaction_id: Optional[str] = None,
    affected_batches: Optional[List[Dict[str, object]]] = None,
    store: Optional[WaiverStore] = None,
    allow_sealed_append: bool = False,
    fork_from: Optional[str] = None,
    actor: str = "",
) -> None:
    if not snapshot_name:
        return
    try:
        snap_store = SnapshotStore()
        config_summary = build_config_summary(store) if store else None
        record = SnapshotRecord(
            command=command,
            timestamp=datetime.now().isoformat(),
            success=success,
            output_summary=output_summary,
            transaction_id=transaction_id,
            affected_batches=affected_batches or [],
            config_summary=config_summary,
        )

        if fork_from:
            existing_target = snap_store.load(snapshot_name)
            if existing_target is not None:
                detail = snap_store.get_snapshot_status_detail(snapshot_name)
                safe_print(
                    f"  [WARN] 快照 '{snapshot_name}' 已存在，无法从 '{fork_from}' 分叉到该名称。\n"
                    f"  当前状态: {detail['status_label'] if detail else '未知'}\n"
                    f"  建议: 使用其他名称作为分叉目标，或直接向已有快照追加记录。",
                    file=sys.stderr,
                )
                return
            snap_store.fork_from(fork_from, snapshot_name, record, actor=actor)
            safe_print(
                f"  [INFO] 已从 '{fork_from}' 分叉到快照 '{snapshot_name}'，并追加本次操作记录。",
                file=sys.stderr,
            )
            return

        existing = snap_store.load(snapshot_name)
        if existing is None:
            safe_print(
                f"  [WARN] 快照 '{snapshot_name}' 不存在，已跳过记录。\n"
                f"  快照必须显式创建后才能写入。\n"
                f"  请先执行: waiver snapshot create {snapshot_name}\n"
                f"  或使用 --snapshot-fork-from <源快照> 从现有快照分叉。",
                file=sys.stderr,
            )
            return

        if existing.sealed and not allow_sealed_append:
            detail = snap_store.get_snapshot_status_detail(snapshot_name)
            safe_print(
                f"  [WARN] 快照 '{snapshot_name}' 已封版 ({existing.sealed_at})，"
                f"未使用 --snapshot-append，跳过记录。\n"
                f"  当前阶段: {detail['stuck_at'] if detail else '未知'}\n"
                f"  如需续写封版快照，请在命令中添加 --snapshot-append。\n"
                f"  如需分叉出新快照，请使用 --snapshot-fork-from。",
                file=sys.stderr,
            )
            return

        if not success:
            if not transaction_id and not output_summary.strip():
                record.gap_warning = "失败命令缺少事务ID和输出摘要，无法核对结果。"

        snap_store.append(snapshot_name, record, allow_sealed=existing.sealed, actor=actor)
    except SnapshotSealedError as e:
        safe_print(f"  [WARN] 封版快照写入被拒: {e}", file=sys.stderr)
    except SnapshotNameConflictError as e:
        safe_print(f"  [WARN] 快照名称冲突: {e}", file=sys.stderr)
    except Exception as e:
        safe_print(f"  [WARN] 快照记录失败: {e}", file=sys.stderr)


def find_batch_file(storage_dir: str, batch_id: Optional[str] = None) -> Optional[str]:
    pattern = os.path.join(storage_dir, "batch_*.json")
    files = sorted(glob.glob(pattern))
    if not files:
        return None
    if batch_id:
        for f in files:
            if batch_id in f:
                return f
        return None
    return files[-1]


def load_batch(backup_dir: str, batch_id: Optional[str] = None) -> Optional[AuditBatch]:
    storage_dir = get_storage_dir(backup_dir)
    batch_file = find_batch_file(storage_dir, batch_id)
    if not batch_file:
        return None
    return AuditBatch.load(batch_file)


def save_batch(batch: AuditBatch, backup_dir: str) -> str:
    storage_dir = get_storage_dir(backup_dir)
    return batch.save(storage_dir)


def get_manifest_file_for_issue(batch: AuditBatch, issue: Issue) -> Optional[ManifestFile]:
    for mf in batch.manifest.files:
        if mf.path == issue.file_path:
            return mf
    return None


def apply_waivers_to_batch(
    batch: AuditBatch,
    store: WaiverStore,
    actor: str,
    always_log: bool = False,
) -> Tuple[int, int]:
    if batch.is_readonly():
        return 0, 0
    newly_waived = 0
    newly_unwaived = 0
    for issue in batch.issues:
        mf = get_manifest_file_for_issue(batch, issue)
        matching_rule = store.match_issue(issue, mf)
        if matching_rule and not issue.waived:
            issue.apply_waiver(matching_rule.id, matching_rule.reason)
            newly_waived += 1
        elif not matching_rule and issue.waived:
            issue.clear_waiver()
            newly_unwaived += 1
    if newly_waived > 0 or newly_unwaived > 0 or always_log:
        batch.log_operation(
            action=OperationType.WAIVER_RESCAN,
            actor=actor,
            detail={
                "newly_waived": newly_waived,
                "newly_unwaived": newly_unwaived,
            },
        )
    return newly_waived, newly_unwaived


def check_readonly(batch: AuditBatch, operation: str) -> Optional[int]:
    if batch.is_readonly():
        signer = batch.signoff.signer if batch.signoff else "未知"
        sign_time = batch.signoff.timestamp if batch.signoff else "未知"
        print(
            f"错误: 批次已签收，禁止执行 {operation} 操作。\n"
            f"  签收人: {signer}\n"
            f"  签收时间: {sign_time}\n"
            f"如需继续编辑，请使用 reopen 命令。",
            file=sys.stderr,
        )
        return 3
    return None


def cmd_import(args: argparse.Namespace) -> int:
    manifest_path = os.path.abspath(args.manifest)
    backup_dir = os.path.abspath(args.backup_dir)

    if not os.path.exists(manifest_path):
        print(f"错误: Manifest 文件不存在: {manifest_path}", file=sys.stderr)
        return 1

    if not os.path.isdir(backup_dir):
        print(f"错误: 备份目录不存在: {backup_dir}", file=sys.stderr)
        return 1

    existing = load_batch(backup_dir)
    if existing:
        if existing.is_readonly():
            rc = check_readonly(existing, "import --force")
            if rc is not None:
                return rc
        if not args.force:
            print(f"警告: 备份目录已有批次 {existing.id}，使用 --force 重新导入，或使用 resume 继续")
            return 2

    try:
        manifest = load_manifest(manifest_path)
    except ManifestValidationError as e:
        print(f"错误: {e}", file=sys.stderr)
        print(f"\n发现 {len(e.errors)} 个格式错误，批次未创建。请修正 manifest 后重新导入。", file=sys.stderr)
        return 1
    batch = AuditBatch(
        id=manifest.batch_id,
        manifest_path=manifest_path,
        backup_dir=backup_dir,
        manifest=manifest,
    )
    save_batch(batch, backup_dir)
    print(f"批次已导入: {batch.id}")
    print(f"  Manifest: {manifest_path}")
    print(f"  备份目录: {backup_dir}")
    print(f"  Manifest 中的文件数: {len(manifest.files)}")
    return 0


def cmd_precheck(args: argparse.Namespace) -> int:
    backup_dir = os.path.abspath(args.backup_dir)
    batch = load_batch(backup_dir, args.batch_id)

    if not batch:
        print("错误: 未找到批次，请先运行 import", file=sys.stderr)
        return 1

    rc = check_readonly(batch, "precheck")
    if rc is not None:
        return rc

    print(f"运行预检: 批次 {batch.id}")
    print(f"  (预检不会修改源备份文件)")

    new_issues = run_precheck(batch)
    batch.log_operation(
        action=OperationType.PRECHECK,
        detail={"new_issues": len(new_issues)},
    )

    store = WaiverStore()
    actor = getattr(args, "actor", "system")
    newly_waived, newly_unwaived = apply_waivers_to_batch(batch, store, actor)

    save_batch(batch, backup_dir)

    print(f"\n预检完成:")
    print(f"  新增问题: {len(new_issues)}")
    active_counts = batch.count_active_issues_by_severity()
    waived_counts = batch.count_waived_by_severity()
    print(f"  累计问题: {len(batch.issues)}")
    print(f"    活跃 (阻断): {active_counts['blocking']}")
    print(f"    活跃 (可确认): {active_counts['confirmable']}")
    print(f"    已豁免 (阻断): {waived_counts['blocking']}")
    print(f"    已豁免 (可确认): {waived_counts['confirmable']}")
    if newly_waived > 0:
        print(f"  本次豁免命中: {newly_waived} 个问题")
    if newly_unwaived > 0:
        print(f"  本次豁免过期/移除后重新暴露: {newly_unwaived} 个问题")
    print_summary(batch)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    backup_dir = os.path.abspath(args.backup_dir)
    batch = load_batch(backup_dir, args.batch_id)

    if not batch:
        print("错误: 未找到批次", file=sys.stderr)
        return 1

    print_summary(batch)

    if not batch.issues:
        print("\n暂无问题记录。")
        return 0

    filter_status = getattr(args, "status", None)
    filter_severity = getattr(args, "severity", None)
    filter_waived = getattr(args, "waived", None)

    store = WaiverStore()
    active_issues: Dict[str, List[Issue]] = {"blocking": [], "confirmable": []}
    waived_issues: Dict[str, List[Tuple[Issue, Optional[WaiverRule]]]] = {
        "blocking": [], "confirmable": []
    }

    for issue in batch.issues:
        sev = issue.severity.value
        if issue.waived:
            rule = store.get_rule(issue.waived_by_rule_id) if issue.waived_by_rule_id else None
            waived_issues[sev].append((issue, rule))
        else:
            active_issues[sev].append(issue)

    for sev_key, sev_label, issues in [
        ("blocking", "阻断问题 (BLOCKING)", active_issues["blocking"]),
        ("confirmable", "可确认问题 (CONFIRMABLE)", active_issues["confirmable"]),
    ]:
        if filter_severity and filter_severity != sev_key:
            continue
        if filter_waived == "only":
            continue
        if not issues and filter_waived != "include":
            pass
        if issues:
            print(f"\n--- {sev_label} [活跃] ---")
            for issue in issues:
                if filter_status and issue.status.value != filter_status:
                    continue
                print(f"  [{issue.id}] {issue.type.value:20s} {issue.status.value:15s} {issue.file_path}")
                if issue.assignee:
                    print(f"      处理人: {issue.assignee}")
                if issue.notes:
                    print(f"      备注: {issue.notes}")
                print(f"      {issue.message}")

    has_waived = any(v for v in waived_issues.values())
    if has_waived and filter_waived != "exclude":
        for sev_key, sev_label, pairs in [
            ("blocking", "阻断问题 (BLOCKING)", waived_issues["blocking"]),
            ("confirmable", "可确认问题 (CONFIRMABLE)", waived_issues["confirmable"]),
        ]:
            if filter_severity and filter_severity != sev_key:
                continue
            if not pairs:
                continue
            print(f"\n--- {sev_label} [已豁免] ---")
            for issue, rule in pairs:
                if filter_status and issue.status.value != filter_status:
                    continue
                rule_info = f"规则ID={issue.waived_by_rule_id}" if issue.waived_by_rule_id else "规则未知"
                print(f"  [{issue.id}] {issue.type.value:20s} WAIVED          {issue.file_path}")
                print(f"      [豁免] {rule_info}")
                if issue.waived_reason:
                    print(f"      豁免理由: {issue.waived_reason}")
                if rule and rule.actor:
                    print(f"      生效人: {rule.actor}")
                if issue.waived_at:
                    print(f"      生效时间: {issue.waived_at}")
                print(f"      {issue.message}")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    backup_dir = os.path.abspath(args.backup_dir)
    batch = load_batch(backup_dir, args.batch_id)

    if not batch:
        print("错误: 未找到批次", file=sys.stderr)
        return 1

    rc = check_readonly(batch, "review")
    if rc is not None:
        return rc

    issue = batch.get_issue(args.issue_id)
    if not issue:
        print(f"错误: 未找到问题 ID: {args.issue_id}", file=sys.stderr)
        return 1

    status_map = {
        "pending_fix": IssueStatus.PENDING_FIX,
        "confirmed": IssueStatus.CONFIRMED,
        "ignored": IssueStatus.IGNORED,
        "open": IssueStatus.OPEN,
    }
    status = status_map.get(args.status)

    batch.push_review_snapshot(args.issue_id)
    issue.update(
        status=status,
        assignee=args.assignee,
        notes=args.notes,
    )
    batch.log_operation(
        action=OperationType.REVIEW,
        actor=args.assignee,
        reason=args.notes,
        detail={
            "issue_id": issue.id,
            "old_status": batch.review_history[-1]["status"],
            "new_status": status.value if status else issue.status.value,
        },
    )
    save_batch(batch, backup_dir)

    print(f"问题已更新: {issue.id}")
    print(f"  状态: {issue.status.value}")
    if issue.assignee:
        print(f"  处理人: {issue.assignee}")
    if issue.notes:
        print(f"  备注: {issue.notes}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    backup_dir = os.path.abspath(args.backup_dir)
    batch = load_batch(backup_dir, args.batch_id)

    if not batch:
        print("错误: 未找到批次", file=sys.stderr)
        return 1

    output_dir = os.path.abspath(args.output) if args.output else backup_dir
    os.makedirs(output_dir, exist_ok=True)

    fmt = args.format
    batch.log_operation(
        action=OperationType.EXPORT,
        detail={"format": fmt, "output_dir": output_dir},
    )

    if fmt == "json" or fmt == "all":
        json_path = os.path.join(output_dir, f"audit_report_{batch.id}.json")
        export_json_report(batch, json_path)
        print(f"JSON 报告: {json_path}")

    if fmt == "csv" or fmt == "all":
        csv_path = os.path.join(output_dir, f"audit_report_{batch.id}.csv")
        export_csv_report(batch, csv_path)
        print(f"CSV 报告: {csv_path}")

    save_batch(batch, backup_dir)

    print_summary(batch)
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    backup_dir = os.path.abspath(args.backup_dir)
    batch = load_batch(backup_dir, args.batch_id)

    if not batch:
        print("错误: 未找到批次", file=sys.stderr)
        return 1

    store = WaiverStore()
    actor = getattr(args, "actor", "system")
    newly_waived, newly_unwaived = apply_waivers_to_batch(batch, store, actor)
    if newly_waived > 0 or newly_unwaived > 0:
        save_batch(batch, backup_dir)

    print(f"已恢复批次: {batch.id}")
    print(f"  存储文件: {batch.storage_path}")
    if batch.is_readonly():
        print(f"  状态: 已签收（豁免规则已锁定在签收时刻，不受当前规则影响）")
    if newly_waived > 0:
        print(f"  本次豁免命中: {newly_waived} 个问题")
    if newly_unwaived > 0:
        print(f"  本次豁免过期/移除后重新暴露: {newly_unwaived} 个问题")
    print_summary(batch)
    return 0


def cmd_undo(args: argparse.Namespace) -> int:
    backup_dir = os.path.abspath(args.backup_dir)
    batch = load_batch(backup_dir, args.batch_id)

    if not batch:
        print("错误: 未找到批次", file=sys.stderr)
        return 1

    rc = check_readonly(batch, "undo")
    if rc is not None:
        return rc

    snapshot = batch.pop_review_snapshot()
    if snapshot is None:
        print("没有可撤销的复核操作（撤销历史为空）。", file=sys.stderr)
        return 1

    issue_id = snapshot["issue_id"]
    issue = batch.get_issue(issue_id)
    if issue is None:
        print(f"错误: 撤销快照对应的问题 {issue_id} 不存在", file=sys.stderr)
        batch.review_history.append(snapshot)
        return 1

    prev_status = IssueStatus(snapshot["status"])
    prev_assignee = snapshot.get("assignee")
    prev_notes = snapshot.get("notes")
    prev_updated_at = snapshot.get("updated_at")

    issue.status = prev_status
    issue.assignee = prev_assignee
    issue.notes = prev_notes
    issue.updated_at = prev_updated_at or issue.updated_at

    batch.log_operation(
        action=OperationType.UNDO,
        detail={
            "issue_id": issue_id,
            "restored_status": prev_status.value,
        },
    )
    save_batch(batch, backup_dir)

    print(f"已撤销上一条复核: 问题 {issue_id}")
    print(f"  状态: {prev_status.value}")
    if prev_assignee:
        print(f"  处理人: {prev_assignee}")
    else:
        print(f"  处理人: (无)")
    if prev_notes:
        print(f"  备注: {prev_notes}")
    else:
        print(f"  备注: (无)")
    print(f"  剩余可撤销次数: {len(batch.review_history)}")
    return 0


def cmd_finalize(args: argparse.Namespace) -> int:
    backup_dir = os.path.abspath(args.backup_dir)
    batch = load_batch(backup_dir, args.batch_id)

    if not batch:
        print("错误: 未找到批次", file=sys.stderr)
        return 1

    if batch.is_readonly():
        signer = batch.signoff.signer if batch.signoff else "未知"
        sign_time = batch.signoff.timestamp if batch.signoff else "未知"
        print(
            f"错误: 批次已签收，不能重复签收。\n"
            f"  签收人: {signer}\n"
            f"  签收时间: {sign_time}\n"
            f"如需重新签收，请先使用 reopen 命令。",
            file=sys.stderr,
        )
        return 4

    unresolved_blocking = batch.count_unresolved_blocking()
    unresolved_confirmable = batch.count_unresolved_confirmable()

    if unresolved_blocking > 0:
        if not args.force:
            print(
                f"错误: 存在 {unresolved_blocking} 个未处理的阻断问题，不能签收。\n"
                f"请先处理所有阻断问题，或使用 --force-with-reason 强制放行（需同时提供 --reason）。",
                file=sys.stderr,
            )
            return 5
        if not args.reason or not args.reason.strip():
            print(
                "错误: 强制放行必须提供 --reason 参数说明签收理由。",
                file=sys.stderr,
            )
            return 6

    if not args.reason or not args.reason.strip():
        print(
            "错误: 签收必须提供 --reason 参数说明签收理由。",
            file=sys.stderr,
        )
        return 7

    success = batch.finalize(
        signer=args.signer,
        reason=args.reason,
        force=args.force,
    )

    if not success:
        print(
            f"错误: 签收失败，存在 {unresolved_blocking} 个未处理的阻断问题。",
            file=sys.stderr,
        )
        return 5

    save_batch(batch, backup_dir)

    signoff = batch.signoff
    print(f"批次已签收: {batch.id}")
    print(f"  状态: {'强制放行' if signoff.forced else '正常签收'}")
    print(f"  签收人: {signoff.signer}")
    print(f"  签收理由: {signoff.reason}")
    print(f"  签收时间: {signoff.timestamp}")
    if signoff.forced:
        print(f"  [!] 未处理阻断问题: {signoff.unresolved_blocking_count} 个")
    if signoff.unresolved_confirmable_count > 0:
        print(f"  未处理可确认问题: {signoff.unresolved_confirmable_count} 个")
    print_summary(batch)
    return 0


def cmd_reopen(args: argparse.Namespace) -> int:
    backup_dir = os.path.abspath(args.backup_dir)
    batch = load_batch(backup_dir, args.batch_id)

    if not batch:
        print("错误: 未找到批次", file=sys.stderr)
        return 1

    if not batch.is_readonly():
        print("错误: 批次未签收，无需重开。", file=sys.stderr)
        return 8

    if not args.reason or not args.reason.strip():
        print(
            "错误: 重开必须提供 --reason 参数说明重开理由。",
            file=sys.stderr,
        )
        return 9

    if not args.reopener or not args.reopener.strip():
        print(
            "错误: 重开必须提供 --reopener 参数说明重开人。",
            file=sys.stderr,
        )
        return 10

    batch.reopen(
        reopener=args.reopener,
        reason=args.reason,
    )
    save_batch(batch, backup_dir)

    print(f"批次已重开，恢复编辑: {batch.id}")
    print(f"  重开人: {args.reopener}")
    print(f"  重开理由: {args.reason}")
    print(f"  累计重开次数: {len(batch.reopen_records)}")
    print_summary(batch)
    return 0


def cmd_waiver_add(args: argparse.Namespace) -> int:
    store = WaiverStore()
    issue_type = IssueType(args.issue_type) if args.issue_type else None
    severity = IssueSeverity(args.severity) if args.severity else None
    rule = WaiverRule.create(
        path_prefix=args.path_prefix,
        business_line=args.business_line,
        issue_type=issue_type,
        severity=severity,
        reason=args.reason,
        description=args.description or "",
        actor=args.actor,
        expires_at=args.expires_at,
    )
    try:
        rule = store.add_rule(rule, args.actor, allow_conflict=args.force)
    except WaiverConflictError as e:
        print(f"错误: {e}", file=sys.stderr)
        return 11
    except WaiverValidationError as e:
        print(f"错误: {e}", file=sys.stderr)
        return 12

    print(f"豁免规则已添加: {rule.id}")
    print(f"  操作人: {rule.actor}")
    print(f"  创建时间: {rule.created_at}")
    if rule.path_prefix:
        print(f"  路径前缀: {rule.path_prefix}")
    if rule.business_line:
        print(f"  业务线: {rule.business_line}")
    if rule.issue_type:
        print(f"  问题类型: {rule.issue_type.value}")
    if rule.severity:
        print(f"  严重程度: {rule.severity.value}")
    if rule.expires_at:
        print(f"  过期时间: {rule.expires_at}")
    print(f"  豁免理由: {rule.reason}")
    if rule.description:
        print(f"  说明: {rule.description}")
    return 0


def cmd_waiver_list(args: argparse.Namespace) -> int:
    store = WaiverStore()
    rules = store.list_rules(include_expired=args.include_expired)

    print(f"豁免规则总数 (含过期): {len(store.rules)}")
    print(f"当前生效规则: {len(rules)}")
    print(f"全局配置目录: {get_global_config_dir()}")

    if not rules:
        print("\n暂无生效的豁免规则。")
    else:
        for rule in rules:
            expired_tag = ""
            if rule.expires_at:
                try:
                    if datetime.fromisoformat(rule.expires_at) < datetime.now():
                        expired_tag = " [已过期]"
                except ValueError:
                    pass
            source_tag = " [手工]" if rule.source.value == "manual" else " [批量导入]"
            print(f"\n  [{rule.id}]{expired_tag}{source_tag}")
            print(f"    操作人: {rule.actor}")
            print(f"    创建时间: {rule.created_at}")
            print(f"    来源: {rule.source.value}")
            if rule.transaction_id:
                print(f"    事务ID: {rule.transaction_id}")
            conditions = []
            if rule.path_prefix:
                conditions.append(f"路径前缀={rule.path_prefix}")
            if rule.business_line:
                conditions.append(f"业务线={rule.business_line}")
            if rule.issue_type:
                conditions.append(f"类型={rule.issue_type.value}")
            if rule.severity:
                conditions.append(f"级别={rule.severity.value}")
            print(f"    匹配条件: {', '.join(conditions) if conditions else '(全部匹配)'}")
            if rule.expires_at:
                print(f"    过期时间: {rule.expires_at}")
            print(f"    理由: {rule.reason}")
            if rule.description:
                print(f"    说明: {rule.description}")

    if args.show_log:
        print(f"\n=== 规则变更操作日志 ===")
        log_entries = store.get_audit_log()
        if not log_entries:
            print("  暂无日志")
        else:
            for entry in log_entries:
                action_desc = {
                    "waiver_add": "新增规则",
                    "waiver_delete": "删除规则",
                    "waiver_import": "导入规则",
                    "waiver_export": "导出规则",
                    "waiver_rollback": "回滚导入",
                    "waiver_precheck": "预演导入",
                }.get(entry.action.value, entry.action.value)
                print(f"  [{entry.timestamp}] {action_desc} ({entry.action.value}) by {entry.actor}")
                if entry.rule_id:
                    print(f"    规则ID: {entry.rule_id}")
                if entry.detail:
                    if entry.action.value == "waiver_import":
                        tx_id = entry.detail.get("transaction_id", "N/A")
                        mode = entry.detail.get("mode", "N/A")
                        added = len(entry.detail.get("added", []))
                        print(f"    事务ID: {tx_id}")
                        print(f"    模式: {mode}")
                        print(f"    新增: {added} 条")
                    elif entry.action.value == "waiver_rollback":
                        tx_id = entry.detail.get("transaction_id", "N/A")
                        restored = entry.detail.get("restored_count", 0)
                        removed = entry.detail.get("removed_count", 0)
                        manual_preserved = entry.detail.get("manual_rules_preserved", 0)
                        print(f"    事务ID: {tx_id}")
                        print(f"    恢复: {restored} 条")
                        print(f"    移除: {removed} 条")
                        print(f"    保留手工规则: {manual_preserved} 条")
                    else:
                        print(f"    详情: {json.dumps(entry.detail, ensure_ascii=False)}")
    return 0


def cmd_waiver_delete(args: argparse.Namespace) -> int:
    store = WaiverStore()
    rule = store.get_rule(args.rule_id)
    if not rule:
        print(f"错误: 未找到规则 ID: {args.rule_id}", file=sys.stderr)
        return 13

    if args.force:
        ok = store.delete_rule(args.rule_id, args.actor)
    else:
        print(f"即将删除规则 {args.rule_id}:")
        print(f"  操作人: {rule.actor}")
        print(f"  创建时间: {rule.created_at}")
        print(f"  理由: {rule.reason}")
        print(f"\n删除后，之前被此规则豁免的问题将重新暴露。")
        print("使用 --force 确认删除，或使用 --yes 静默确认。")
        if not args.yes:
            print("错误: 请使用 --force 或 --yes 确认删除。", file=sys.stderr)
            return 14
        ok = store.delete_rule(args.rule_id, args.actor)

    if ok:
        print(f"规则已删除: {args.rule_id}")
        print(f"  操作人: {args.actor}")
    return 0 if ok else 13


def cmd_waiver_export(args: argparse.Namespace) -> int:
    store = WaiverStore()
    output_path = os.path.abspath(args.output)
    try:
        store.export_rules(output_path, args.actor)
    except OSError as e:
        print(f"错误: 导出失败 - {e}", file=sys.stderr)
        return 15
    print(f"豁免规则已导出: {output_path}")
    print(f"  操作人: {args.actor}")
    print(f"  规则数量: {len(store.rules)}")
    return 0


def _print_precheck_result(precheck, affected_batches: Optional[List[Dict[str, object]]] = None) -> None:
    safe_print(f"=== 导入预演结果 ===")
    safe_print(f"  源文件: {precheck.source_file}")
    safe_print(f"  导入模式: {precheck.mode}")
    safe_print(f"  文件中规则总数: {precheck.total_rules}")
    safe_print()
    safe_print(f"  新增规则: {len(precheck.new_rules)}")
    for r in precheck.new_rules:
        desc = []
        if r.path_prefix:
            desc.append(f"路径={r.path_prefix}")
        if r.business_line:
            desc.append(f"业务线={r.business_line}")
        if r.issue_type:
            desc.append(f"类型={r.issue_type.value}")
        if r.severity:
            desc.append(f"严重度={r.severity.value}")
        safe_print(f"    + {r.id}: {r.reason} ({', '.join(desc)})")
    safe_print()
    safe_print(f"  已存在 (跳过): {len(precheck.existing_rules)}")
    for r in precheck.existing_rules:
        safe_print(f"    = {r.id}: {r.reason}")
    safe_print()
    safe_print(f"  冲突/风险 (跳过): {len(precheck.conflicting_rules)}")
    for c in precheck.conflicting_rules:
        rule = c["rule"]
        reasons = "; ".join(c["conflict_reasons"])
        safe_print(f"    ! {rule['id']}: {reasons}")
    safe_print()
    safe_print(f"  已过期 (跳过): {len(precheck.expired_rules)}")
    for r in precheck.expired_rules:
        safe_print(f"    e {r.id}: 过期于 {r.expires_at}")
    safe_print()
    safe_print(f"  无效规则: {len(precheck.invalid_rules)}")
    for inv in precheck.invalid_rules:
        safe_print(f"    x 索引 {inv['index']}: {inv['error']}")
    safe_print()
    if precheck.file_errors:
        safe_print(f"  文件错误: {len(precheck.file_errors)}")
        for err in precheck.file_errors:
            safe_print(f"    X {err}")
        safe_print()
    if affected_batches:
        safe_print(f"  下次 precheck/rescan 受影响批次: {len(affected_batches)}")
        for ab in affected_batches:
            safe_print(f"    * 批次 {ab['batch_id']}: 影响 {ab['affected_count']} 个问题")
        safe_print()
    elif hasattr(precheck, "affected_batches") and precheck.affected_batches:
        safe_print(f"  下次 precheck/rescan 受影响批次: {len(precheck.affected_batches)}")
        for bid in precheck.affected_batches:
            safe_print(f"    * {bid}")
        safe_print()
    if precheck.can_commit:
        safe_print(f"  [OK] 预演通过，可以执行导入。")
    else:
        safe_print(f"  [FAIL] 预演未通过，存在错误，无法执行导入。")


def cmd_waiver_import(args: argparse.Namespace) -> int:
    store = WaiverStore()
    input_path = os.path.abspath(args.input)
    backup_dir = getattr(args, "backup_dir", None)
    snapshot_name = getattr(args, "snapshot", None)
    snapshot_append = getattr(args, "snapshot_append", False)
    snapshot_fork_from = getattr(args, "snapshot_fork_from", None)
    actor = getattr(args, "actor", "")

    if getattr(args, "dry_run", False):
        try:
            precheck = store.precheck_import(input_path, mode=args.mode)
        except Exception as e:
            safe_print(f"错误: 预演失败 - {e}", file=sys.stderr)
            _record_to_snapshot(snapshot_name, "waiver import --dry-run", False, str(e), store=store,
                                allow_sealed_append=snapshot_append, fork_from=snapshot_fork_from,
                                actor=actor)
            return 20

        affected_batches: Optional[List[Dict[str, object]]] = None
        if backup_dir and precheck.new_rules:
            temp_rules = store.rules + precheck.new_rules
            temp_store = WaiverStore.__new__(WaiverStore)
            temp_store.rules = temp_rules
            try:
                affected_batches = analyze_affected_batches(backup_dir, temp_store)
                precheck.affected_batches = [str(ab["batch_id"]) for ab in affected_batches]
            except Exception:
                pass

        _print_precheck_result(precheck, affected_batches)

        summary_parts = [f"新增:{len(precheck.new_rules)}", f"冲突:{len(precheck.conflicting_rules)}",
                         f"已存在:{len(precheck.existing_rules)}", f"过期:{len(precheck.expired_rules)}"]
        _record_to_snapshot(snapshot_name, "waiver import --dry-run", precheck.can_commit,
                            "; ".join(summary_parts),
                            affected_batches=affected_batches, store=store,
                            allow_sealed_append=snapshot_append, fork_from=snapshot_fork_from,
                            actor=actor)
        return 0 if precheck.can_commit else 21

    try:
        affected_batches: Optional[List[Dict[str, object]]] = None
        if backup_dir:
            temp_rules = store.rules[:]
            precheck = store.precheck_import(input_path, mode=args.mode)
            if args.mode == "replace":
                temp_rules = []
            temp_rules.extend(precheck.new_rules)
            temp_store = WaiverStore.__new__(WaiverStore)
            temp_store.rules = temp_rules
            try:
                affected_batches = analyze_affected_batches(backup_dir, temp_store)
            except Exception:
                affected_batches = None

        result = store.import_rules(
            input_path,
            args.actor,
            mode=args.mode,
            replace_confirm_manual_delete=getattr(args, "replace_confirm_manual_delete", False),
            affected_batches=affected_batches,
        )
    except WaiverValidationError as e:
        safe_print(f"错误: {e}", file=sys.stderr)
        _record_to_snapshot(snapshot_name, "waiver import", False, str(e), store=store,
                            allow_sealed_append=snapshot_append, fork_from=snapshot_fork_from,
                            actor=actor)
        return 16
    except WaiverTransactionError as e:
        safe_print(f"错误: {e}", file=sys.stderr)
        _record_to_snapshot(snapshot_name, "waiver import", False, str(e), store=store,
                            allow_sealed_append=snapshot_append, fork_from=snapshot_fork_from,
                            actor=actor)
        return 22
    except (json.JSONDecodeError, KeyError) as e:
        safe_print(f"错误: 导入文件格式无效 - {e}", file=sys.stderr)
        _record_to_snapshot(snapshot_name, "waiver import", False, str(e), store=store,
                            allow_sealed_append=snapshot_append, fork_from=snapshot_fork_from,
                            actor=actor)
        return 17

    tx_id = result.get("transaction_id")
    safe_print(f"豁免规则导入完成 (模式: {args.mode})")
    safe_print(f"  事务ID: {tx_id or 'N/A'}")
    safe_print(f"  操作人: {args.actor}")
    safe_print(f"  文件中规则数: {result['total_imported']}")
    safe_print(f"  成功添加: {len(result['added'])}")
    if result["added"]:
        for rid in result["added"]:
            safe_print(f"    + {rid}")
    if result["skipped"]:
        safe_print(f"  跳过 (已存在): {len(result['skipped'])}")
        for rid in result["skipped"]:
            safe_print(f"    = {rid}")
    if result["conflicts"]:
        safe_print(f"  跳过 (冲突/风险): {len(result['conflicts'])}")
        for rid in result["conflicts"]:
            safe_print(f"    ! {rid}")
    actual_affected = result.get("affected_batches") or affected_batches
    if actual_affected:
        safe_print(f"  波及批次: {len(actual_affected)}")
        for ab in actual_affected:
            safe_print(f"    * 批次 {ab['batch_id']}: 影响 {ab['affected_count']} 个问题")
    safe_print()
    safe_print("提示: 如需回滚此次导入，请执行:")
    safe_print(f"  python backup_audit_cli.py waiver rollback --actor {args.actor} --yes")

    summary = f"模式:{args.mode}; 添加:{len(result['added'])}; 跳过:{len(result['skipped'])}; 冲突:{len(result['conflicts'])}"
    _record_to_snapshot(snapshot_name, "waiver import", True, summary,
                        transaction_id=tx_id, affected_batches=actual_affected, store=store,
                        allow_sealed_append=snapshot_append, fork_from=snapshot_fork_from,
                        actor=actor)
    return 0


def cmd_waiver_rollback(args: argparse.Namespace) -> int:
    store = WaiverStore()
    last_tx = store.get_last_committed_transaction()
    backup_dir = getattr(args, "backup_dir", None)
    snapshot_name = getattr(args, "snapshot", None)
    snapshot_append = getattr(args, "snapshot_append", False)
    snapshot_fork_from = getattr(args, "snapshot_fork_from", None)
    actor = getattr(args, "actor", "")

    if not last_tx:
        safe_print("错误: 没有可回滚的导入事务。", file=sys.stderr)
        _record_to_snapshot(snapshot_name, "waiver rollback", False, "没有可回滚的导入事务", store=store,
                            allow_sealed_append=snapshot_append, fork_from=snapshot_fork_from,
                            actor=actor)
        return 23

    safe_print(f"即将回滚最近一次导入事务:")
    safe_print(f"  事务ID: {last_tx.id}")
    safe_print(f"  操作人: {last_tx.actor}")
    safe_print(f"  时间: {last_tx.timestamp}")
    safe_print(f"  模式: {last_tx.mode}")
    safe_print(f"  源文件: {last_tx.source_file}")
    safe_print(f"  导入规则数: {len(last_tx.imported_rule_ids)}")
    if last_tx.affected_batches:
        safe_print(f"  导入时波及批次: {len(last_tx.affected_batches)}")
        for ab in last_tx.affected_batches:
            safe_print(f"    * 批次 {ab['batch_id']}: 影响 {ab['affected_count']} 个问题")
    safe_print()
    safe_print("回滚将:")
    safe_print(f"  - 移除本次导入的 {len(last_tx.imported_rule_ids)} 条规则")
    safe_print(f"  - 保留手工规则")
    safe_print(f"  - 标记事务状态为已回滚")
    safe_print()

    if not getattr(args, "yes", False):
        safe_print("请使用 --yes 确认回滚操作。")
        return 24

    try:
        result = store.rollback_last_import(args.actor)
    except WaiverTransactionError as e:
        safe_print(f"错误: {e}", file=sys.stderr)
        _record_to_snapshot(snapshot_name, "waiver rollback", False, str(e),
                            transaction_id=last_tx.id, store=store,
                            allow_sealed_append=snapshot_append, fork_from=snapshot_fork_from,
                            actor=actor)
        return 25

    safe_print(f"回滚完成:")
    safe_print(f"  事务ID: {result['transaction_id']}")
    safe_print(f"  操作人: {args.actor}")
    safe_print(f"  移除导入规则数: {result['removed_count']}")
    safe_print(f"  保留手工规则数: {result['manual_rules_preserved']}")
    if result["removed_ids"]:
        safe_print(f"  已移除规则:")
        for rid in result["removed_ids"]:
            safe_print(f"    - {rid}")
    post_affected: Optional[List[Dict[str, object]]] = None
    if backup_dir and result["removed_ids"]:
        try:
            current_batches = analyze_affected_batches(backup_dir, store)
            if current_batches:
                safe_print(f"  回滚后仍受影响批次: {len(current_batches)}")
                for ab in current_batches:
                    safe_print(f"    * 批次 {ab['batch_id']}: {ab['affected_count']} 个问题")
                post_affected = current_batches
            else:
                safe_print(f"  回滚后无批次受豁免规则影响")
        except Exception:
            pass

    rb_summary = f"移除:{result['removed_count']}; 保留手工:{result['manual_rules_preserved']}"
    _record_to_snapshot(snapshot_name, "waiver rollback", True, rb_summary,
                        transaction_id=result["transaction_id"],
                        affected_batches=post_affected, store=store,
                        allow_sealed_append=snapshot_append, fork_from=snapshot_fork_from,
                        actor=actor)
    return 0


def cmd_snapshot_create(args: argparse.Namespace) -> int:
    snap_store = SnapshotStore()
    actor = getattr(args, "actor", "")
    try:
        record = None
        if getattr(args, "cmd", None) or getattr(args, "summary", None):
            record = SnapshotRecord(
                command=getattr(args, "cmd", "snapshot create"),
                timestamp=datetime.now().isoformat(),
                success=True,
                output_summary=getattr(args, "summary", "显式创建快照"),
            )
        snapshot = snap_store.create(args.name, record, actor=actor)
        detail = snap_store.get_snapshot_status_detail(args.name)
        safe_print(f"快照已创建: {snapshot.name}")
        safe_print(f"  当前状态: {detail['status_label'] if detail else '草稿'}")
        safe_print(f"  创建时间: {snapshot.created_at}")
        safe_print(f"  记录条数: {len(snapshot.records)}")
        safe_print(f"  配置目录指纹: {snapshot.config_dir_fingerprint}")
        safe_print()
        if detail:
            safe_print(f"当前阶段: {detail['stuck_at']}")
            safe_print("建议下一步:")
            for i, step in enumerate(detail["next_steps"][:1], 1):
                safe_print(f"  {i}. {step}")
    except SnapshotNameConflictError as e:
        safe_print(f"错误: {e}", file=sys.stderr)
        return 31
    return 0


def cmd_snapshot_seal(args: argparse.Namespace) -> int:
    snap_store = SnapshotStore()
    actor = getattr(args, "actor", "")
    try:
        snapshot = snap_store.seal(args.name, actor=actor)
        detail = snap_store.get_snapshot_status_detail(args.name)
        safe_print(f"快照已封版: {snapshot.name}")
        safe_print(f"  封版时间: {snapshot.sealed_at}")
        safe_print(f"  封版人: {snapshot.meta.get('sealed_by', '未知')}")
        safe_print(f"  记录条数: {len(snapshot.records)}")
        safe_print()
        if detail:
            safe_print(f"当前阶段: {detail['stuck_at']}")
            safe_print("建议下一步:")
            for i, step in enumerate(detail["next_steps"][:2], 1):
                safe_print(f"  {i}. {step}")
        safe_print()
        safe_print("封版快照在重启后仍可通过 show/export 查看和对账。")
    except ValueError as e:
        safe_print(f"错误: {e}", file=sys.stderr)
        return 32
    return 0


def cmd_snapshot_fork(args: argparse.Namespace) -> int:
    snap_store = SnapshotStore()
    actor = getattr(args, "actor", "")
    try:
        record = None
        if getattr(args, "cmd", None) or getattr(args, "summary", None):
            record = SnapshotRecord(
                command=getattr(args, "cmd", f"snapshot fork --fork-from {args.source}"),
                timestamp=datetime.now().isoformat(),
                success=True,
                output_summary=getattr(args, "summary", "从源快照分叉"),
            )
        snapshot = snap_store.fork_from(args.source, args.new_name, record, actor=actor)
        detail = snap_store.get_snapshot_status_detail(args.new_name)
        safe_print(f"快照已分叉: {args.source} → {args.new_name}")
        safe_print(f"  当前状态: {detail['status_label'] if detail else '草稿'}")
        safe_print(f"  创建时间: {snapshot.created_at}")
        safe_print(f"  继承记录条数: {len(snapshot.records)}")
        safe_print(f"  分叉自: {args.source}")
        safe_print(f"  配置目录指纹: {snapshot.config_dir_fingerprint}")
        safe_print()
        if detail:
            safe_print(f"当前阶段: {detail['stuck_at']}")
            safe_print("建议下一步:")
            for i, step in enumerate(detail["next_steps"][:2], 1):
                safe_print(f"  {i}. {step}")
    except (ValueError, SnapshotNameConflictError) as e:
        safe_print(f"错误: {e}", file=sys.stderr)
        return 33
    return 0


def cmd_snapshot_list(args: argparse.Namespace) -> int:
    snap_store = SnapshotStore()
    snapshots = snap_store.list_snapshots()
    if not snapshots:
        safe_print("暂无操作快照。")
        return 0
    safe_print(f"=== 操作快照列表 ({len(snapshots)} 个) ===")
    for s in snapshots:
        seal_tag = " [封版]" if s.get("sealed") else ""
        fork_tag = f" [分叉自:{s['forked_from']}]" if s.get("forked_from") else ""
        safe_print(f"  * {s['name']}{seal_tag}{fork_tag}  记录:{s['record_count']}  创建:{s['created_at']}  更新:{s['updated_at']}")
    return 0


def cmd_snapshot_show(args: argparse.Namespace) -> int:
    snap_store = SnapshotStore()
    snapshot = snap_store.load(args.name)
    if snapshot is None:
        safe_print(f"错误: 快照 '{args.name}' 不存在。", file=sys.stderr)
        return 30

    detail = snap_store.get_snapshot_status_detail(args.name)

    safe_print(f"=== 操作快照: {snapshot.name} ===")
    safe_print(f"  当前状态: {detail['status_label'] if detail else '未知'}")
    safe_print(f"  当前阶段: {detail['stuck_at'] if detail else '未知'}")
    safe_print(f"  创建时间: {snapshot.created_at}")
    safe_print(f"  最后更新: {snapshot.updated_at}")
    safe_print(f"  记录条数: {len(snapshot.records)}")
    safe_print(f"  导出次数: {len(snapshot.export_history)}")

    if snapshot.sealed:
        safe_print(f"  封版时间: {snapshot.sealed_at}")
        safe_print(f"  封版人: {snapshot.meta.get('sealed_by', '未知')}")

    if snapshot.forked_from:
        safe_print(f"  分叉自: {snapshot.forked_from}")

    if snapshot.config_dir_fingerprint:
        safe_print(f"  配置目录指纹: {snapshot.config_dir_fingerprint}")

    safe_print()

    store = WaiverStore()

    staleness = snap_store.check_staleness(args.name, store)
    if staleness:
        safe_print("=== ⚠ 失效提示 ===")
        for sw in staleness:
            safe_print(f"  [{sw['type']}] {sw['message']}")
        safe_print()

    if getattr(args, "validate", False):
        tx_warnings = snap_store.validate_transactions(args.name, store)
        fail_warnings = snap_store.validate_failed_records(args.name)
        all_warnings = tx_warnings + fail_warnings
        if all_warnings:
            safe_print("=== 事务与失败记录校验 ===")
            for w in all_warnings:
                safe_print(f"  [WARN] {w}")
            safe_print()
        else:
            safe_print("  [OK] 校验通过，快照记录与当前状态一致。")
            safe_print()

    if snapshot.records:
        safe_print("=== 操作记录 ===")
        safe_print()
        for i, rec in enumerate(snapshot.records, 1):
            status = "[OK]" if rec.success else "[FAIL]"
            safe_print(f"  {i}. {status} {rec.command}")
            safe_print(f"     时间: {rec.timestamp}")
            if rec.transaction_id:
                safe_print(f"     事务ID: {rec.transaction_id}")
            safe_print(f"     摘要: {rec.output_summary}")
            if rec.affected_batches:
                safe_print(f"     受影响批次: {len(rec.affected_batches)}")
                for ab in rec.affected_batches:
                    safe_print(f"       * {ab['batch_id']}: {ab['affected_count']} 个问题")
            if rec.config_summary:
                parts = [f"{k}={v}" for k, v in rec.config_summary.items()]
                safe_print(f"     配置: {', '.join(parts)}")
            if rec.gap_warning:
                safe_print(f"     [WARN] {rec.gap_warning}")
            safe_print()

    if snapshot.export_history:
        safe_print("=== 导出历史 ===")
        for eh in snapshot.export_history:
            safe_print(f"  {eh['timestamp']}: {eh['format']} → {eh['output_path']}")
        safe_print()

    if detail and detail["next_steps"]:
        safe_print("=== 建议下一步 ===")
        for i, step in enumerate(detail["next_steps"], 1):
            safe_print(f"  {i}. {step}")
        safe_print()

    if getattr(args, "show_audit_log", False):
        audit_log = snap_store.get_audit_log(limit=getattr(args, "audit_log_limit", 20))
        snap_audit = [e for e in audit_log if e.snapshot_name == args.name]
        if snap_audit:
            safe_print("=== 快照审计日志 ===")
            action_labels = {
                "snapshot_create": "创建",
                "snapshot_seal": "封版",
                "snapshot_fork": "分叉",
                "snapshot_append": "追加记录",
                "snapshot_export": "导出",
                "snapshot_show": "查看",
            }
            for entry in snap_audit:
                label = action_labels.get(entry.action.value, entry.action.value)
                safe_print(f"  [{entry.timestamp}] {label} by {entry.actor}")
                if entry.detail:
                    for k, v in entry.detail.items():
                        safe_print(f"    {k}: {v}")
            safe_print()

    return 0


def cmd_snapshot_export(args: argparse.Namespace) -> int:
    snap_store = SnapshotStore()
    store = WaiverStore()
    actor = getattr(args, "actor", "")
    try:
        if args.format == "markdown":
            content = snap_store.export_markdown(args.name, store)
        else:
            content = snap_store.export_json(args.name, store)
    except ValueError as e:
        safe_print(f"错误: {e}", file=sys.stderr)
        return 30

    output_path = getattr(args, "output", None)
    if output_path:
        abs_output = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_output) or ".", exist_ok=True)
        with open(abs_output, "w", encoding="utf-8") as f:
            f.write(content)
        snap_store.record_export(args.name, args.format, abs_output, actor=actor)
        safe_print(f"快照已导出: {abs_output}")
        safe_print(f"  格式: {args.format}")
        safe_print(f"  操作人: {actor}")

        staleness = snap_store.check_staleness(args.name, store)
        if staleness:
            safe_print()
            safe_print("=== ⚠ 导出失效提示 ===")
            for sw in staleness:
                safe_print(f"  [{sw['type']}] {sw['message']}")
            safe_print("  建议在消除上述问题后重新导出，以确保导出文件的准确性。")
        safe_print()
        safe_print("导出记录已保存，重启后仍可通过 snapshot show 查看导出历史。")
    else:
        safe_print(content)
    return 0


def cmd_waiver_transactions(args: argparse.Namespace) -> int:
    store = WaiverStore()
    transactions = store.list_transactions(limit=getattr(args, "limit", 10))

    if not transactions:
        safe_print("暂无导入事务记录。")
        return 0

    safe_print(f"=== 导入事务历史 (最近 {len(transactions)} 条) ===")
    for tx in transactions:
        status_icon = "[COMMITTED]" if tx.status.value == "committed" else "[ROLLED_BACK]" if tx.status.value == "rolled_back" else "[PENDING]"
        safe_print(f"{status_icon} [{tx.timestamp}] {tx.id}")
        safe_print(f"    状态: {tx.status.value}")
        safe_print(f"    操作人: {tx.actor}")
        safe_print(f"    模式: {tx.mode}")
        safe_print(f"    源文件: {tx.source_file}")
        safe_print(f"    导入规则数: {len(tx.imported_rule_ids)}")
        if tx.affected_batches:
            safe_print(f"    波及批次: {len(tx.affected_batches)}")
            for ab in tx.affected_batches:
                safe_print(f"      * {ab['batch_id']}: {ab['affected_count']} 个问题")
        if tx.detail.get("removed_ids"):
            safe_print(f"    回滚移除: {len(tx.detail['removed_ids'])} 条")
        safe_print()
    return 0


def cmd_waiver_rescan(args: argparse.Namespace) -> int:
    backup_dir = os.path.abspath(args.backup_dir)
    batch = load_batch(backup_dir, args.batch_id)
    if not batch:
        print("错误: 未找到批次", file=sys.stderr)
        return 1

    rc = check_readonly(batch, "waiver rescan")
    if rc is not None:
        return rc

    store = WaiverStore()
    newly_waived, newly_unwaived = apply_waivers_to_batch(batch, store, args.actor, always_log=True)
    save_batch(batch, backup_dir)

    print(f"豁免规则重新扫描完成: 批次 {batch.id}")
    print(f"  操作人: {args.actor}")
    print(f"  新命中豁免: {newly_waived}")
    print(f"  豁免失效后重新暴露: {newly_unwaived}")
    active = batch.count_active_issues_by_severity()
    waived = batch.count_waived_by_severity()
    print(f"  活跃问题: 阻断={active['blocking']}, 可确认={active['confirmable']}")
    print(f"  已豁免: 阻断={waived['blocking']}, 可确认={waived['confirmable']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="backup-audit",
        description="离线备份包验收 CLI - 校验备份完整性并生成验收报告",
    )
    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    p_import = subparsers.add_parser("import", help="导入 manifest 并创建验收批次")
    p_import.add_argument("manifest", help="manifest.json 路径")
    p_import.add_argument("backup_dir", help="备份包目录")
    p_import.add_argument("--force", action="store_true", help="强制重新导入（覆盖已有批次）")
    p_import.set_defaults(func=cmd_import)

    p_precheck = subparsers.add_parser("precheck", help="运行预检（只读，不修改源文件）")
    p_precheck.add_argument("backup_dir", help="备份包目录")
    p_precheck.add_argument("--batch-id", help="指定批次 ID（默认使用最新）")
    p_precheck.add_argument("--actor", default="system", help="操作人（用于日志）")
    p_precheck.set_defaults(func=cmd_precheck)

    p_list = subparsers.add_parser("list", help="列出批次问题")
    p_list.add_argument("backup_dir", help="备份包目录")
    p_list.add_argument("--batch-id", help="指定批次 ID")
    p_list.add_argument("--status", choices=["open", "pending_fix", "confirmed", "ignored"], help="按状态过滤")
    p_list.add_argument("--severity", choices=["blocking", "confirmable"], help="按严重程度过滤")
    p_list.add_argument(
        "--waived",
        choices=["include", "exclude", "only"],
        default="include",
        help="豁免问题显示方式: include(默认)=同时显示, exclude=只显示活跃, only=只显示豁免",
    )
    p_list.set_defaults(func=cmd_list)

    p_review = subparsers.add_parser("review", help="复核/标记问题状态")
    p_review.add_argument("backup_dir", help="备份包目录")
    p_review.add_argument("issue_id", help="问题 ID")
    p_review.add_argument(
        "--status",
        choices=["pending_fix", "confirmed", "ignored", "open"],
        required=True,
        help="标记状态: pending_fix(待补), confirmed(已确认), ignored(忽略), open(重置)",
    )
    p_review.add_argument("--assignee", help="处理人")
    p_review.add_argument("--notes", help="备注")
    p_review.add_argument("--batch-id", help="指定批次 ID")
    p_review.set_defaults(func=cmd_review)

    p_export = subparsers.add_parser("export", help="导出验收报告")
    p_export.add_argument("backup_dir", help="备份包目录")
    p_export.add_argument("--format", choices=["json", "csv", "all"], default="all", help="报告格式")
    p_export.add_argument("--output", help="输出目录（默认备份目录）")
    p_export.add_argument("--batch-id", help="指定批次 ID")
    p_export.set_defaults(func=cmd_export)

    p_resume = subparsers.add_parser("resume", help="恢复/查看已有批次状态")
    p_resume.add_argument("backup_dir", help="备份包目录")
    p_resume.add_argument("--batch-id", help="指定批次 ID")
    p_resume.add_argument("--actor", default="system", help="操作人（用于日志）")
    p_resume.set_defaults(func=cmd_resume)

    p_undo = subparsers.add_parser("undo", help="撤销上一条复核操作")
    p_undo.add_argument("backup_dir", help="备份包目录")
    p_undo.add_argument("--batch-id", help="指定批次 ID")
    p_undo.set_defaults(func=cmd_undo)

    p_finalize = subparsers.add_parser("finalize", help="签收批次（阻断问题未处理时禁止，强制放行需说明理由）")
    p_finalize.add_argument("backup_dir", help="备份包目录")
    p_finalize.add_argument("--signer", required=True, help="签收人")
    p_finalize.add_argument("--reason", required=True, help="签收理由（强制放行时必须填写）")
    p_finalize.add_argument(
        "--force-with-reason",
        dest="force",
        action="store_true",
        help="强制放行：即使有未处理阻断问题也签收，必须同时提供 --reason",
    )
    p_finalize.add_argument("--batch-id", help="指定批次 ID")
    p_finalize.set_defaults(func=cmd_finalize)

    p_reopen = subparsers.add_parser("reopen", help="重开已签收批次，恢复编辑")
    p_reopen.add_argument("backup_dir", help="备份包目录")
    p_reopen.add_argument("--reopener", required=True, help="重开人")
    p_reopen.add_argument("--reason", required=True, help="重开理由")
    p_reopen.add_argument("--batch-id", help="指定批次 ID")
    p_reopen.set_defaults(func=cmd_reopen)

    p_waiver = subparsers.add_parser("waiver", help="问题豁免规则管理")
    waiver_sub = p_waiver.add_subparsers(dest="waiver_command", help="豁免规则子命令")

    p_waiver_add = waiver_sub.add_parser("add", help="新增豁免规则")
    p_waiver_add.add_argument("--actor", required=True, help="操作人/生效人")
    p_waiver_add.add_argument("--reason", required=True, help="豁免理由（必填）")
    p_waiver_add.add_argument("--description", help="补充说明")
    p_waiver_add.add_argument("--path-prefix", help="按文件路径前缀匹配，如 data/legacy/")
    p_waiver_add.add_argument("--business-line", help="按业务线匹配")
    p_waiver_add.add_argument(
        "--issue-type",
        choices=[t.value for t in IssueType],
        help="按问题类型匹配",
    )
    p_waiver_add.add_argument(
        "--severity",
        choices=[s.value for s in IssueSeverity],
        help="按严重程度匹配",
    )
    p_waiver_add.add_argument("--expires-at", help="规则过期时间 (ISO 格式，如 2025-12-31T23:59:59)")
    p_waiver_add.add_argument("--force", action="store_true", help="强制添加（即使与现有规则冲突）")
    p_waiver_add.set_defaults(func=cmd_waiver_add)

    p_waiver_list = waiver_sub.add_parser("list", help="查看豁免规则列表")
    p_waiver_list.add_argument("--include-expired", action="store_true", help="包含已过期规则")
    p_waiver_list.add_argument("--show-log", action="store_true", help="同时显示规则变更操作日志")
    p_waiver_list.set_defaults(func=cmd_waiver_list)

    p_waiver_delete = waiver_sub.add_parser("delete", help="删除豁免规则（删除后问题重新暴露）")
    p_waiver_delete.add_argument("rule_id", help="规则 ID")
    p_waiver_delete.add_argument("--actor", required=True, help="操作人")
    p_waiver_delete.add_argument("--force", action="store_true", help="强制删除（等同于 --yes）")
    p_waiver_delete.add_argument("--yes", action="store_true", help="确认删除")
    p_waiver_delete.set_defaults(func=cmd_waiver_delete)

    p_waiver_export = waiver_sub.add_parser("export", help="导出豁免规则到 JSON 文件")
    p_waiver_export.add_argument("output", help="输出文件路径 (.json)")
    p_waiver_export.add_argument("--actor", required=True, help="操作人")
    p_waiver_export.set_defaults(func=cmd_waiver_export)

    p_waiver_import = waiver_sub.add_parser(
        "import",
        help="从 JSON 文件导入豁免规则（建议先使用 --dry-run 预演）",
    )
    p_waiver_import.add_argument("input", help="输入文件路径 (.json)")
    p_waiver_import.add_argument("--actor", required=True, help="操作人")
    p_waiver_import.add_argument(
        "--mode",
        choices=["merge", "replace"],
        default="merge",
        help="导入模式: merge(默认)=合并跳过冲突, replace=替换全部",
    )
    p_waiver_import.add_argument(
        "--dry-run",
        action="store_true",
        help="仅预演导入，不实际修改规则。显示新增、冲突、已存在、已过期数量；指定 --backup-dir 时还会分析受影响批次。",
    )
    p_waiver_import.add_argument(
        "--replace-confirm-manual-delete",
        action="store_true",
        help="replace 模式下确认删除所有手工规则（防止误删）",
    )
    p_waiver_import.add_argument(
        "--backup-dir",
        default=None,
        help="备份包目录，用于分析下次 precheck/rescan 受影响的批次",
    )
    p_waiver_import.add_argument(
        "--snapshot",
        default=None,
        help="操作快照名称，自动记录本次命令的关键输出、事务ID、受影响批次到快照",
    )
    p_waiver_import.add_argument(
        "--snapshot-append",
        action="store_true",
        help="允许向已封版的快照追加记录（需同时指定 --snapshot）",
    )
    p_waiver_import.add_argument(
        "--snapshot-fork-from",
        default=None,
        help="从指定源快照分叉出新快照（新快照名称由 --snapshot 指定），并记录本次操作",
    )
    p_waiver_import.set_defaults(func=cmd_waiver_import)

    p_waiver_rollback = waiver_sub.add_parser(
        "rollback",
        help="回滚最近一次导入事务（只移除批量导入的规则，保留手工规则）",
    )
    p_waiver_rollback.add_argument("--actor", required=True, help="操作人")
    p_waiver_rollback.add_argument("--yes", action="store_true", help="确认执行回滚")
    p_waiver_rollback.add_argument(
        "--backup-dir",
        default=None,
        help="备份包目录，用于分析回滚后受影响的批次",
    )
    p_waiver_rollback.add_argument(
        "--snapshot",
        default=None,
        help="操作快照名称，自动记录本次命令的关键输出、事务ID、受影响批次到快照",
    )
    p_waiver_rollback.add_argument(
        "--snapshot-append",
        action="store_true",
        help="允许向已封版的快照追加记录（需同时指定 --snapshot）",
    )
    p_waiver_rollback.add_argument(
        "--snapshot-fork-from",
        default=None,
        help="从指定源快照分叉出新快照（新快照名称由 --snapshot 指定），并记录本次操作",
    )
    p_waiver_rollback.set_defaults(func=cmd_waiver_rollback)

    p_waiver_transactions = waiver_sub.add_parser(
        "transactions",
        help="查看导入事务历史（可用于追溯和确认回滚）",
    )
    p_waiver_transactions.add_argument("--limit", type=int, default=10, help="显示最近 N 条记录")
    p_waiver_transactions.add_argument(
        "--backup-dir",
        default=None,
        help="备份包目录，用于分析事务回滚时波及的批次",
    )
    p_waiver_transactions.set_defaults(func=cmd_waiver_transactions)

    p_waiver_rescan = waiver_sub.add_parser("rescan", help="用当前豁免规则重新扫描批次，更新豁免状态")
    p_waiver_rescan.add_argument("backup_dir", help="备份包目录")
    p_waiver_rescan.add_argument("--actor", required=True, help="操作人")
    p_waiver_rescan.add_argument("--batch-id", help="指定批次 ID")
    p_waiver_rescan.set_defaults(func=cmd_waiver_rescan)

    p_waiver_snapshot = waiver_sub.add_parser("snapshot", help="操作快照管理（记录和查看命令操作历史）")
    snapshot_sub = p_waiver_snapshot.add_subparsers(dest="snapshot_command", help="快照子命令")

    p_snap_create = snapshot_sub.add_parser("create", help="显式创建操作快照（必须先创建才能写入）")
    p_snap_create.add_argument("name", help="快照名称")
    p_snap_create.add_argument("--actor", default="", help="创建操作人（用于审计日志）")
    p_snap_create.add_argument("--summary", default=None, help="创建说明")
    p_snap_create.add_argument("--command", dest="cmd", default=None, help="关联命令")
    p_snap_create.set_defaults(func=cmd_snapshot_create)

    p_snap_seal = snapshot_sub.add_parser("seal", help="封版快照（封版后只能 --snapshot-append 续写或 --snapshot-fork-from 分叉）")
    p_snap_seal.add_argument("name", help="快照名称")
    p_snap_seal.add_argument("--actor", default="", help="封版操作人")
    p_snap_seal.set_defaults(func=cmd_snapshot_seal)

    p_snap_fork = snapshot_sub.add_parser("fork", help="从已有快照分叉出新快照")
    p_snap_fork.add_argument("--fork-from", dest="source", required=True, help="源快照名称")
    p_snap_fork.add_argument("new_name", help="新快照名称")
    p_snap_fork.add_argument("--actor", default="", help="分叉操作人（用于审计日志）")
    p_snap_fork.add_argument("--summary", default=None, help="分叉说明")
    p_snap_fork.add_argument("--command", dest="cmd", default=None, help="关联命令")
    p_snap_fork.set_defaults(func=cmd_snapshot_fork)

    p_snap_list = snapshot_sub.add_parser("list", help="列出所有操作快照")
    p_snap_list.set_defaults(func=cmd_snapshot_list)

    p_snap_show = snapshot_sub.add_parser("show", help="查看快照详情（含状态、失效提示、导出历史、下一步建议）")
    p_snap_show.add_argument("name", help="快照名称")
    p_snap_show.add_argument("--validate", action="store_true", help="校验快照中的事务是否仍有效")
    p_snap_show.add_argument("--show-audit-log", action="store_true", help="显示快照的审计日志")
    p_snap_show.add_argument("--audit-log-limit", type=int, default=20, help="审计日志显示条数 (默认: 20)")
    p_snap_show.set_defaults(func=cmd_snapshot_show)

    p_snap_export = snapshot_sub.add_parser("export", help="导出快照为 Markdown 或 JSON 文件（含事务校验、配置摘要、失效提示）")
    p_snap_export.add_argument("name", help="快照名称")
    p_snap_export.add_argument("--format", choices=["markdown", "json"], default="markdown", help="导出格式 (默认: markdown)")
    p_snap_export.add_argument("--output", default=None, help="输出文件路径 (默认输出到终端)")
    p_snap_export.add_argument("--actor", default="", help="导出操作人（用于审计日志）")
    p_snap_export.set_defaults(func=cmd_snapshot_export)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1
    if args.command == "waiver" and not getattr(args, "waiver_command", None):
        parser._subparsers._group_actions[0].choices["waiver"].print_help()
        return 1
    if getattr(args, "waiver_command", None) == "snapshot" and not getattr(args, "snapshot_command", None):
        parser._subparsers._group_actions[0].choices["waiver"]._subparsers._group_actions[0].choices["snapshot"].print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
