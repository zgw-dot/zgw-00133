from __future__ import annotations

import argparse
import glob
import os
import sys
from typing import List, Optional

from .models import AuditBatch, IssueStatus, OperationType
from .reporter import (
    export_csv_report,
    export_json_report,
    group_issues_by_severity,
    print_summary,
)
from .validator import load_manifest, run_precheck, ManifestValidationError


STORAGE_DIR_NAME = ".audit_state"


def get_storage_dir(backup_dir: str) -> str:
    return os.path.join(backup_dir, STORAGE_DIR_NAME)


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
    save_batch(batch, backup_dir)

    print(f"\n预检完成:")
    print(f"  新增问题: {len(new_issues)}")
    print(f"  累计问题: {len(batch.issues)}")
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

    grouped = group_issues_by_severity(batch)

    filter_status = getattr(args, "status", None)
    filter_severity = getattr(args, "severity", None)

    for sev_key, sev_label, issues in [
        ("blocking", "阻断问题 (BLOCKING)", grouped["blocking"]),
        ("confirmable", "可确认问题 (CONFIRMABLE)", grouped["confirmable"]),
    ]:
        if filter_severity and filter_severity != sev_key:
            continue
        if not issues:
            continue
        print(f"\n--- {sev_label} ---")
        for issue in issues:
            if filter_status and issue.status.value != filter_status:
                continue
            print(f"  [{issue.id}] {issue.type.value:20s} {issue.status.value:15s} {issue.file_path}")
            if issue.assignee:
                print(f"      处理人: {issue.assignee}")
            if issue.notes:
                print(f"      备注: {issue.notes}")
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

    print(f"已恢复批次: {batch.id}")
    print(f"  存储文件: {batch.storage_path}")
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
    p_precheck.set_defaults(func=cmd_precheck)

    p_list = subparsers.add_parser("list", help="列出批次问题")
    p_list.add_argument("backup_dir", help="备份包目录")
    p_list.add_argument("--batch-id", help="指定批次 ID")
    p_list.add_argument("--status", choices=["open", "pending_fix", "confirmed", "ignored"], help="按状态过滤")
    p_list.add_argument("--severity", choices=["blocking", "confirmable"], help="按严重程度过滤")
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

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
