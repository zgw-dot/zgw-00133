from __future__ import annotations

import argparse
import glob
import os
import sys
from typing import List, Optional

from .models import AuditBatch, IssueStatus
from .reporter import (
    export_csv_report,
    export_json_report,
    group_issues_by_severity,
    print_summary,
)
from .validator import load_manifest, run_precheck


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
    if existing and not args.force:
        print(f"警告: 备份目录已有批次 {existing.id}，使用 --force 重新导入，或使用 resume 继续")
        return 2

    manifest = load_manifest(manifest_path)
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

    print(f"运行预检: 批次 {batch.id}")
    print(f"  (预检不会修改源备份文件)")

    new_issues = run_precheck(batch)
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

    for sev_label, issues in [
        ("阻断问题 (BLOCKING)", grouped["blocking"]),
        ("可确认问题 (CONFIRMABLE)", grouped["confirmable"]),
    ]:
        if filter_severity and filter_severity != sev_label.split()[0].lower():
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

    issue.update(
        status=status,
        assignee=args.assignee,
        notes=args.notes,
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
    if fmt == "json" or fmt == "all":
        json_path = os.path.join(output_dir, f"audit_report_{batch.id}.json")
        export_json_report(batch, json_path)
        print(f"JSON 报告: {json_path}")

    if fmt == "csv" or fmt == "all":
        csv_path = os.path.join(output_dir, f"audit_report_{batch.id}.csv")
        export_csv_report(batch, csv_path)
        print(f"CSV 报告: {csv_path}")

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
