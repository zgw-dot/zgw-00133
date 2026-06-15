import json
import sys

with open("sample_backup/reports/audit_report_BATCH-2024-001.json", "r", encoding="utf-8") as f:
    report = json.load(f)

print("=== JSON 报告内容校验 ===")
print("batch_id:", report["batch_id"])
print("total_issues:", report["summary"]["total_issues"])
print("blocking:", report["summary"]["by_severity"]["blocking"])
print("confirmable:", report["summary"]["by_severity"]["confirmable"])
print("by_status:", report["summary"]["by_status"])
print()

for issue in report["all_issues"]:
    aid = issue["id"]
    atype = issue["type"]
    astatus = issue["status"]
    aassignee = issue.get("assignee")
    anotes = issue.get("notes")
    print(f"  [{aid}] {atype:25s} status={astatus:15s} assignee={str(aassignee):10s} notes={str(anotes)[:30]}")

print()
print("=== 一致性检查 ===")
ids_in_report = [i["id"] for i in report["all_issues"]]
print("Issue IDs:", ids_in_report)

ignored = [i for i in report["all_issues"] if i["status"] == "ignored"]
if ignored:
    i = ignored[0]
    print(f"ignored issue: id={i['id']} assignee={i['assignee']} notes={i['notes']}")
    assert i["id"] == "02d8013c22e5", "ignored issue id mismatch"
    assert i["assignee"] == "wangwu", "assignee mismatch"
    assert "已知篡改" in i["notes"], "notes mismatch"
    print("ignored issue 验证通过")

open_issues = [i for i in report["all_issues"] if i["status"] == "open"]
assert len(open_issues) == 5, f"expected 5 open, got {len(open_issues)}"
print(f"open issues 数量: {len(open_issues)} 验证通过")
print("跨进程一致性检查全部通过!")
