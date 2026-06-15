"""生成 clean 批次数据并跑完整流程，供 README 文档抄真实输出。"""
import hashlib
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# make_temp_backup 定义在 test_regression.py
import importlib.util
_reg_mod = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests", "test_regression.py")
_spec = importlib.util.spec_from_file_location("test_regression_ext", _reg_mod)
_reg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_reg)
make_temp_backup = _reg.make_temp_backup

PROJECT = os.path.dirname(os.path.abspath(__file__))
CLEAN_DIR = os.path.join(PROJECT, "sample_backup_clean")


def run(cmd_list):
    import subprocess
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    r = subprocess.run(
        [sys.executable, os.path.join(PROJECT, "backup_audit_cli.py")] + cmd_list,
        capture_output=True, env=env,
    )
    stdout = r.stdout.decode("utf-8", errors="replace")
    stderr = r.stderr.decode("utf-8", errors="replace")
    tag = f"$ python backup_audit_cli.py {' '.join(cmd_list)}"
    sep = "=" * 72
    print(f"\n{sep}\n{tag}\n{sep}")
    if stdout:
        print(stdout.rstrip())
    if stderr:
        print("--- STDERR ---")
        print(stderr.rstrip())
    print(f"\n[exit code: {r.returncode}]")
    # 为了方便 assert，返回解码后的字符串
    r.stdout_text = stdout
    r.stderr_text = stderr
    return r


if __name__ == "__main__":
    # --- clean 批次: 所有 sha256/size 都匹配，且在备份窗口内 ---
    if os.path.isdir(CLEAN_DIR):
        shutil.rmtree(CLEAN_DIR)
    content1 = b"clean-file-1-no-issues"
    content2 = b"clean-file-2-no-issues-either"
    make_temp_backup(
        CLEAN_DIR,
        [
            {"name": "report_2024_001.parquet", "content": content1,
             "business_line": "order_system", "age_minutes": 10},
            {"name": "report_2024_002.parquet", "content": content2,
             "business_line": "order_system", "age_minutes": 10},
            {"name": "report_2024_003.parquet", "content": b"third clean file",
             "business_line": "order_system", "age_minutes": 10},
        ],
        valid_bl=["order_system"],
        window_hours=24,
    )

    print("===== CLEAN 批次完整流程输出 =====")
    run(["import", os.path.join(CLEAN_DIR, "manifest.json"), CLEAN_DIR])
    run(["precheck", CLEAN_DIR])
    run(["list", CLEAN_DIR, "--severity", "blocking"])
    run(["list", CLEAN_DIR, "--severity", "confirmable"])
    run(["finalize", CLEAN_DIR, "--signer", "wangwu",
         "--reason", "所有校验通过，未处理问题数为 0，可归档"])

    print("\n\n===== CLEAN 批次：签收后执行只读拦截 =====\n")
    run(["precheck", CLEAN_DIR])
    run(["undo", CLEAN_DIR])
    run(["finalize", CLEAN_DIR, "--signer", "other",
         "--reason", "重复签收测试"])

    print("\n\n===== CLEAN 批次：resume 显示 finalized 状态 =====\n")
    run(["resume", CLEAN_DIR])

    print("\n\n===== CLEAN 批次：reopen 恢复编辑 =====\n")
    run(["reopen", CLEAN_DIR, "--reopener", "ops_lead",
         "--reason", "补充复核一条可确认问题"])

    print("\n\n===== CLEAN 批次：reopen 后恢复可 review =====\n")
    run(["list", CLEAN_DIR, "--severity", "confirmable"])
    run(["resume", CLEAN_DIR])

    # --- mixed 批次: 既有 blocking 也有 confirmable，已有 sample_backup ---
    print("\n\n==============================================================")
    print("===== MIXED 批次完整流程输出（已有 sample_backup）   =====")
    print("==============================================================\n")
    MIXED = os.path.join(PROJECT, "sample_backup")
    if os.path.isdir(os.path.join(MIXED, ".audit_state")):
        shutil.rmtree(os.path.join(MIXED, ".audit_state"))

    run(["import", os.path.join(MIXED, "manifest.json"), MIXED])
    run(["precheck", MIXED])
    run(["list", MIXED, "--severity", "blocking"])
    run(["list", MIXED, "--severity", "confirmable"])

    # 先尝试不带 force 签收 → 应当失败
    print("\n--- mixed 批次：无 force 签收（预期失败）---\n")
    run(["finalize", MIXED, "--signer", "wangwu",
         "--reason", "误尝试无 force 签收"])

    # 处理掉部分 blocking，让 blocking 剩 1 条
    # 取前 2 个 blocking 问题
    import json
    state_dir = os.path.join(MIXED, ".audit_state")
    batch_file = [f for f in os.listdir(state_dir) if f.startswith("batch_")][0]
    with open(os.path.join(state_dir, batch_file), "r", encoding="utf-8") as fp:
        batch = json.load(fp)
    blocking_issue_ids = [
        i["id"] for i in batch["issues"]
        if i["severity"] == "blocking"
    ][:2]
    for iid in blocking_issue_ids:
        run(["review", MIXED, iid, "--status", "confirmed",
             "--assignee", "zhangsan", "--notes", "已人工核实可接受"])

    print("\n--- mixed 批次：处理 2/3 blocking 后，再次尝试签收（预期仍失败）---\n")
    run(["finalize", MIXED, "--signer", "wangwu",
         "--reason", "还剩 1 条 blocking"])

    print("\n--- mixed 批次：强制放行（--force-with-reason + 理由）---\n")
    run(["finalize", MIXED, "--signer", "dept_manager",
         "--reason", "经 2024-Q2 备份风险评审会审批，剩余 1 条 SHA 不匹配可追溯到源端已知故障，特批放行",
         "--force-with-reason"])

    print("\n--- mixed 批次：resume 看到 finalized + 强制放行信息 ---\n")
    run(["resume", MIXED])

    print("\n--- mixed 批次：list 看到 finalized 状态 ---\n")
    run(["list", MIXED])

    print("\n--- mixed 批次：只读拦截 review 和 precheck ---\n")
    run(["precheck", MIXED])
    first_blocking = [
        i["id"] for i in batch["issues"] if i["severity"] == "blocking"
    ][-1]
    run(["review", MIXED, first_blocking, "--status", "confirmed"])

    print("\n--- mixed 批次：reopen 恢复编辑，累计重开次数 1 ---\n")
    run(["reopen", MIXED, "--reopener", "zhangsan",
         "--reason", "上轮签收漏处理 1 条 blocking，需补复核"])

    print("\n--- mixed 批次：reopen 后再次 resume 看到重开次数 ---\n")
    run(["resume", MIXED])

    print("\n--- mixed 批次：reopen 后再次 finalize（现在 0 条 blocking 未处理 = 正常签收）---\n")
    last_blocking = [
        i["id"] for i in json.load(
            open(os.path.join(state_dir, batch_file), "r", encoding="utf-8")
        )["issues"] if i["severity"] == "blocking"
    ][-1]
    run(["review", MIXED, last_blocking, "--status", "confirmed",
         "--assignee", "zhangsan", "--notes", "重开后补充完成复核"])
    run(["finalize", MIXED, "--signer", "dept_manager",
         "--reason", "所有 blocking 已复核完成，批次可归档"])
    run(["resume", MIXED])

    print("\n--- mixed 批次：export 导出包含 signoff 摘要和操作日志 ---\n")
    report_dir = os.path.join(MIXED, "reports_doc")
    if os.path.isdir(report_dir):
        shutil.rmtree(report_dir)
    run(["export", MIXED, "--output", report_dir])
    print("\n--- JSON 报告开头（signoff/reopen_records/operation_log 关键字段）---\n")
    json_file = [f for f in os.listdir(report_dir) if f.endswith(".json")][0]
    with open(os.path.join(report_dir, json_file), "r", encoding="utf-8") as fp:
        data = json.load(fp)
    for key in ["batch_id", "status", "signoff", "reopen_records"]:
        print(f"{key}: {json.dumps(data.get(key), ensure_ascii=False, indent=2)}")
    print(f"operation_log 条目数: {len(data.get('operation_log', []))}")
    print("  前 3 条 action: " + ", ".join(
        l["action"] for l in data.get("operation_log", [])[:3]
    ))
