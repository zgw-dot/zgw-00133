"""验证 precheck 不修改源文件"""
import os
import hashlib
import shutil
import subprocess
import sys


def file_snapshot(path: str) -> dict:
    with open(path, "rb") as f:
        content = f.read()
    return {
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "mtime": os.path.getmtime(path),
    }


def dir_snapshot(dir_path: str) -> dict:
    snap = {}
    for root, _, files in os.walk(dir_path):
        for f in files:
            fp = os.path.join(root, f)
            rel = os.path.relpath(fp, dir_path)
            snap[rel] = file_snapshot(fp)
    return snap


def main() -> int:
    base = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base, "sample_backup", "data")
    manifest_path = os.path.join(base, "sample_backup", "manifest.json")
    state_dir = os.path.join(base, "sample_backup", ".audit_state")

    if os.path.exists(state_dir):
        shutil.rmtree(state_dir)

    before = dir_snapshot(data_dir)
    print(f"Precheck 前: {len(before)} 个文件已记录")

    result = subprocess.run(
        [sys.executable, os.path.join(base, "backup_audit_cli.py"), "import", manifest_path, os.path.join(base, "sample_backup")],
        capture_output=True, text=True,
    )
    print("import:", result.returncode)

    result = subprocess.run(
        [sys.executable, os.path.join(base, "backup_audit_cli.py"), "precheck", os.path.join(base, "sample_backup")],
        capture_output=True, text=True,
    )
    print("precheck:", result.returncode)

    after = dir_snapshot(data_dir)
    print(f"Precheck 后: {len(after)} 个文件")

    unchanged = 0
    changed = []
    for path in before:
        if path not in after:
            changed.append(f"  丢失: {path}")
            continue
        if before[path] != after[path]:
            b = before[path]
            a = after[path]
            changed.append(f"  修改: {path}")
            if b["size"] != a["size"]:
                changed.append(f"    大小: {b['size']} -> {a['size']}")
            if b["sha256"] != a["sha256"]:
                changed.append(f"    sha256: {b['sha256'][:16]}... -> {a['sha256'][:16]}...")
            if b["mtime"] != a["mtime"]:
                changed.append(f"    mtime: {b['mtime']} -> {a['mtime']}")
        else:
            unchanged += 1

    new_files = set(after.keys()) - set(before.keys())
    for nf in new_files:
        changed.append(f"  新增: {nf}")

    print(f"\n未改变: {unchanged}/{len(before)}")
    if changed:
        print("改变的文件:")
        for c in changed:
            print(c)
        return 1
    else:
        print("验证通过: precheck 未修改任何源文件")
        return 0


if __name__ == "__main__":
    sys.exit(main())
