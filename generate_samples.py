"""Generate sample backup package data for testing."""
import hashlib
import json
import os
import random
from datetime import datetime, timedelta


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def set_file_mtime(path: str, dt: datetime) -> None:
    ts = dt.timestamp()
    os.utime(path, (ts, ts))


def main() -> None:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_dir = os.path.join(base_dir, "sample_backup")
    data_dir = os.path.join(sample_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    now = datetime.now()
    window_start = (now - timedelta(hours=2)).isoformat()
    window_end = now.isoformat()
    outside_time = now - timedelta(days=7)

    files_info = []

    good_content = b"this is a normal backup file with correct content"
    good_path = os.path.join(data_dir, "normal_file.dat")
    with open(good_path, "wb") as f:
        f.write(good_content)
    set_file_mtime(good_path, now - timedelta(minutes=30))
    files_info.append({
        "path": os.path.relpath(good_path, sample_dir).replace("\\", "/"),
        "sha256": sha256_file(good_path),
        "size": len(good_content),
        "business_line": "order_system",
    })

    good2_content = b"another good file for business payments"
    good2_path = os.path.join(data_dir, "payments_2024.dat")
    with open(good2_path, "wb") as f:
        f.write(good2_content)
    set_file_mtime(good2_path, now - timedelta(minutes=60))
    files_info.append({
        "path": os.path.relpath(good2_path, sample_dir).replace("\\", "/"),
        "sha256": sha256_file(good2_path),
        "size": len(good2_content),
        "business_line": "payment_system",
    })

    bad_hash_content = b"this file content has been tampered with!"
    bad_hash_path = os.path.join(data_dir, "tampered_file.dat")
    with open(bad_hash_path, "wb") as f:
        f.write(bad_hash_content)
    set_file_mtime(bad_hash_path, now - timedelta(minutes=45))
    wrong_hash = hashlib.sha256(b"completely different content that does not match").hexdigest()
    files_info.append({
        "path": os.path.relpath(bad_hash_path, sample_dir).replace("\\", "/"),
        "sha256": wrong_hash,
        "size": len(bad_hash_content),
        "business_line": "order_system",
    })

    wrong_size_content = b"this file is shorter than declared size"
    wrong_size_path = os.path.join(data_dir, "wrong_size.dat")
    with open(wrong_size_path, "wb") as f:
        f.write(wrong_size_content)
    set_file_mtime(wrong_size_path, now - timedelta(minutes=20))
    files_info.append({
        "path": os.path.relpath(wrong_size_path, sample_dir).replace("\\", "/"),
        "sha256": sha256_file(wrong_size_path),
        "size": len(wrong_size_content) + 500,
        "business_line": "user_system",
    })

    missing_path_rel = "data/deleted_file.dat"
    files_info.append({
        "path": missing_path_rel,
        "sha256": hashlib.sha256(b"this file was deleted").hexdigest(),
        "size": 1024,
        "business_line": "order_system",
    })

    outside_content = b"this file was modified outside the backup window"
    outside_path = os.path.join(data_dir, "old_file.dat")
    with open(outside_path, "wb") as f:
        f.write(outside_content)
    set_file_mtime(outside_path, outside_time)
    files_info.append({
        "path": os.path.relpath(outside_path, sample_dir).replace("\\", "/"),
        "sha256": sha256_file(outside_path),
        "size": len(outside_content),
        "business_line": "payment_system",
    })

    wrong_bl_content = b"file with unknown business line"
    wrong_bl_path = os.path.join(data_dir, "unknown_bl.dat")
    with open(wrong_bl_path, "wb") as f:
        f.write(wrong_bl_content)
    set_file_mtime(wrong_bl_path, now - timedelta(minutes=15))
    files_info.append({
        "path": os.path.relpath(wrong_bl_path, sample_dir).replace("\\", "/"),
        "sha256": sha256_file(wrong_bl_path),
        "size": len(wrong_bl_content),
        "business_line": "unknown_system_xyz",
    })

    manifest = {
        "batch_id": "BATCH-2024-001",
        "backup_window": {
            "start": window_start,
            "end": window_end,
        },
        "valid_business_lines": ["order_system", "payment_system", "user_system"],
        "files": files_info,
        "revocation_list": [],
    }

    manifest_path = os.path.join(sample_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print(f"样例数据已生成: {sample_dir}")
    print(f"  Manifest: {manifest_path}")
    print(f"  文件数: {len(files_info)}")
    print(f"    - 正常文件: 2")
    print(f"    - 坏 sha256: 1")
    print(f"    - 大小不匹配: 1")
    print(f"    - 缺失文件: 1")
    print(f"    - 备份窗口外: 1")
    print(f"    - 未知业务线: 1")
    print(f"    - 空撤销列表: yes")


if __name__ == "__main__":
    main()
