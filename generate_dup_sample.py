from __future__ import annotations

import hashlib
import json
import os
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
    sample_dir = os.path.join(base_dir, "sample_backup_dup")
    data_dir = os.path.join(sample_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    now = datetime.now()
    window_start = (now - timedelta(hours=2)).isoformat()
    window_end = now.isoformat()

    content = b"file that appears twice in manifest"
    fpath = os.path.join(data_dir, "duplicated_file.dat")
    with open(fpath, "wb") as f:
        f.write(content)
    set_file_mtime(fpath, now - timedelta(minutes=30))

    file_entry = {
        "path": os.path.relpath(fpath, sample_dir).replace("\\", "/"),
        "sha256": sha256_file(fpath),
        "size": len(content),
        "business_line": "order_system",
    }

    manifest = {
        "batch_id": "BATCH-DUP-001",
        "backup_window": {
            "start": window_start,
            "end": window_end,
        },
        "valid_business_lines": ["order_system"],
        "files": [file_entry, file_entry],
        "revocation_list": ["cert-123", "cert-456"],
    }

    manifest_path = os.path.join(sample_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print(f"重复条目样例已生成: {sample_dir}")
    print(f"  Manifest: {manifest_path}")
    print(f"  重复文件条目: 2 次 (data/duplicated_file.dat)")
    print(f"  非空吊销列表: 是")


if __name__ == "__main__":
    main()
