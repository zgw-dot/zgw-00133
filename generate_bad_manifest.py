from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta


def main() -> None:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_dir = os.path.join(base_dir, "sample_bad_manifest")
    data_dir = os.path.join(sample_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    now = datetime.now()
    window_start = (now - timedelta(hours=2)).isoformat()
    window_end = now.isoformat()

    content = b"good file content"
    fpath = os.path.join(data_dir, "good_file.dat")
    with open(fpath, "wb") as f:
        f.write(content)
    from datetime import datetime as _dt
    ts = (now - timedelta(minutes=30)).timestamp()
    os.utime(fpath, (ts, ts))

    files = [
        {
            "path": "data/good_file.dat",
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
            "business_line": "order_system",
        },
        {
            "path": "data/short_hash.dat",
            "sha256": "abc123",
            "size": 100,
            "business_line": "order_system",
        },
        {
            "path": "data/non_hex.dat",
            "sha256": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "size": 200,
            "business_line": "payment_system",
        },
        {
            "path": "data/empty_hash.dat",
            "sha256": "",
            "size": 50,
            "business_line": "order_system",
        },
    ]

    manifest = {
        "batch_id": "BATCH-BAD-SHA",
        "backup_window": {"start": window_start, "end": window_end},
        "valid_business_lines": ["order_system", "payment_system"],
        "files": files,
        "revocation_list": [],
    }

    manifest_path = os.path.join(sample_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print(f"坏 sha256 样例已生成: {sample_dir}")


if __name__ == "__main__":
    main()
