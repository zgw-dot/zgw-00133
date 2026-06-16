import os
import json
import hashlib
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BACKUP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BACKUP_DIR, "data")
STORAGE_DIR = os.path.join(BACKUP_DIR, ".audit_state")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(STORAGE_DIR, exist_ok=True)


def sha256_file(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main():
    files = []
    for i in range(5):
        name = f"pay_file_{i}.dat"
        content = f"payment data record {i}".encode("utf-8")
        with open(os.path.join(DATA_DIR, name), "wb") as f:
            f.write(content)
        files.append({
            "path": f"data/{name}",
            "size": len(content),
            "mtime": int(datetime.now().timestamp()),
            "blake3": sha256_file(content),
            "business_line": "payment_system" if i < 3 else "order_system",
        })

    bad = "bad_checksum_file.dat"
    real_data = b"corrupted content"
    correct_hash = sha256_file(b"expected content")
    with open(os.path.join(DATA_DIR, bad), "wb") as f:
        f.write(real_data)
    files.append({
        "path": f"data/{bad}",
        "size": len(real_data),
        "mtime": int(datetime.now().timestamp()),
        "blake3": correct_hash,
        "business_line": "order_system",
    })

    unknown = "unknown_line.dat"
    real_data = b"unknown biz"
    with open(os.path.join(DATA_DIR, unknown), "wb") as f:
        f.write(real_data)
    files.append({
        "path": f"data/{unknown}",
        "size": len(real_data),
        "mtime": int(datetime.now().timestamp()),
        "blake3": sha256_file(real_data),
        "business_line": "not_exist_line",
    })

    batch_id = datetime.now().strftime("BATCH_MANUAL_%Y%m%d_%H%M%S")
    batch = {
        "batch_id": batch_id,
        "exported_at": datetime.now().isoformat(),
        "finalized": False,
        "signed_off": False,
        "files": files,
        "issues": [],
    }
    batch_path = os.path.join(STORAGE_DIR, f"batch_{batch_id}.json")
    with open(batch_path, "w", encoding="utf-8") as f:
        json.dump(batch, f, indent=2, ensure_ascii=False)

    print(f"[OK] 批次 {batch_id} 已创建，共 {len(files)} 个文件")
    print(f"  - 3 个 payment_system 业务线正常文件")
    print(f"  - 2 个 order_system 业务线正常文件")
    print(f"  - 1 个 bad_checksum 文件 (order_system)")
    print(f"  - 1 个 unknown business line 文件")
    print(f"批次文件: {batch_path}")


if __name__ == "__main__":
    main()
