import json
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta

TZ_MSK = timezone(timedelta(hours=3))
now = datetime.now(TZ_MSK)
ts_msk = now.strftime("%d.%m.%Y %H:%M") + " МСК"

total = 0
try:
    raw = Path("status2.txt").read_text()
    if raw.strip().startswith("{"):
        d = json.loads(raw)
        total = int(d.get("total_count", 0))
except Exception:
    pass

if total == 0 and Path("v2ray_sub.txt").exists():
    with open("v2ray_sub.txt") as f:
        total = sum(1 for l in f if l.startswith(("vless://", "vmess://", "trojan://", "ss://")))

print(f"Confs: {total} | Time: {ts_msk}")

if Path("README.md").exists():
    content = Path("README.md").read_text(encoding="utf-8")
    pattern = r"\*Последнее обновление: [^*]+\*"
    replacement = f"*Последнее обновление: {ts_msk}*"
    new_content = re.sub(pattern, replacement, content)
    if new_content != content:
        Path("README.md").write_text(new_content, encoding="utf-8")
        print("OK: README.md updated")
    else:
        print("README.md: no change needed")
