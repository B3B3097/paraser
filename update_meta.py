import json
import re
import base64
from pathlib import Path
from datetime import datetime, timezone, timedelta

TZ_MSK = timezone(timedelta(hours=3))
now = datetime.now(TZ_MSK)
ts_now_msk = now.strftime("%d.%m.%Y %H:%M") + " МСК"

# Читаем данные из status2.txt (пишется чекером после реальной проверки)
total = 0
last_check_msk = ts_now_msk
try:
    raw = Path("status2.txt").read_text()
    if raw.strip().startswith("{"):
        d = json.loads(raw)
        total = int(d.get("total_count", 0))
        last_check_msk = d.get("last_update_msk", ts_now_msk)
except Exception:
    pass

# Если status2.txt пуст — считаем строки в v2ray_sub.txt
if total == 0 and Path("v2ray_sub.txt").exists():
    with open("v2ray_sub.txt") as f:
        total = sum(1 for l in f if l.startswith(("vless://", "vmess://", "trojan://", "ss://")))

print(f"Confs: {total} | Last check: {last_check_msk}")

# --- Обновляем #profile-title в v2ray_sub.txt ---
sub_path = Path("v2ray_sub.txt")
if sub_path.exists():
    lines = sub_path.read_text(encoding="utf-8").splitlines(keepends=True)
    new_title = f"#profile-title: base64:{base64.b64encode(f'ОСТАТЬСЯ НА СВЯЗИ🛜 | {total} конфигов | {last_check_msk}'.encode()).decode()}\n"
    updated = False
    for i, line in enumerate(lines):
        if line.startswith("#profile-title:"):
            lines[i] = new_title
            updated = True
            break
    if not updated:
        lines.insert(0, new_title)
    sub_path.write_text("".join(lines), encoding="utf-8")
    print(f"OK: v2ray_sub.txt profile-title updated ({total} confs, {last_check_msk})")

# --- Обновляем README.md ---
readme_path = Path("README.md")
if readme_path.exists():
    content = readme_path.read_text(encoding="utf-8")
    pattern = r"\*Последнее обновление: [^*]+\*"
    replacement = f"*Последнее обновление: {last_check_msk}*"
    new_content = re.sub(pattern, replacement, content)
    if new_content != content:
        readme_path.write_text(new_content, encoding="utf-8")
        print("OK: README.md updated")
    else:
        print("README.md: no change needed")
