import json
import re
import os
import base64
import urllib.request
from pathlib import Path
from datetime import datetime, timezone, timedelta

TZ_MSK = timezone(timedelta(hours=3))
now = datetime.now(TZ_MSK)
ts_now_msk = now.strftime("%d.%m.%Y %H:%M") + " МСК"

# Читаем данные из status2.txt (пишется чекером после реальной проверки)
total = 0
last_check_msk = ts_now_msk
try:
    raw = Path("status2.txt").read_text(encoding="utf-8")
    if raw.strip().startswith("{"):
        d = json.loads(raw)
        total = int(d.get("total_count", 0))
        last_check_msk = d.get("last_update_msk", ts_now_msk)
except Exception:
    pass

# Если status2.txt пуст — считаем строки в v2ray_sub.txt
if total == 0 and Path("v2ray_sub.txt").exists():
    with open("v2ray_sub.txt", "r", encoding="utf-8") as f:
        total = sum(1 for l in f if l.startswith(("vless://", "vmess://", "trojan://", "ss://")))

print(f"Confs: {total} | Last check: {last_check_msk}")

def update_file_headers(path: Path, title_base: str, fname: str, desc_text: str):
    """Обновляет метаданные подписки в файле и его base64 версии для корректного отображения в клиентах."""
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    cfgs = [l for l in lines if l and not l.startswith("#")]
    count = len(cfgs) if len(cfgs) > 0 else total
    
    full_title = f"{title_base} | {count} конфигов | {last_check_msk}"
    b64_title = base64.b64encode(full_title.encode("utf-8")).decode("ascii")
    raw_url = f"https://raw.githubusercontent.com/B3B3097/paraser/main/{fname}"
    desc = f"{desc_text} · Обновлено: {last_check_msk} · Конфигов: {count}"
    
    new_header = [
        f"# !name={full_title}",
        f"# profile-title: base64:{b64_title}",
        f"#profile-title: {full_title}",
        f"# !desc={desc}",
        f"# !url={raw_url}",
        "#profile-update-interval: 1",
        "#subscription-userinfo: upload=0; download=0; total=1099511627776; expire=4102444800",
        f"#announce: {full_title} | {desc_text}",
        "",
    ]
    new_content = "\n".join(new_header) + "\n" + "\n".join(cfgs) + "\n"
    path.write_text(new_content, encoding="utf-8")
    
    # Также обновляем base64 файл
    b64_path = path.parent / path.name.replace(".txt", "_base64.txt")
    if b64_path.exists() or "_base64" not in path.name:
        b64_data = base64.b64encode(new_content.encode("utf-8")).decode("ascii") + "\n"
        b64_path.write_text(b64_data, encoding="utf-8")
    print(f"OK: {fname} headers updated ({count} confs)")

# --- Обновляем подписки ---
update_file_headers(Path("v2ray_sub.txt"), "ОСТАТЬСЯ НА СВЯЗИ 🛜", "v2ray_sub.txt", "Основной проверенный пул конфигураций")
update_file_headers(Path("OSTATSYA_NA_SVYAZI.txt"), "ОСТАТЬСЯ НА СВЯЗИ (Xray) 🛜", "OSTATSYA_NA_SVYAZI.txt", "Проверено через Xray Core: TCP + TLS + Speedtest")
update_file_headers(Path("OSTATSYA_NA_SVYAZI_tcptls.txt"), "ОСТАТЬСЯ НА СВЯЗИ (TCP+TLS) 🛜", "OSTATSYA_NA_SVYAZI_tcptls.txt", "Топ серверов с успешным TCP и TLS рукопожатием")

# --- Запускаем генератор 3 специализированных подписок (БС) ---
try:
    import generate_subscriptions
    generate_subscriptions.generate_all_subscriptions()
except Exception as e:
    print(f"Warning: could not run generate_subscriptions: {e}")

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

# --- Обновляем описание репозитория через GitHub API (если есть токен) ---
token = os.environ.get("GITHUB_TOKEN", "")
if token:
    try:
        desc = f"ОСТАТЬСЯ НА СВЯЗИ 🛜 | {total} конфигов (БС + Интернет) | Обновлено: {last_check_msk}"
        req = urllib.request.Request(
            "https://api.github.com/repos/B3B3097/paraser",
            data=json.dumps({"description": desc}).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "paraser/4.0",
                "Content-Type": "application/json",
            },
            method="PATCH",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            pass
        print(f"[+] GitHub repo description updated: {desc}")
    except Exception as e:
        print(f"[-] GitHub description update skipped: {e}")
