#!/usr/bin/env python3
"""
generate_subscriptions.py — Генератор 3 новых подписок:
1. sub_250_20bs.txt: ровно 250 конфигов (20 из которых БС, 230 скоростной интернет)
2. sub_bs_top_ping.txt: конфиги белых списков, отсортированные по минимальному пингу
3. sub_bs_all.txt: все доступные рабочие конфиги белых списков

Проверка белых списков (БС) построена на анализе подписки vlessforu (sub.vlessfo.ru)
и правилах изоляции Рунета / ТСПУ:
- RU Whitelist SNI: vk.com, mail.ru, yandex.ru, ok.ru, x5.ru, sber.ru, gosuslugi.ru, avito.ru, 4pda.to, habr.com и др.
- Специальные мобильные LTE/5G обходы (xhttp, SplitHTTP, WebSocket, Reality)
- Исключение заблокированных зарубежных SNI (cloudflare, amazon, google, intel и т.д.)
"""

import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import parse_qs, unquote

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
VLESSFORU_URL = "https://sub.vlessfo.ru/vlessforu/working_configs.txt"

# Корневые домены и поддомены, входящие в официальные «белые списки» РФ (ТСПУ / глушение мобильного интернета)
TRUE_BS_ROOTS = {
    "vk.com", "userapi.com", "mail.ru", "ok.ru",
    "yandex.ru", "ya.ru", "yandex.net", "yccdn.ru", "yccdn.cloud.yandex.net",
    "x5.ru", "5post-gate.x5.ru", "ads.x5.ru",
    "gosuslugi.ru", "mos.ru", "sberbank.ru", "sber.ru",
    "ozon.ru", "wildberries.ru", "avito.ru", "4pda.to", "habr.com",
    "tinkoff.ru", "t-bank.ru", "megafon.ru", "mts.ru", "beeline.ru", "tele2.ru", "rutube.ru",
    # Специальные узлы и фронты обхода vlessforu для LTE/5G
    "refcapmap.pro", "refprov.online", "sysopnova.art", "hello-there.ru", "utiltools.site", "4subnodes.com"
}

def extract_sni_and_host(link: str) -> tuple[str, str]:
    """Извлекает SNI и Host из vless/vmess/trojan/ss ссылки."""
    if link.startswith("vless://") or link.startswith("trojan://"):
        hash_idx = link.find("#")
        main = link[:hash_idx] if hash_idx != -1 else link
        q_idx = main.find("?")
        if q_idx != -1:
            params = parse_qs(main[q_idx + 1:])
            sni = params.get("sni", [""])[0].lower().strip()
            host = params.get("host", [""])[0].lower().strip()
            return sni, host
    elif link.startswith("vmess://"):
        try:
            b64_str = link[8:]
            pad = len(b64_str) % 4
            if pad:
                b64_str += "=" * (4 - pad)
            data = json.loads(base64.b64decode(b64_str).decode("utf-8", errors="ignore"))
            sni = (data.get("sni") or "").lower().strip()
            host = (data.get("host") or "").lower().strip()
            return sni, host
        except Exception:
            pass
    return "", ""

def extract_ping(link: str) -> int:
    """Извлекает пинг (мс) из комментария ссылки."""
    hash_idx = link.find("#")
    remark = unquote(link[hash_idx + 1:]) if hash_idx != -1 else ""
    m = re.search(r"(\d+)\s*ms", remark, re.IGNORECASE)
    if m:
        return int(m.group(1))
    m = re.search(r"(\d+)\s*мс", remark, re.IGNORECASE)
    if m:
        return int(m.group(1))
    # Приоритет проверенных vlessforu конфигов
    if "top ping" in remark.lower():
        return 70
    if "top speed" in remark.lower():
        return 90
    if "lte/5g" in remark.lower():
        return 120
    return 9999

def extract_speed(link: str) -> float:
    """Извлекает скорость (MB/s) из комментария ссылки."""
    hash_idx = link.find("#")
    remark = unquote(link[hash_idx + 1:]) if hash_idx != -1 else ""
    m = re.search(r"(\d+(?:\.\d+)?)\s*MB/s", remark, re.IGNORECASE)
    if m:
        return float(m.group(1))
    m = re.search(r"(\d+(?:\.\d+)?)\s*KB/s", remark, re.IGNORECASE)
    if m:
        return float(m.group(1)) / 1024.0
    return 1.0

def is_true_whitelist_config(link: str) -> bool:
    """
    Автономная проверка конфигурации на соответствие Белым Спискам (БС) РФ
    через whitelist_validator (SNI 23k+ доменов, CIDR 28k+ подсетей РФ, ASN и DPI-маркеры).
    """
    try:
        from whitelist_validator import evaluate_whitelist_criteria
        is_bs, _, _ = evaluate_whitelist_criteria(link)
        return is_bs
    except Exception:
        # Резервный поиск по корням доменов
        hash_idx = link.find("#")
        remark = unquote(link[hash_idx + 1:]).lower() if hash_idx != -1 else ""
        if any(m in remark for m in ["lte/5g", "sni vk", "sni x5", "белый список", "белые списки"]):
            return True
            
        sni, host = extract_sni_and_host(link)
        for target in (sni, host):
            if not target:
                continue
            for root in TRUE_BS_ROOTS:
                if target == root or target.endswith("." + root):
                    return True
        return False

def fetch_vlessforu_configs() -> list[str]:
    """Скачивает и возвращает актуальные конфиги из vlessforu."""
    import urllib.request
    try:
        req = urllib.request.Request(
            VLESSFORU_URL,
            headers={"User-Agent": "v2rayNG/1.8.12 (Linux; Android 14)"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
            return lines
    except Exception as e:
        print(f"[!] Внимание: не удалось скачать vlessforu ({e}), используем локальные кэшированные данные")
        return []

def format_subscription(configs: list[str], title: str, filename: str, announce_text: str) -> str:
    """Форматирует подписку со всеми стандартными заголовками (v2rayNG, Happ, Streisand, NekoBox, Hiddify, Sing-box)."""
    TZ_MSK = timezone(timedelta(hours=3))
    now_msk = datetime.now(TZ_MSK)
    ts = now_msk.strftime("%d.%m.%Y %H:%M МСК")
    total_cfgs = len(configs)
    
    EXPIRE_TS = 4102444800  # 2100-01-01 UTC
    TOTAL_BYTES = 1099511627776  # 1 TiB
    
    full_title = f"{title} | {total_cfgs} конфигов | {ts}"
    b64_title = base64.b64encode(full_title.encode("utf-8")).decode("ascii")
    raw_url = f"https://raw.githubusercontent.com/B3B3097/paraser/main/{filename}"
    
    header = [
        f"# !name={full_title}",
        f"# profile-title: base64:{b64_title}",
        f"#profile-title: {full_title}",
        f"# !desc={announce_text} · Обновлено: {ts} · Всего конфигов: {total_cfgs}",
        f"# !url={raw_url}",
        "#profile-update-interval: 1",
        f"#subscription-userinfo: upload=0; download=0; total={TOTAL_BYTES}; expire={EXPIRE_TS}",
        f"#announce: {full_title} | {announce_text}",
        "",
    ]
    return "\n".join(header) + "\n" + "\n".join(configs) + "\n"

def generate_all_subscriptions():
    print("[*] Запуск формирования 3 подписок...")
    
    # 1. Загрузка
    vlessforu_configs = fetch_vlessforu_configs()
    print(f"[+] Из vlessforu получено {len(vlessforu_configs)} конфигов")
    
    valid_wl_file = os.path.join(PROJECT_DIR, "valid_whitelist_links.txt")
    valid_int_file = os.path.join(PROJECT_DIR, "valid_internet_links.txt")
    
    valid_wl = []
    if os.path.exists(valid_wl_file):
        with open(valid_wl_file, "r", encoding="utf-8", errors="ignore") as f:
            valid_wl = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            
    valid_int = []
    if os.path.exists(valid_int_file):
        with open(valid_int_file, "r", encoding="utf-8", errors="ignore") as f:
            valid_int = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            
    # 2. Фильтрация на БС и Интернет
    bs_vlessforu = []
    internet_vlessforu = []
    for cfg in vlessforu_configs:
        if is_true_whitelist_config(cfg):
            bs_vlessforu.append(cfg)
        else:
            internet_vlessforu.append(cfg)
            
    bs_pool = set(bs_vlessforu)
    internet_pool = set(internet_vlessforu)
    
    for cfg in valid_wl:
        if is_true_whitelist_config(cfg):
            bs_pool.add(cfg)
        else:
            internet_pool.add(cfg)
            
    for cfg in valid_int:
        if is_true_whitelist_config(cfg):
            bs_pool.add(cfg)
        else:
            internet_pool.add(cfg)
            
    print(f"[+] Всего уникальных БС конфигов: {len(bs_pool)}")
    print(f"[+] Всего уникальных интернет конфигов: {len(internet_pool)}")
    
    # Сортировка БС по пингу (сначала меньший пинг, затем большая скорость)
    # Гарантируем, что активные LTE/5G из vlessforu будут в топе
    bs_sorted = sorted(
        list(bs_pool),
        key=lambda c: (
            0 if "lte/5g" in c.lower() or "sni vk" in c.lower() or "sni x5" in c.lower() else 1,
            extract_ping(c),
            -extract_speed(c)
        )
    )
    
    # Сортировка интернет-конфигов по скорости и пингу
    internet_sorted = sorted(
        list(internet_pool),
        key=lambda c: (-extract_speed(c), extract_ping(c))
    )
    
    # =========================================================================
    # Подписка 1: Ровно 250 конфигов (20 из которых БС, 230 скоростной интернет)
    # =========================================================================
    sub_1_bs = bs_sorted[:20]
    sub_1_internet = internet_sorted[:230]
    sub_1_all = sub_1_bs + sub_1_internet
    
    sub_1_text = format_subscription(
        sub_1_all,
        "ОСТАТЬСЯ НА СВЯЗИ [250 / 20 БС] ⭐",
        "sub_250_20bs.txt",
        "250 серверов: ровно 20 для Белых Списков РФ + 230 скоростных зарубежных"
    )
    
    # =========================================================================
    # Подписка 2: BS Top Ping (БС отсортированные по наилучшему пингу)
    # =========================================================================
    bs_top_ping_configs = sorted(
        list(bs_pool),
        key=lambda c: (extract_ping(c), -extract_speed(c))
    )
    
    sub_2_text = format_subscription(
        bs_top_ping_configs[:200],  # Топ по пингу
        "ОСТАТЬСЯ НА СВЯЗИ [BS TOP PING] ⚡",
        "sub_bs_top_ping.txt",
        "Белые списки (БС) — отсортированы строго по минимальному пингу"
    )
    
    # =========================================================================
    # Подписка 3: BS Все (Все рабочие конфиги белых списков)
    # =========================================================================
    sub_3_text = format_subscription(
        bs_sorted,
        "ОСТАТЬСЯ НА СВЯЗИ [BS ВСЕ] 🛡️",
        "sub_bs_all.txt",
        "Полный пул всех рабочих конфигураций для белых списков РФ"
    )
    
    # Сохранение файлов
    files_to_save = [
        ("sub_250_20bs.txt", sub_1_text),
        ("sub_bs_top_ping.txt", sub_2_text),
        ("sub_bs_all.txt", sub_3_text),
    ]
    
    for filename, text in files_to_save:
        path = os.path.join(PROJECT_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[✓] Создан файл: {filename}")
        
        # Base64 вариант (включает метаданные для отображения имени и описания в клиентах)
        b64_content = base64.b64encode(text.encode("utf-8")).decode("ascii") + "\n"
        b64_filename = filename.replace(".txt", "_base64.txt")
        b64_path = os.path.join(PROJECT_DIR, b64_filename)
        with open(b64_path, "w", encoding="utf-8") as f:
            f.write(b64_content)
        print(f"[✓] Создан base64 файл: {b64_filename}")

    print("[SUCCESS] Все 3 подписки успешно сгенерированы!")

if __name__ == "__main__":
    generate_all_subscriptions()
