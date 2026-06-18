#!/usr/bin/env python3
"""
cf_ip_utils.py — утилиты для работы с Cloudflare IP-диапазонами

- Загрузка и кэширование префиксов из ip_list.txt
- Проверка принадлежности IP к Cloudflare (is_cf_ip)
- Поиск IP в диапазонах Cloudflare (find_cf_ips_in_subnet)
- Динамическое обновление списка с официального API Cloudflare
- Генерация CIDR из двухоктетных префиксов
- Быстрый lookup по двухоктетному префиксу
"""

import ipaddress
import json
import time
from functools import lru_cache
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    requests = None

from cloudflare_checker import CLOUDFLARE_PREFIXES, load_cf_prefixes, is_cf_ip, get_cf_prefix

# ══════════════════════════════════════════════════════════════════════════════
# Константы
# ══════════════════════════════════════════════════════════════════════════════

CLOUDFLARE_IP_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_API_URL = "https://api.cloudflare.com/client/v4/ips"

PROJECT_DIR = Path(__file__).parent
IP_LIST_PATH = PROJECT_DIR.parent / "misc" / "ip_list.txt"

# ══════════════════════════════════════════════════════════════════════════════
# CIDR-генерация из двухоктетных префиксов
# ══════════════════════════════════════════════════════════════════════════════

@lru_cache(maxsize=1)
def generate_cf_cidrs() -> list[str]:
    """Генерирует /16 CIDR из двухоктетных префиксов Cloudflare.

    Например, префикс "172.64" → "172.64.0.0/16".
    """
    if not CLOUDFLARE_PREFIXES:
        load_cf_prefixes()
    return sorted(f"{prefix}.0.0/16" for prefix in CLOUDFLARE_PREFIXES)


def prefix_to_cidr(prefix: str) -> str:
    """Конвертирует двухоктетный префикс в /16 CIDR."""
    return f"{prefix}.0.0/16"


def cidr_to_prefix(cidr: str) -> str:
    """Извлекает двухоктетный префикс из CIDR."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        addr = net.network_address
        return f"{addr.packed[0]}.{addr.packed[1]}"
    except ValueError:
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# Поиск IP в Cloudflare-диапазонах
# ══════════════════════════════════════════════════════════════════════════════

def find_cf_ips_in_subnet(cidr: str, max_ips: int = 256) -> list[str]:
    """Находит Cloudflare-IP внутри заданной подсети.

    Args:
        cidr: подсеть в формате CIDR, например "172.64.0.0/24"
        max_ips: максимальное число возвращаемых IP

    Returns:
        список IP-адресов в подсети, принадлежащих Cloudflare
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []

    cf_ips = []
    for addr in net.hosts():
        if len(cf_ips) >= max_ips:
            break
        ip_str = str(addr)
        if is_cf_ip(ip_str):
            cf_ips.append(ip_str)
    return cf_ips


def filter_cf_ips(ip_list: list[str]) -> tuple[list[str], list[str]]:
    """Разделяет список IP на Cloudflare и не-Cloudflare.

    Returns:
        (cf_ips, non_cf_ips) — два списка
    """
    cf = []
    non_cf = []
    for ip in ip_list:
        if is_cf_ip(ip.strip()):
            cf.append(ip.strip())
        else:
            non_cf.append(ip.strip())
    return cf, non_cf


# ══════════════════════════════════════════════════════════════════════════════
# Динамическое обновление списка Cloudflare IP
# ══════════════════════════════════════════════════════════════════════════════

def fetch_cf_ips_from_api() -> list[str]:
    """Получает актуальный список IPv4 CIDR Cloudflare через публичный API.

    Возвращает список CIDR строк, например ['173.245.48.0/20', ...].
    """
    if requests is None:
        raise ImportError("requests не установлен. Установите: pip install requests")

    cidrs = []
    # Пробуем оба источника
    for url in (CLOUDFLARE_IP_URL, CLOUDFLARE_API_URL):
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            if "api.cloudflare.com" in url:
                data = resp.json()
                if data.get("success"):
                    ipv4_cidrs = data.get("result", {}).get("ipv4_cidrs", [])
                    cidrs = ipv4_cidrs
                    break
            else:
                cidrs = [line.strip() for line in resp.text.splitlines()
                         if line.strip() and "/" in line]
                break
        except Exception:
            continue
    return cidrs


def update_ip_list_from_api(path: Optional[Path] = None) -> int:
    """Обновляет ip_list.txt данными с официального API Cloudflare.

    Скачивает IPv4 CIDR, извлекает двухоктетные префиксы и сохраняет.

    Returns:
        число новых префиксов
    """
    cidrs = fetch_cf_ips_from_api()
    if not cidrs:
        return 0

    prefixes = set()
    for cidr in cidrs:
        prefix = cidr_to_prefix(cidr)
        if prefix:
            prefixes.add(prefix)

    fp = path or IP_LIST_PATH
    old_count = 0
    if fp.exists():
        old_count = len(set(fp.read_text().splitlines()))

    with open(fp, "w") as f:
        for prefix in sorted(prefixes, key=lambda p: tuple(map(int, p.split(".")))):
            f.write(prefix + "\n")

    # Перезагружаем префиксы
    load_cf_prefixes(fp)

    new_count = len(prefixes)
    return new_count - old_count


# ══════════════════════════════════════════════════════════════════════════════
# Расширенные проверки
# ══════════════════════════════════════════════════════════════════════════════

def ip_range_info(ip_str: str) -> dict:
    """Возвращает информацию об IP: Cloudflare-статус, префикс, CIDR."""
    result = {
        "ip": ip_str,
        "is_cloudflare": False,
        "prefix": None,
        "cidr": None,
        "is_blocked_subnet": False,
    }
    try:
        addr = ipaddress.ip_address(ip_str.split("/")[0])
    except ValueError:
        result["error"] = f"Invalid IP: {ip_str}"
        return result

    result["is_cloudflare"] = is_cf_ip(ip_str)
    if result["is_cloudflare"]:
        prefix = get_cf_prefix(ip_str)
        result["prefix"] = prefix
        result["cidr"] = f"{prefix}.0.0/16"

    from cloudflare_checker import is_blocked_subnet
    result["is_blocked_subnet"] = is_blocked_subnet(ip_str)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Статистика
# ══════════════════════════════════════════════════════════════════════════════

def cf_prefix_stats() -> dict:
    """Возвращает статистику по загруженным префиксам Cloudflare."""
    if not CLOUDFLARE_PREFIXES:
        load_cf_prefixes()
    prefixes = sorted(CLOUDFLARE_PREFIXES,
                      key=lambda p: tuple(map(int, p.split("."))))
    return {
        "total_prefixes": len(prefixes),
        "total_ips_covered": len(prefixes) * 65536,  # каждый /16 = 65536 IP
        "first_prefix": prefixes[0] if prefixes else None,
        "last_prefix": prefixes[-1] if prefixes else None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Cloudflare IP Utilities")
    ap.add_argument("action", nargs="?",
                    choices=["stats", "check", "filter", "update", "cidrs"],
                    default="stats",
                    help="Действие (default: stats)")
    ap.add_argument("target", nargs="?", help="IP-адрес или CIDR для проверки")
    ap.add_argument("--from-file", help="Файл со списком IP (для фильтрации)")
    ap.add_argument("--output", help="Выходной файл (default: stdout)")

    args = ap.parse_args()

    if args.action == "stats":
        stats = cf_prefix_stats()
        print(f"Cloudflare IP Prefixes: {stats['total_prefixes']}")
        print(f"Covered IPs: {stats['total_ips_covered']:,}")
        print(f"Range: {stats['first_prefix']} → {stats['last_prefix']}")

    elif args.action == "check" and args.target:
        info = ip_range_info(args.target)
        for k, v in info.items():
            print(f"  {k}: {v}")

    elif args.action == "filter":
        source = args.from_file
        if not source:
            print("Укажите --from-file")
            exit(1)
        with open(source) as f:
            ips = [l.strip() for l in f if l.strip()]
        cf, non_cf = filter_cf_ips(ips)
        print(f"Cloudflare: {len(cf)}  |  Not CF: {len(non_cf)}")
        if args.output:
            with open(args.output, "w") as f:
                f.write("\n".join(cf))
            print(f"Saved CF IPs to {args.output}")

    elif args.action == "update":
        added = update_ip_list_from_api()
        print(f"Updated: {added:+d} new prefixes")

    elif args.action == "cidrs":
        cidrs = generate_cf_cidrs()
        output = "\n".join(cidrs)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"{len(cidrs)} CIDRs saved to {args.output}")
        else:
            print(output)
