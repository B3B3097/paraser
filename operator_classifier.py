#!/usr/bin/env python3
"""
operator_classifier.py — v4.0 «Siberian Pro» (июнь 2026)
Динамическая классификация конфигов по провайдерам/ASN.

- Определение ASN и ISP через ip-api.com (кэшированное)
- Группировка конфигов по операторам
- Определение российских провайдеров под ТСПУ
- Per-operator статистика для сортировки
- Экспорт группированных списков

Использование:
    from operator_classifier import (
        classify_operator, get_operator_group,
        group_by_operator, get_operator_stats,
        OPERATOR_RU_TSPU, OPERATOR_FOREIGN, OPERATOR_CLOUDFLARE,
    )
"""

import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass


# ══════════════════════════════════════════════════════════════════════════════
# Категории операторов
# ══════════════════════════════════════════════════════════════════════════════

OPERATOR_RU_TSPU = "ru_tspu"        # Российский провайдер под ТСПУ
OPERATOR_RU_CLEAN = "ru_clean"      # Российский провайдер БЕЗ ТСПУ
OPERATOR_FOREIGN = "foreign"        # Зарубежный хостинг
OPERATOR_CLOUDFLARE = "cloudflare"  # Cloudflare-транзит
OPERATOR_UNKNOWN = "unknown"        # Не определён

OPERATOR_NAMES = {
    OPERATOR_RU_TSPU:    "🇷🇺 ТСПУ",
    OPERATOR_RU_CLEAN:   "🇷🇺 Чистый",
    OPERATOR_FOREIGN:    "🌍 Иностранный",
    OPERATOR_CLOUDFLARE: "☁️ Cloudflare",
    OPERATOR_UNKNOWN:    "❓ Неизвестно",
}

# Российские ASN под ТСПУ (расширенный список)
RU_TSPU_ASNS: set[str] = {
    # Selectel
    "AS197695", "AS210079", "AS60604", "AS49505",
    # Яндекс / Яндекс.Облако
    "AS200350", "AS13238",
    # TimeWeb
    "AS9123", "AS51789",
    # Beget
    "AS198610", "AS213533",
    # Cloud.ru
    "AS208677",
    # SpaceWeb
    "AS44112",
    # FirstVDS / FirstByte / FirstDed
    "AS48642", "AS49392", "AS202984", "AS29182",
    # Majordomo
    "AS43362",
    # Qrator Labs
    "AS197068",
    # Ростелеком
    "AS12389", "AS8342", "AS9049",
    # МТС
    "AS8359", "AS31363", "AS42668",
    # Вымпелком (Билайн)
    "AS16345", "AS200350", "AS50319",
    # Мегафон
    "AS31246", "AS31257", "AS41037",
    # TTK
    "AS20485", "AS42362",
    # ER-Telecom (Дом.ru)
    "AS31363", "AS50261",
    # Transtelecom
    "AS15774",
    # РКН / ТСПУ (операторы блокировки)
    "AS39508",  # РКН
    "AS201776", # ТСПУ-инфраструктура
}

# Российские ASN, НЕ под ТСПУ (обычно мелкие дата-центры, которые ещё не заблокировали)
RU_CLEAN_ASNS: set[str] = {
    "AS56630",  # Миран
    "AS49063",  # Servercore
    "AS200068", # SberCloud
    "AS207713", # MIRHosting
    "AS21412",  # IgraNet
    "AS56679",  # DataLine
    "AS35278",  # Rostelecom (регионы с разной фильтрацией)
}

# Известные зарубежные хостинги (приоритетные)
FOREIGN_ASNS: set[str] = {
    # Hetzner
    "AS24940", "AS213230",
    # OVH
    "AS16276", "AS35540",
    # DigitalOcean
    "AS14061",
    # Vultr
    "AS20473",
    # Linode / Akamai
    "AS63949", "AS35995",
    # AWS
    "AS16509", "AS14618", "AS38895",
    # Google Cloud
    "AS15169", "AS396982",
    # Azure / Microsoft
    "AS8075", "AS12076",
    # Oracle Cloud
    "AS31898",
    # Scaleway
    "AS12876",
    # Contabo
    "AS51167",
    # NFOrce
    "AS18403",
    # BuyVM / FranTech
    "AS53667", "AS394256",
    # DediPath / Psychz
    "AS40676",
    # IONOS / 1&1
    "AS8560", "AS197180",
}

# Cloudflare ASN
CLOUDFLARE_ASNS: set[str] = {"AS13335", "AS209242", "AS395747"}


# ══════════════════════════════════════════════════════════════════════════════
# ASN-кэш (ip-api.com — быстрый, бесплатный, без ключа)
# ══════════════════════════════════════════════════════════════════════════════

_asn_cache: dict[str, dict] = {}
_asn_cache_hits = 0
_asn_cache_misses = 0


def _resolve_ip(host: str) -> Optional[str]:
    """Резолвит домен в IP, если передан домен, а не IP."""
    try:
        ipaddress.ip_address(host)  # уже IP
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def fetch_asn_info(host: str) -> Optional[dict]:
    """Получает ASN и ISP информацию для хоста через ip-api.com.

    Возвращает словарь с ключами as, org, isp, country, countryCode, query
    или None при ошибке.
    """
    global _asn_cache_hits, _asn_cache_misses

    # Проверяем кэш сначала по хосту
    if host in _asn_cache:
        _asn_cache_hits += 1
        return _asn_cache[host]

    # Резолвим IP
    ip = _resolve_ip(host)
    if not ip:
        return None

    # Проверяем кэш по IP
    if ip in _asn_cache:
        _asn_cache_hits += 1
        result = _asn_cache[ip]
        _asn_cache[host] = result
        return result

    _asn_cache_misses += 1

    # ip-api.com — бесплатно до 45 запросов/мин
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=as,org,isp,country,countryCode,query",
            headers={"User-Agent": "vless-parser/4.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())

        if data.get("status") == "fail":
            result = {
                "as": "",
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
                "country": data.get("country", ""),
                "countryCode": data.get("countryCode", ""),
                "query": ip,
            }
        else:
            result = {
                "as": data.get("as", ""),
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
                "country": data.get("country", ""),
                "countryCode": data.get("countryCode", ""),
                "query": ip,
            }

        # Кэшируем
        _asn_cache[ip] = result
        _asn_cache[host] = result
        return result
    except Exception:
        return None


@lru_cache(maxsize=65536)
def classify_operator(host: str) -> str:
    """Классифицирует хост по оператору.

    Returns:
        Одна из констант: OPERATOR_RU_TSPU, OPERATOR_RU_CLEAN,
        OPERATOR_FOREIGN, OPERATOR_CLOUDFLARE, OPERATOR_UNKNOWN
    """
    info = fetch_asn_info(host)
    if not info:
        return OPERATOR_UNKNOWN

    as_str = info.get("as", "").strip()
    country = info.get("countryCode", "").upper()
    org = info.get("org", "").lower()

    # Извлекаем ASN
    asn = ""
    if as_str:
        parts = as_str.split()
        if parts:
            asn = parts[0].strip()

    # Cloudflare
    if asn in CLOUDFLARE_ASNS or "cloudflare" in org:
        return OPERATOR_CLOUDFLARE

    # Российские провайдеры
    if country == "RU":
        if asn in RU_TSPU_ASNS:
            return OPERATOR_RU_TSPU
        if asn in RU_CLEAN_ASNS:
            return OPERATOR_RU_CLEAN
        # Если ASN не в списке, считаем подозрительным (вероятно ТСПУ)
        if asn:
            return OPERATOR_RU_TSPU
        return OPERATOR_RU_TSPU

    # Зарубежные хостинги
    if country and country != "RU":
        if asn in FOREIGN_ASNS:
            return OPERATOR_FOREIGN
        return OPERATOR_FOREIGN

    return OPERATOR_UNKNOWN


# ══════════════════════════════════════════════════════════════════════════════
# Группировка конфигов по операторам
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class OperatorGroup:
    """Группа конфигов одного оператора."""
    operator: str
    display_name: str
    configs: list = field(default_factory=list)
    count: int = 0
    avg_latency: float = 0.0
    avg_speed: float = 0.0
    cf_count: int = 0
    tls_count: int = 0


def group_by_operator(configs: list, host_attr: str = "host") -> dict[str, OperatorGroup]:
    """Группирует список конфигов по провайдерам.

    Args:
        configs: список объектов с атрибутом host
        host_attr: имя атрибута, содержащего хост

    Returns:
        dict {operator: OperatorGroup}
    """
    groups: dict[str, OperatorGroup] = {}

    for cfg in configs:
        host = getattr(cfg, host_attr, "") or getattr(cfg, "host", "")
        if not host:
            continue

        operator = classify_operator(host)
        if operator not in groups:
            groups[operator] = OperatorGroup(
                operator=operator,
                display_name=OPERATOR_NAMES.get(operator, operator),
            )
        groups[operator].configs.append(cfg)
        groups[operator].count += 1

        # Дополнительная статистика
        latency = getattr(cfg, "latency", 0) or getattr(cfg, "tcp_latency_ms", 0)
        speed = getattr(cfg, "speed_mbps", 0)
        if latency and latency < 9999:
            groups[operator].avg_latency = (
                (groups[operator].avg_latency * (groups[operator].count - 1) + latency)
                / groups[operator].count
            )
        if speed:
            groups[operator].avg_speed = (
                (groups[operator].avg_speed * (groups[operator].count - 1) + speed)
                / groups[operator].count
            )

    return groups


def get_operator_stats(configs: list) -> dict:
    """Возвращает статистику распределения конфигов по операторам."""
    groups = group_by_operator(configs)
    stats = {}
    for op, group in sorted(groups.items(), key=lambda x: -x[1].count):
        stats[op] = {
            "name": group.display_name,
            "count": group.count,
            "avg_latency_ms": round(group.avg_latency, 1),
            "avg_speed_mbps": round(group.avg_speed, 2),
        }
    return stats


# ══════════════════════════════════════════════════════════════════════════════
# Batch-классификация для пайплайна
# ══════════════════════════════════════════════════════════════════════════════

def batch_classify(hosts: list[str], max_workers: int = 10) -> dict[str, str]:
    """Параллельная классификация списка хостов.

    Returns:
        dict {host: operator}
    """
    # Сначала проверяем кэш
    result = {}
    uncached = []
    for host in hosts:
        if host in _asn_cache:
            info = _asn_cache[host]
            as_str = info.get("as", "").strip()
            country = info.get("countryCode", "").upper()
            result[host] = _classify_from_info(as_str, country, info.get("org", ""))
        else:
            uncached.append(host)

    if not uncached:
        return result

    # Параллельный резолв некэшированных
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(classify_operator, h): h for h in uncached}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                result[host] = fut.result()
            except Exception:
                result[host] = OPERATOR_UNKNOWN

    return result


def _classify_from_info(as_str: str, country: str, org: str) -> str:
    """Классифицирует на основе уже полученных данных (без запроса)."""
    org_lower = org.lower()
    asn = as_str.split()[0] if as_str else ""

    if asn in CLOUDFLARE_ASNS or "cloudflare" in org_lower:
        return OPERATOR_CLOUDFLARE
    if country == "RU":
        if asn in RU_TSPU_ASNS:
            return OPERATOR_RU_TSPU
        if asn in RU_CLEAN_ASNS:
            return OPERATOR_RU_CLEAN
        return OPERATOR_RU_TSPU if asn else OPERATOR_UNKNOWN
    if country and country != "RU":
        return OPERATOR_FOREIGN
    return OPERATOR_UNKNOWN


# ══════════════════════════════════════════════════════════════════════════════
# Экспорт группированных списков
# ══════════════════════════════════════════════════════════════════════════════

def write_operator_files(configs: list, host_attr: str = "host") -> dict[str, int]:
    """Записывает конфиги, сгруппированные по операторам, в отдельные файлы.

    Создаёт файлы вида `operator_<operator>.txt`.

    Returns:
        dict {operator: count}
    """
    groups = group_by_operator(configs, host_attr)
    counts = {}

    for op, group in sorted(groups.items(), key=lambda x: -x[1].count):
        fname = f"operator_{op}.txt"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                for cfg in group.configs:
                    uri = getattr(cfg, "raw_uri", None) or getattr(cfg, "link", str(cfg))
                    f.write(uri + "\n")
            counts[op] = group.count
        except Exception:
            pass

    return counts


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Operator Classifier — ASN/ISP классификация")
    ap.add_argument("hosts", nargs="+", help="IP-адреса или домены для проверки")
    ap.add_argument("--batch", type=int, default=0, help="Макс рабочих потоков")

    args = ap.parse_args()

    for host in args.hosts:
        op = classify_operator(host)
        info = fetch_asn_info(host)
        if info:
            as_str = info.get("as", "N/A")
            org = info.get("org", "N/A")
            country = info.get("countryCode", "??")
            print(f"{host:30s}  {op:15s}  {country:4s}  {as_str:30s}  {org}")
        else:
            print(f"{host:30s}  {op:15s}  [no data]")
