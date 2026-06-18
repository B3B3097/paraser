#!/usr/bin/env python3
"""
sni_scanner.py — сканер SNI доменов для Cloudflare-фронтов

- Проверка SNI на whitelist/blacklist ТСПУ
- Поиск рабочих Cloudflare SNI методом мульти-пробинга (TCP+TLS+HTTP)
- Сканирование списка доменов с параллельным пробингом
- Определение блокировки SNI через ТСПУ (сравнение TLS-результатов)
- Генерация SNI-кандидатов из whitelist_sni.txt
"""

import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

from cloudflare_checker import (
    CLOUDFLARE_PREFIXES,
    SAFE_FRONT_SNI,
    TPU_BLACKLIST_SNI,
    is_cf_ip,
    is_blocked_subnet,
    load_cf_prefixes,
    probe_cf_front,
    tpsu_sni_score,
)

PROJECT_DIR = Path(__file__).parent
WHITELIST_SNI_PATH = PROJECT_DIR / "whitelist_sni.txt"


# ══════════════════════════════════════════════════════════════════════════════
# Данные SNI: загрузка и кэширование
# ══════════════════════════════════════════════════════════════════════════════

_sni_whitelist_cache: set[str] = set()
_sni_whitelist_loaded = False


def load_sni_whitelist(path: Optional[Path] = None) -> int:
    """Загружает белый список SNI доменов из файла."""
    global _sni_whitelist_cache, _sni_whitelist_loaded
    if _sni_whitelist_loaded and not path:
        return len(_sni_whitelist_cache)
    fp = path or WHITELIST_SNI_PATH
    try:
        with open(fp) as f:
            for line in f:
                sni = line.strip()
                if sni:
                    _sni_whitelist_cache.add(sni)
        _sni_whitelist_loaded = True
    except FileNotFoundError:
        pass
    return len(_sni_whitelist_cache)


@lru_cache(maxsize=65536)
def is_sni_whitelisted(sni: str) -> bool:
    """Проверяет, находится ли SNI в белом списке (загруженном из whitelist_sni.txt)."""
    if not _sni_whitelist_cache:
        load_sni_whitelist()
    return sni.lower().strip() in _sni_whitelist_cache


def is_sni_blacklisted(sni: str) -> bool:
    """Проверяет, находится ли SNI в чёрном списке ТСПУ."""
    sni_lower = sni.lower().strip()
    for blocked in TPU_BLACKLIST_SNI:
        if blocked in sni_lower:
            return True
    return False


def is_sni_safe_front(sni: str) -> bool:
    """Проверяет, является ли SNI гарантированно безопасным фронтом."""
    sni_lower = sni.lower().strip()
    for safe in SAFE_FRONT_SNI:
        if safe in sni_lower:
            return True
    return False


def sni_classification(sni: str) -> str:
    """Классифицирует SNI: 'safe', 'whitelisted', 'neutral', 'blacklisted'."""
    if is_sni_safe_front(sni):
        return "safe"
    if is_sni_blacklisted(sni):
        return "blacklisted"
    if is_sni_whitelisted(sni):
        return "whitelisted"
    return "neutral"


# ══════════════════════════════════════════════════════════════════════════════
# SNI-пробинг (TCP + TLS + HTTP)
# ══════════════════════════════════════════════════════════════════════════════

_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE


@dataclass
class SNIScanResult:
    """Результат проверки SNI на одном IP."""
    sni: str
    ip: str
    port: int = 443
    tcp_ok: bool = False
    tcp_latency_ms: float = 9999.0
    tls_ok: bool = False
    tls_latency_ms: float = 9999.0
    http_code: int = 0
    http_latency_ms: float = 9999.0
    cf_ray: Optional[str] = None
    is_cf_front: bool = False
    classification: str = "neutral"
    error: Optional[str] = None
    total_latency_ms: float = 9999.0


def probe_sni(sni: str, ip: str, port: int = 443,
              timeout: float = 5.0) -> SNIScanResult:
    """Проверяет один SNI на заданном IP через TCP → TLS → HTTP."""
    result = SNIScanResult(sni=sni, ip=ip, port=port,
                           classification=sni_classification(sni))
    t0 = time.time()

    # ── TCP ──────────────────────────────────────────────────────────────
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            result.tcp_ok = True
            result.tcp_latency_ms = (time.time() - t0) * 1000
    except socket.timeout:
        result.error = "TCP timeout"
        result.total_latency_ms = (time.time() - t0) * 1000
        return result
    except OSError as e:
        result.error = f"TCP error: {e}"
        result.total_latency_ms = (time.time() - t0) * 1000
        return result

    # ── TLS ──────────────────────────────────────────────────────────────
    t1 = time.time()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with _TLS_CTX.wrap_socket(raw, server_hostname=sni) as s:
                s.do_handshake()
        result.tls_ok = True
        result.tls_latency_ms = (time.time() - t1) * 1000
    except Exception as e:
        result.error = f"TLS error: {e}"
        result.total_latency_ms = (time.time() - t0) * 1000
        return result

    # ── HTTP ─────────────────────────────────────────────────────────────
    t2 = time.time()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            f"https://{ip}:{port}/cdn-cgi/trace",
            headers={"Host": sni, "User-Agent": "Mozilla/5.0"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        result.http_code = resp.status

        body = resp.read(2048).decode("utf-8", errors="ignore")
        if any(kw in body.lower() for kw in ("colo=", "http=", "tls=", "fl=")):
            result.is_cf_front = True

        cf_ray = resp.getheader("CF-RAY") or resp.getheader("Cf-Ray")
        if cf_ray:
            result.cf_ray = cf_ray
            result.is_cf_front = True

        server = resp.getheader("Server") or ""
        if "cloudflare" in server.lower():
            result.is_cf_front = True

    except Exception:
        pass

    result.http_latency_ms = (time.time() - t2) * 1000
    result.total_latency_ms = (time.time() - t0) * 1000
    result.error = None
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Batch-сканирование
# ══════════════════════════════════════════════════════════════════════════════

def scan_sni_list(
    sni_list: list[str],
    ips: list[str],
    port: int = 443,
    timeout: float = 5.0,
    max_workers: int = 30,
) -> list[SNIScanResult]:
    """Сканирует список SNI на списке IP с параллельным пробингом.

    Args:
        sni_list: список SNI для проверки
        ips: список IP-адресов
        port: порт
        timeout: таймаут на один пробинг
        max_workers: количество параллельных потоков

    Returns:
        список SNIScanResult (каждая комбинация SNI×IP)
    """
    results: list[SNIScanResult] = []
    pairs = [(sni, ip) for sni in sni_list for ip in ips]

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(probe_sni, sni, ip, port, timeout): (sni, ip)
            for sni, ip in pairs
        }
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


def find_working_cf_snis(
    sni_candidates: list[str],
    cf_ips: list[str],
    port: int = 443,
    timeout: float = 5.0,
    max_workers: int = 30,
) -> tuple[list[SNIScanResult], dict]:
    """Ищет рабочие Cloudflare SNI-фронты из списка кандидатов.

    Returns:
        (рабочие SNI, статистика)
    """
    results = scan_sni_list(sni_candidates, cf_ips, port, timeout, max_workers)
    working = [r for r in results if r.is_cf_front]

    stats = {
        "total_scanned": len(results),
        "tcp_ok": sum(1 for r in results if r.tcp_ok),
        "tls_ok": sum(1 for r in results if r.tls_ok),
        "cf_fronts": len(working),
        "latency_avg_ms": sum(r.total_latency_ms for r in working) / max(len(working), 1),
        "safe_snis": sum(1 for r in working if r.classification == "safe"),
        "whitelisted_snis": sum(1 for r in working if r.classification == "whitelisted"),
        "neutral_snis": sum(1 for r in working if r.classification == "neutral"),
    }
    return working, stats


# ══════════════════════════════════════════════════════════════════════════════
# Обнаружение ТСПУ-блокировки по SNI
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TSPUBlockTestResult:
    """Результат теста на ТСПУ-блокировку SNI."""
    snitested: str
    cf_ip: str
    safe_sni_ok: bool = False
    safe_sni_latency_ms: float = 0
    target_sni_ok: bool = False
    target_sni_latency_ms: float = 0
    blocked: bool = False
    blocking_type: str = "none"


def detect_sni_block(sni_target: str, cf_ip: str,
                     safe_sni: str = "yandex.ru",
                     port: int = 443, timeout: float = 5.0) -> TSPUBlockTestResult:
    """Обнаруживает, блокирует ли ТСПУ заданный SNI на Cloudflare-IP.

    Метод: сравнивает TLS handshake с безопасным SNI (yandex.ru)
    и целевым SNI на одном и том же IP. Если безопасный проходит,
    а целевой — нет, это ТСПУ-блокировка по SNI.

    Args:
        sni_target: проверяемый SNI
        cf_ip: IP-адрес за Cloudflare
        safe_sni: заведомо безопасный SNI (по умолчанию yandex.ru)
        port: порт
        timeout: таймаут

    Returns:
        TSPUBlockTestResult с результатами.
    """
    result = TSPUBlockTestResult(sni_tested=sni_target, cf_ip=cf_ip)

    # Проверяем безопасный SNI
    probe_safe = probe_sni(safe_sni, cf_ip, port, timeout)
    result.safe_sni_ok = probe_safe.tls_ok
    result.safe_sni_latency_ms = probe_safe.tls_latency_ms

    # Проверяем целевой SNI
    probe_target = probe_sni(sni_target, cf_ip, port, timeout)
    result.target_sni_ok = probe_target.tls_ok
    result.target_sni_latency_ms = probe_target.tls_latency_ms

    # Анализ
    if result.safe_sni_ok and not result.target_sni_ok:
        result.blocked = True
        result.blocking_type = "TLS DPI on SNI"
    elif not result.safe_sni_ok and not result.target_sni_ok:
        result.blocked = True
        result.blocking_type = "IP block (TCP or deeper)"

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Генерация SNI-кандидатов
# ══════════════════════════════════════════════════════════════════════════════

def generate_sni_candidates(
    include_whitelist: bool = True,
    include_safe_fronts: bool = True,
    include_common_cdn: bool = True,
    max_snis: int = 500,
) -> list[str]:
    """Генерирует список SNI-кандидатов для поиска Cloudflare-фронтов.

    Приоритет: безопасные фронты → whitelist → популярные CDN-домены.
    """
    candidates: list[str] = []

    if include_safe_fronts:
        candidates.extend(SAFE_FRONT_SNI)

    if include_whitelist:
        load_sni_whitelist()
        # Берем из whitelist_sni.txt только уникальные домены второго уровня
        seen = set(candidates)
        for sni in sorted(_sni_whitelist_cache):
            if len(candidates) >= max_snis:
                break
            # Извлекаем домен второго уровня
            parts = sni.split(".")
            if len(parts) >= 2:
                domain_2nd = ".".join(parts[-2:])
                if domain_2nd not in seen:
                    candidates.append(sni)
                    seen.add(domain_2nd)
                    if sni not in seen:
                        seen.add(sni)

    if include_common_cdn and len(candidates) < max_snis:
        common_cdn = [
            "www.cloudflare.com", "cdnjs.cloudflare.com",
            "blog.cloudflare.com", "developers.cloudflare.com",
            "www.google.com", "www.microsoft.com", "www.apple.com",
            "www.amazon.com", "www.netflix.com", "www.spotify.com",
            "github.com", "gitlab.com", "bitbucket.org",
            "stackoverflow.com", "medium.com", "reddit.com",
            "wikipedia.org", "mozilla.org", "ubuntu.com",
            "python.org", "nodejs.org", "docker.com",
            "www.adobe.com", "www.oracle.com", "www.ibm.com",
            "discord.com", "slack.com", "zoom.us",
        ]
        for sni in common_cdn:
            if len(candidates) >= max_snis:
                break
            if sni not in candidates:
                candidates.append(sni)

    return candidates[:max_snis]


# ══════════════════════════════════════════════════════════════════════════════
# Утилиты
# ══════════════════════════════════════════════════════════════════════════════

def sni_stats() -> dict:
    """Возвращает статистику по SNI-базам."""
    load_sni_whitelist()
    return {
        "whitelist_total": len(_sni_whitelist_cache),
        "safe_fronts": len(SAFE_FRONT_SNI),
        "blacklisted": len(TPU_BLACKLIST_SNI),
    }


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser(description="SNI Scanner for Cloudflare fronts")
    ap.add_argument("action", nargs="?",
                    choices=["stats", "check", "scan", "detect", "candidates"],
                    default="stats")
    ap.add_argument("target", nargs="?", help="SNI для проверки")
    ap.add_argument("--ip", help="IP-адрес для проверки (default: 1.1.1.1)")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--max-workers", type=int, default=30)
    ap.add_argument("--max-snis", type=int, default=500)
    ap.add_argument("--output", help="JSON-файл для сохранения результатов")

    args = ap.parse_args()

    if args.action == "stats":
        s = sni_stats()
        print(f"Whitelist SNIs: {s['whitelist_total']:,}")
        print(f"Safe fronts:   {s['safe_fronts']}")
        print(f"Blacklisted:   {s['blacklisted']}")

    elif args.action == "check" and args.target:
        cls = sni_classification(args.target)
        safe = is_sni_safe_front(args.target)
        wl = is_sni_whitelisted(args.target)
        bl = is_sni_blacklisted(args.target)
        print(f"SNI:           {args.target}")
        print(f"Classification: {cls}")
        print(f"Safe front:    {safe}")
        print(f"Whitelisted:   {wl}")
        print(f"Blacklisted:   {bl}")

    elif args.action == "scan":
        ip = args.ip or "1.1.1.1"
        candidates = generate_sni_candidates(max_snis=args.max_snis)
        print(f"Scanning {len(candidates)} SNIs on {ip}...")
        results = scan_sni_list(candidates, [ip], args.port,
                                max_workers=args.max_workers)
        working = [r for r in results if r.is_cf_front]
        print(f"\nResults: {len(working)}/{len(results)} are CF fronts")
        for r in sorted(working, key=lambda x: x.total_latency_ms)[:20]:
            print(f"  {r.sni:40s}  {r.total_latency_ms:6.0f}ms  {r.classification}")

    elif args.action == "detect" and args.target:
        ip = args.ip or "1.1.1.1"
        r = detect_sni_block(args.target, ip, port=args.port)
        print(f"SNI: {args.target}  IP: {ip}")
        print(f"  Safe SNI OK:  {r.safe_sni_ok}  ({r.safe_sni_latency_ms:.0f}ms)")
        print(f"  Target SNI OK: {r.target_sni_ok}  ({r.target_sni_latency_ms:.0f}ms)")
        print(f"  Blocked:      {r.blocked}")
        print(f"  Type:         {r.blocking_type}")

    elif args.action == "candidates":
        candidates = generate_sni_candidates(max_snis=args.max_snis)
        if args.output:
            with open(args.output, "w") as f:
                f.write("\n".join(candidates))
            print(f"{len(candidates)} candidates saved to {args.output}")
        else:
            for sni in candidates:
                print(sni)
