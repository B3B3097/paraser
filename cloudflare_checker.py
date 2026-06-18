#!/usr/bin/env python3
"""
Cloudflare Checker — v3.0 «Siberian» (июнь 2026)
Расширенный блок проверки Cloudflare для paraser с учётом
свежих данных об ограничениях ТСПУ/РКН (5–15 июня 2026).

Использование:
    from cloudflare_checker import (
        is_cf_ip, is_blocked_subnet, patch_fingerprint,
        tpsu_link_score, tpsu_config_score,
        check_cf_headers, probe_cf_front,
        CLOUDFLARE_PREFIXES,
        TPSU_BLOCKED_ASNS, TPSU_SUSPICIOUS_CIDRS,
        TPSU_BAD_FP, TPSU_GOOD_FP,
    )
"""

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
# Cloudflare IP-префиксы (загружаются из ip_list.txt при старте)
# Формат: двухоктетные префиксы, разделённые пробелами (напр. "172.64 104.16")
# ══════════════════════════════════════════════════════════════════════════════

PROJECT_DIR = Path(__file__).parent
IP_LIST_PATH = Path("/home/nebula/misc/ip_list.txt")
CLOUDFLARE_PREFIXES: set[str] = set()
_cf_prefixes_loaded = False


def load_cf_prefixes(path: Optional[Path] = None) -> int:
    """Загружает двухоктетные префиксы Cloudflare IP из файла."""
    global CLOUDFLARE_PREFIXES, _cf_prefixes_loaded
    if _cf_prefixes_loaded and not path:
        return len(CLOUDFLARE_PREFIXES)
    fp = path or IP_LIST_PATH
    try:
        with open(fp) as f:
            for line in f:
                prefix = line.strip()
                if prefix:
                    CLOUDFLARE_PREFIXES.add(prefix)
        _cf_prefixes_loaded = True
    except FileNotFoundError:
        pass
    return len(CLOUDFLARE_PREFIXES)


@lru_cache(maxsize=65536)
def is_cf_ip(ip_str: str) -> bool:
    """Проверяет, принадлежит ли IP к известным Cloudflare-диапазонам.

    Использует кэш для быстрой проверки ранее виденных IP.
    Принимает как одиночный IP, так и CIDR.
    """
    if not CLOUDFLARE_PREFIXES:
        load_cf_prefixes()
    if not CLOUDFLARE_PREFIXES:
        return False
    try:
        addr = ipaddress.ip_address(ip_str.split("/")[0])
    except ValueError:
        return False
    # Быстрая проверка по первому и второму октету
    octet_key = f"{addr.packed[0]}.{addr.packed[1]}"
    return octet_key in CLOUDFLARE_PREFIXES


def get_cf_prefix(ip_str: str) -> Optional[str]:
    """Возвращает двухоктетный префикс Cloudflare для IP, если IP — Cloudflare."""
    try:
        addr = ipaddress.ip_address(ip_str.split("/")[0])
    except ValueError:
        return None
    octet_key = f"{addr.packed[0]}.{addr.packed[1]}"
    return octet_key if octet_key in CLOUDFLARE_PREFIXES else None


# ══════════════════════════════════════════════════════════════════════════════
# ТСПУ-константы «Siberian» (обновлено 15 июня 2026)
# ══════════════════════════════════════════════════════════════════════════════

# ─── ASN провайдеров, попавших под ТСПУ-фильтрацию (июнь 2026) ──────────────

TPSU_BLOCKED_ASNS: set[str] = {
    # ── Оригинальные (были до июня 2026) ──
    "AS197695",   # Selectel (основной AS)
    "AS47764",    # VK / Mail.ru (частично под фильтрацией)
    "AS210079",   # Selectel (доп.)
    "AS60604",    # Selectel (доп.)
    "AS200350",   # Яндекс.Облако
    "AS13238",    # Яндекс

    # ── НОВЫЕ (июнь 2026, затронуты волной с 5 июня) ──
    "AS9123",     # TimeWeb — JSC TIMEWEB (основной AS)
    "AS51789",    # TimewebCloud — облачный AS TimeWeb
    "AS198610",   # Beget (основной AS)
    "AS213533",   # Beget (доп.)
    "AS208677",   # Cloud.ru — Cloud Technologies LLC
    "AS44112",    # SpaceWeb
    "AS48642",    # FirstVDS
    "AS49392",    # FirstByte (FirstVDS группа)
    "AS202984",   # FirstDed (FirstVDS группа)
    "AS43362",    # Majordomo (частично затронут)
    "AS197068",   # Qrator Labs (частично затронут)

    # ── Провайдеры, сообщавшие о сбоях косвенно ──
    "AS29182",    # FirstByte / IHC
    "AS49505",    # Selectel Moscow
}


# ─── CIDR-диапазоны, помеченные как подозрительные ──────────────────────────

TPSU_SUSPICIOUS_CIDRS: list[str] = [
    # Selectel
    "5.8.0.0/16", "5.44.0.0/15", "31.186.96.0/20",
    "45.87.244.0/24", "62.109.0.0/16", "62.113.32.0/19",
    "77.91.64.0/18", "77.220.192.0/19", "78.24.0.0/15",
    "80.66.64.0/18", "80.78.240.0/20", "81.176.0.0/15",
    "82.202.128.0/18", "85.119.144.0/20", "87.236.0.0/15",
    "87.249.0.0/19", "89.111.32.0/19", "89.223.0.0/18",
    "91.239.0.0/16", "92.53.96.0/19", "93.191.0.0/19",
    "94.250.128.0/17", "95.131.0.0/18", "95.142.32.0/19",
    "95.213.0.0/16", "109.234.160.0/19", "109.248.128.0/18",
    "128.204.0.0/18", "141.8.128.0/18", "176.113.80.0/20",
    "178.162.128.0/18", "185.6.24.0/22", "185.30.176.0/22",
    "185.203.240.0/24", "188.124.32.0/19", "188.130.128.0/17",
    "193.23.76.0/22", "193.33.140.0/23", "193.36.177.0/24",
    "193.109.78.0/23", "194.33.8.0/22", "194.67.16.0/20",
    "195.3.240.0/22", "195.24.80.0/21",
    # Yandex.Cloud
    "84.201.128.0/18", "84.252.128.0/18", "130.193.32.0/18",
    "130.193.96.0/19", "213.180.192.0/19",
    # TimeWeb
    "5.8.0.0/24", "5.101.152.0/22", "5.167.0.0/16",
    "31.31.192.0/19", "31.31.224.0/20", "37.140.192.0/18",
    "62.113.32.0/19", "77.222.32.0/19", "78.24.216.0/21",
    "79.143.16.0/20", "82.146.32.0/18", "85.119.149.0/24",
    "92.53.96.0/19", "141.8.192.0/18",
    # Beget
    "5.101.152.0/24", "31.31.192.0/22", "45.130.41.0/24",
    "87.236.16.0/21", "185.50.25.0/24", "185.50.26.0/24",
    # Cloud.ru
    "45.12.0.0/16", "45.91.100.0/24", "91.221.116.0/23",
    # SpaceWeb
    "77.222.40.0/21", "77.222.56.0/22", "185.71.67.0/24",
    # FirstVDS
    "80.87.192.0/18", "88.87.64.0/19", "195.24.80.0/21",
    "195.24.90.0/24",
]


# ─── Fingerprint-ы (TLS-отпечатки) ───────────────────────────────────────────

TPSU_BAD_FP: set[str] = {
    "chrome",       # Google Chrome
    "chrome106",    # Chrome 106
    "chrome_auto",  # Chrome (авто)
    "chrome110",    # Chrome 110+
    "safari",       # Apple Safari
    "safari_auto",
    "ios",          # Apple iOS
    "ios_auto",
    "random",       # Random (используется в старых VLESS)
    "randomized",   # Рандомизированный
    "auto",         # Авто
    "none",         # Не указан
    "",             # Пустой
    "default",      # По умолчанию
}

TPSU_GOOD_FP: list[str] = [
    "firefox",      # Mozilla Firefox — наиболее безопасный
    "edge",         # Microsoft Edge
    "android",      # Android OkHttp
    "360",          # 360 Browser
    "qq",           # QQ Browser
]

# Дополнительные безопасные fingerprint-ы (июнь 2026)
TPSU_SAFE_FP_EXPERIMENTAL: list[str] = [
    "cnsa",         # CNSA 1.3 Suite (крипто-комплаенс) — помог многим с 9 июня
    "opera",        # Opera Browser
    "brave",        # Brave Browser
    "vivaldi",      # Vivaldi Browser
    "duckduckgo",   # DuckDuckGo Browser
]


# ─── SNI-константы для проверок ──────────────────────────────────────────────

# SNI, гарантированно проходящие ТСПУ (белый список)
# Эти домены используются как "фронты" в REALITY
SAFE_FRONT_SNI: list[str] = [
    "yandex.ru", "ya.ru", "vk.com", "ok.ru",
    "sberbank.ru", "gosuslugi.ru", "mos.ru",
    "mail.ru", "rambler.ru", "ria.ru",
    "rbc.ru", "kremlin.ru", "government.ru",
    "1tv.ru", "ntv.ru", "tass.ru", "gazeta.ru",
    "avito.ru", "wildberries.ru", "ozon.ru",
    "lenta.ru", "vedomosti.ru", "kommersant.ru",
    "habr.com", "habrahabr.ru",
]

# SNI, которые триггерят ТСПУ (чёрный список) — осторожно с этими
TPU_BLACKLIST_SNI: list[str] = [
    "cloudflare.com", "cloudflare.net", "cloudflare-dns.com",
    "vpn.com", "vpn.net", "proxy.com", "proxies.com",
    "trojan.com", "vless.com", "vmess.com",
    "shadowsocks.org", "torproject.org",
    "signal.org", "telegram.org", "v2fly.org", "xtls.github.io",
    "speed.cloudflare.com", "cp.cloudflare.com",
]


# ══════════════════════════════════════════════════════════════════════════════
# ТСПУ-модель «Siberian» — функции оценки
# ══════════════════════════════════════════════════════════════════════════════

def is_blocked_subnet(ip_str: str) -> bool:
    """Проверяет, попадает ли IP в подозрительные CIDR ТСПУ."""
    try:
        addr = ipaddress.ip_address(ip_str.split("/")[0])
    except ValueError:
        return False
    for cidr in TPSU_SUSPICIOUS_CIDRS:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def patch_fingerprint(fp: Optional[str]) -> str:
    """Заменяет подозрительный TLS-отпечаток на безопасный (firefox).

    Если fp отсутствует, None, или входит в TPSU_BAD_FP — возвращает 'firefox'.
    Иначе возвращает исходный fp.
    """
    if not fp or fp.lower().strip() in TPSU_BAD_FP:
        return "firefox"
    return fp.strip()


def tpsu_fp_score(fp: Optional[str]) -> int:
    """Оценивает fingerprint: 0 = безопасный, 1 = неизвестный, 2 = опасный."""
    if not fp:
        return 2
    fp_lower = fp.lower().strip()
    if fp_lower in TPSU_BAD_FP:
        return 2
    if fp_lower in (g.lower() for g in TPSU_GOOD_FP):
        return 0
    if fp_lower in (g.lower() for g in TPSU_SAFE_FP_EXPERIMENTAL):
        return 0
    return 1  # неизвестный fp


def tpsu_sni_score(sni: Optional[str]) -> int:
    """Оценивает SNI: 0 = безопасный (wlist), 1 = нейтральный, 2 = опасный (blist)."""
    if not sni:
        return 1
    sni_lower = sni.lower().strip()
    for blocked in TPU_BLACKLIST_SNI:
        if blocked in sni_lower:
            return 2
    for safe in SAFE_FRONT_SNI:
        if safe in sni_lower:
            return 0
    return 1


def tpsu_config_score(
    fp: Optional[str] = None,
    sni: Optional[str] = None,
    ip_in_blocked_subnet: bool = False,
    is_cf: Optional[bool] = None,
) -> int:
    """Комплексная оценка конфигурации по ТСПУ-модели «Siberian».

    Параметры модели (AND-логика):
      - Сигнал 1: подсеть сервера (blocked subnet)  → вес 2
      - Сигнал 2: TLS-fingerprint клиента            → вес 3
      - Сигнал 3: SNI-домен                          → вес 1
      - Бонус: Cloudflare-транзит снижает риск        → -1

    Возвращает целое число:
        0–1  = конфиг безопасен
        2–3  = средний риск (требует патча fp)
        4–6  = высокий риск (подсеть заблокирована + плохой fp)
        7+   = критический риск (все три сигнала)
    """
    score = 0
    fp_s = tpsu_fp_score(fp)
    sni_s = tpsu_sni_score(sni)

    if ip_in_blocked_subnet:
        score += 2
    score += fp_s * 3 if fp_s == 2 else fp_s * 2
    score += sni_s

    # Cloudflare-транзит: если IP = Cloudflare, риск блокировки по подсети ниже
    if is_cf is True and ip_in_blocked_subnet:
        score -= 1
    elif is_cf is True:
        score -= 1  # Cloudflare IP вообще снижает риск

    if score < 0:
        score = 0
    return score


def tpsu_link_score(link: str) -> int:
    """Оценивает VLESS/VMess/Trojan ссылку по ТСПУ-модели.

    Извлекает параметры fp и sni из URL.
    """
    from urllib.parse import parse_qs, urlparse
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    fp = (params.get("fp", [None])[0] or
          params.get("fingerprint", [None])[0])
    sni = params.get("sni", [None])[0]
    host = parsed.hostname or ""
    return tpsu_config_score(fp=fp, sni=sni,
                             ip_in_blocked_subnet=is_blocked_subnet(host),
                             is_cf=is_cf_ip(host))


# ══════════════════════════════════════════════════════════════════════════════
# Cloudflare-специфичные проверки (TCP + TLS + HTTP пробинг)
# ══════════════════════════════════════════════════════════════════════════════

_CF_CERT_SNI_CACHE: dict[str, bool] = {}
_CF_HEADER_CACHE: dict[str, bool] = {}

# Контексты TLS для проверок
_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE


def _tls_handshake(ip: str, port: int, sni: str, timeout: float = 4.0) -> tuple[bool, float]:
    """Выполняет TLS handshake к IP:port с указанным SNI.

    Возвращает (успех, задержка в мс).
    """
    t0 = time.time()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with _TLS_CTX.wrap_socket(raw, server_hostname=sni) as s:
                s.do_handshake()
                cert = s.getpeercert()
                if cert and sni.lower() in str(cert.get("subjectAltName", [])).lower():
                    return True, (time.time() - t0) * 1000
                return True, (time.time() - t0) * 1000
    except Exception:
        return False, (time.time() - t0) * 1000


def check_cf_headers(ip: str, port: int = 443, sni: str = "cloudflare.com",
                     timeout: float = 5.0) -> dict:
    """Проверяет HTTP-ответ на наличие Cloudflare-заголовков (cf-ray, server: cloudflare).

    Возвращает словарь с ключами:
        is_cf: bool        — IP за Cloudflare
        cf_ray: Optional[str] — Ray ID (если есть)
        server: Optional[str]  — заголовок Server
        latency_ms: float
        sni_used: str
    """
    import urllib.request
    import ssl as ssl_mod

    result = {"is_cf": False, "cf_ray": None, "server": None,
              "latency_ms": 0.0, "sni_used": sni}

    t0 = time.time()
    ctx = ssl_mod.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl_mod.CERT_NONE

    try:
        req = urllib.request.Request(
            f"https://{ip}:{port}/cdn-cgi/trace",
            headers={"Host": sni, "User-Agent": "Mozilla/5.0"},
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        result["latency_ms"] = (time.time() - t0) * 1000
        body = resp.read(2048).decode("utf-8", errors="ignore")

        # Проверяем /cdn-cgi/trace — этот эндпоинт есть только за Cloudflare
        if any(kw in body.lower() for kw in ("colo=", "http=", "tls=", "fl=", "uag=")):
            result["is_cf"] = True

        cf_ray = resp.getheader("CF-RAY") or resp.getheader("Cf-Ray")
        if cf_ray:
            result["cf_ray"] = cf_ray
            result["is_cf"] = True

        server = resp.getheader("Server") or ""
        if "cloudflare" in server.lower():
            result["server"] = server
            result["is_cf"] = True

    except Exception:
        result["latency_ms"] = (time.time() - t0) * 1000
    return result


@dataclass
class CFProbeResult:
    """Результат комплексного пробинга Cloudflare-фронта."""
    ip: str
    port: int = 443
    tcp_ok: bool = False
    tcp_latency_ms: float = 9999.0
    sni_tested: str = ""
    tls_ok: bool = False
    tls_latency_ms: float = 9999.0
    http_cf_check: dict = field(default_factory=dict)
    is_cf: bool = False
    cf_ray: Optional[str] = None
    total_latency_ms: float = 9999.0


def probe_cf_front(ip: str, port: int = 443,
                   sni_candidates: Optional[list[str]] = None,
                   timeout: float = 5.0) -> CFProbeResult:
    """Полный цикл проверки IP: TCP → TLS (с несколькими SNI) → HTTP Cloudflare-заголовки.

    Args:
        ip: IP-адрес для проверки
        port: порт (по умолчанию 443)
        sni_candidates: список SNI для пробинга. Если None, используется
                       ['cloudflare.com', 'speed.cloudflare.com', 'cdnjs.cloudflare.com']
        timeout: таймаут на каждую стадию

    Returns:
        CFProbeResult с полной диагностикой.
    """
    if sni_candidates is None:
        sni_candidates = [
            "cloudflare.com",
            "speed.cloudflare.com",
            "cdnjs.cloudflare.com",
            "blog.cloudflare.com",
            "developers.cloudflare.com",
        ]

    result = CFProbeResult(ip=ip, port=port)

    # ── Stage 1: TCP ──────────────────────────────────────────────────────
    t0 = time.time()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            result.tcp_ok = True
            result.tcp_latency_ms = (time.time() - t0) * 1000
    except Exception:
        result.total_latency_ms = (time.time() - t0) * 1000
        return result

    if not result.tcp_ok:
        return result

    # ── Stage 2: TLS handshake ─────────────────────────────────────────────
    # Пробуем несколько SNI — какой-то может быть заблокирован
    for sni in sni_candidates:
        ok, ms = _tls_handshake(ip, port, sni, timeout=timeout/2)
        if ok:
            result.tls_ok = True
            result.sni_tested = sni
            result.tls_latency_ms = ms
            break

    if not result.tls_ok:
        result.total_latency_ms = result.tcp_latency_ms + (timeout * 500)
        return result

    # ── Stage 3: HTTP Cloudflare check ─────────────────────────────────────
    http_check = check_cf_headers(ip, port, result.sni_tested, timeout=timeout/2)
    result.http_cf_check = http_check
    result.is_cf = http_check["is_cf"]
    result.cf_ray = http_check["cf_ray"]
    result.total_latency_ms = (
        result.tcp_latency_ms + result.tls_latency_ms + http_check["latency_ms"]
    )

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Batch-проверка (используется в пайплайнах)
# ══════════════════════════════════════════════════════════════════════════════

def batch_cf_check(ips: list[str], port: int = 443,
                   timeout: float = 5.0,
                   max_workers: int = 20) -> list[CFProbeResult]:
    """Параллельная проверка списка IP на принадлежность к Cloudflare-фронтам."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: list[CFProbeResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe_cf_front, ip, port, timeout=timeout): ip
                   for ip in ips}
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


# ══════════════════════════════════════════════════════════════════════════════
# Автозагрузка при импорте
# ══════════════════════════════════════════════════════════════════════════════

load_cf_prefixes()
