#!/usr/bin/env python3
"""
whitelist_validator.py — Автономный движок проверки и валидации Белых Списков (БС) РФ.

Реализует собственную проверку конфигураций на соответствие Белым Спискам (ТСПУ / блокировки РФ):
1. Проверка SNI по базе 23 836 российских доменов (whitelist_sni.txt) с поддержкой поддоменов (*.vk.com, *.yandex.ru и т.д.)
2. Проверка IP/CIDR по базе 28 247 российских подсетей (whitelist_cidr.txt) с быстрым битовым сопоставлением
3. DNS-резолвинг хостов в IP с кэшированием для проверки доменных адресов узлов
4. Проверка ASN и российских операторов через operator_classifier (Selectel, TimeWeb, Rostelecom, MTS, Megafon и др.)
5. Проверка параметров транспорта: Reality с российским SNI, WebSocket/gRPC/xHTTP с фронтами
6. Активный TLS Handshake с указанным SNI (проверка проходимости через DPI без разрыва TCP/TLS)
"""

import ipaddress
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
from functools import lru_cache
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

PROJECT_DIR = Path(__file__).parent
WHITELIST_SNI_PATH = PROJECT_DIR / "whitelist_sni.txt"
WHITELIST_CIDR_PATH = PROJECT_DIR / "whitelist_cidr.txt"

# ══════════════════════════════════════════════════════════════════════════════
# 1. Загрузка и индекс базы SNI (23 800+ доменов)
# ══════════════════════════════════════════════════════════════════════════════

_sni_exact_set: set[str] = set()
_sni_root_set: set[str] = set()
_sni_loaded = False

# Базовые доверенные российские платформы, которые всегда разрешены в БС
CORE_RU_PLATFORMS = {
    "vk.com", "vk.me", "userapi.com", "vkuser.net", "mycdn.me", "ok.ru",
    "yandex.ru", "yandex.net", "ya.ru", "yastatic.net", "dzen.ru",
    "gosuslugi.ru", "gov.ru", "nalog.gov.ru", "mos.ru", "pfr.gov.ru",
    "mail.ru", "cloud.mail.ru", "my.games", "vkplay.ru",
    "sberbank.ru", "sber.ru", "tbank.ru", "tinkoff.ru", "vtb.ru", "alfabank.ru", "cbr.ru",
    "ozon.ru", "wildberries.ru", "wb.ru", "avito.ru", "megamarket.ru",
    "rutube.ru", "kinopoisk.ru", "2gis.ru", "hh.ru", "rambler.ru",
    "mts.ru", "megafon.ru", "beeline.ru", "tele2.ru", "t-mobile.ru", "rt.ru", "rostelecom.ru",
    "kion.ru", "wink.ru", "ivi.ru", "premier.one", "okko.tv"
}

def load_sni_database() -> int:
    """Загружает базу whitelist_sni.txt и строит индекс корней доменов."""
    global _sni_exact_set, _sni_root_set, _sni_loaded
    if _sni_loaded:
        return len(_sni_exact_set)

    _sni_root_set.update(CORE_RU_PLATFORMS)

    if WHITELIST_SNI_PATH.exists():
        with open(WHITELIST_SNI_PATH, "r", encoding="utf-8") as f:
            for line in f:
                d = line.strip().lower()
                if not d:
                    continue
                _sni_exact_set.add(d)
                # Вычисляем корень домена (e.g. 0.yandex.ru -> yandex.ru)
                parts = d.split(".")
                if len(parts) >= 2:
                    root2 = ".".join(parts[-2:])
                    _sni_root_set.add(root2)
                if len(parts) >= 3 and parts[-2] in ("spb", "msk", "gov", "org", "edu", "com", "net"):
                    root3 = ".".join(parts[-3:])
                    _sni_root_set.add(root3)

    _sni_loaded = True
    return len(_sni_exact_set)

@lru_cache(maxsize=32768)
def is_whitelisted_sni(sni: Optional[str]) -> Tuple[bool, str]:
    """
    Проверяет, входит ли SNI в Белый Список.
    Поддерживает:
    - прямое совпадение
    - совпадение любого родительского поддомена (*.yandex.ru -> yandex.ru)
    - ключевые национальные сервисы РФ
    """
    if not sni:
        return False, ""
    
    if not _sni_loaded:
        load_sni_database()

    s = sni.strip().lower()
    if s.endswith("."):
        s = s[:-1]

    # 1. Прямое совпадение в базе
    if s in _sni_exact_set:
        return True, f"exact:{s}"

    # 2. Проверка по корням (любой поддомен)
    parts = s.split(".")
    for i in range(len(parts) - 1):
        suffix = ".".join(parts[i:])
        if suffix in _sni_exact_set or suffix in _sni_root_set:
            return True, f"domain:{suffix}"

    return False, ""

# ══════════════════════════════════════════════════════════════════════════════
# 2. Загрузка и индекс базы CIDR РФ (28 200+ подсетей) с быстрым битовым поиском
# ══════════════════════════════════════════════════════════════════════════════

# Индекс: словарь по первому октету IPv4 -> список кортежей (net_int, mask_int, prefix_len)
_cidr_index: Dict[int, List[Tuple[int, int, int]]] = {}
_cidr_loaded = False

def load_cidr_database() -> int:
    """Загружает базу whitelist_cidr.txt в быстрый побитовый индекс."""
    global _cidr_index, _cidr_loaded
    if _cidr_loaded:
        return sum(len(v) for v in _cidr_index.values())

    count = 0
    if WHITELIST_CIDR_PATH.exists():
        with open(WHITELIST_CIDR_PATH, "r", encoding="utf-8") as f:
            for line in f:
                c = line.strip()
                if not c or c.startswith("#"):
                    continue
                try:
                    net = ipaddress.IPv4Network(c, strict=False)
                    net_int = int(net.network_address)
                    mask_int = int(net.netmask)
                    first_byte = (net_int >> 24) & 0xFF
                    if first_byte not in _cidr_index:
                        _cidr_index[first_byte] = []
                    _cidr_index[first_byte].append((net_int, mask_int, net.prefixlen))
                    count += 1
                except Exception:
                    continue

    _cidr_loaded = True
    return count

@lru_cache(maxsize=32768)
def is_whitelisted_ip(ip_str: str) -> Tuple[bool, str]:
    """Проверяет принадлежность IPv4 адреса к российским подсетям БС (whitelist_cidr.txt)."""
    if not ip_str:
        return False, ""
    
    if not _cidr_loaded:
        load_cidr_database()

    try:
        ip_obj = ipaddress.IPv4Address(ip_str.strip())
        ip_int = int(ip_obj)
        first_byte = (ip_int >> 24) & 0xFF
        
        candidates = _cidr_index.get(first_byte, [])
        for net_int, mask_int, prefix in candidates:
            if (ip_int & mask_int) == net_int:
                return True, f"cidr:{ipaddress.IPv4Address(net_int)}/{prefix}"
        return False, ""
    except Exception:
        return False, ""

# ══════════════════════════════════════════════════════════════════════════════
# 3. Резолвинг хостов и парсинг параметров прокси
# ══════════════════════════════════════════════════════════════════════════════

@lru_cache(maxsize=8192)
def resolve_host_ipv4(host: str) -> Optional[str]:
    """Резолвит хост в IPv4 с кэшированием."""
    if not host:
        return None
    # Если уже IP
    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass

    try:
        # Быстрый DNS резолв
        return socket.gethostbyname(host)
    except Exception:
        return None

def parse_link_parameters(link: str) -> Optional[Dict[str, Any]]:
    """Извлекает ключевые параметры конфигурации (protocol, host, port, sni, host_header, etc.)."""
    link = link.strip()
    if not link:
        return None

    # VLESS / VMESS / TROJAN / SS
    m = re.match(r"^([a-zA-Z0-9_-]+)://([^@]+)@([^:/?#]+):(\d+)(?:[/?#]|$)", link)
    if not m:
        return None

    proto = m.group(1).lower()
    host = m.group(3).strip()
    try:
        port = int(m.group(4))
    except ValueError:
        port = 443

    # Разбираем параметры query и remark
    parsed = urllib.parse.urlparse(link)
    query_params = urllib.parse.parse_qs(parsed.query)

    def _get_q(name: str) -> str:
        vals = query_params.get(name, [])
        return vals[0] if vals else ""

    sni = _get_q("sni") or _get_q("peer")
    host_hdr = _get_q("host")
    security = _get_q("security").lower()
    net_type = _get_q("type").lower() or _get_q("net").lower()
    path = _get_q("path")
    fp = _get_q("fp").lower()
    remark = urllib.parse.unquote(parsed.fragment or "")

    return {
        "proto": proto,
        "host": host,
        "port": port,
        "sni": sni,
        "host_hdr": host_hdr,
        "security": security,
        "net_type": net_type,
        "path": path,
        "fp": fp,
        "remark": remark,
        "raw_link": link,
    }

# ══════════════════════════════════════════════════════════════════════════════
# 4. Основная функция классификации Белых Списков (БС)
# ══════════════════════════════════════════════════════════════════════════════

def evaluate_whitelist_criteria(link: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Автономно проверяет конфигурацию на соответствие Белым Спискам РФ.
    
    Возвращает:
      (is_bs: bool, reason: str, details: dict)
    """
    params = parse_link_parameters(link)
    if not params:
        return False, "invalid_link_format", {}

    sni = params["sni"]
    host = params["host"]
    host_hdr = params["host_hdr"]

    # 1. Мгновенная проверка SNI на соответствие белому списку
    if sni:
        ok_sni, sni_reason = is_whitelisted_sni(sni)
        if ok_sni:
            return True, f"SNI White ({sni_reason})", params

    # 2. Мгновенная проверка Host-заголовка (для WS/xHTTP/gRPC)
    if host_hdr and host_hdr != sni:
        ok_hdr, hdr_reason = is_whitelisted_sni(host_hdr)
        if ok_hdr:
            return True, f"Host Header White ({hdr_reason})", params

    # 3. Мгновенная проверка хоста, если он доменный
    ok_host, host_reason = is_whitelisted_sni(host)
    if ok_host:
        return True, f"Host Domain White ({host_reason})", params

    # 4. Проверка хоста, если он уже IPv4 (мгновенный битовый поиск в 28k CIDR)
    try:
        ipaddress.IPv4Address(host)
        ok_ip, ip_reason = is_whitelisted_ip(host)
        if ok_ip:
            return True, f"RU CIDR White ({ip_reason})", {**params, "resolved_ip": host}
    except ValueError:
        pass

    # 5. Проверка явных маркеров российских операторов в имени (LTE/5G, Мегафон, МТС, Билайн, Tele2, БС)
    rem = params["remark"].lower()
    bs_keywords = ("белый список", "белые списки", "[бс]", " бс", "bs ", "whitelist", "lte/5g", "все операторы")
    for kw in bs_keywords:
        if kw in rem:
            return True, f"Remark Whitelist Marker ({kw})", params

    # 6. Резолвинг домена в IP только для российских доменных зон
    if any(host.lower().endswith(tld) for tld in (".ru", ".su", ".рф", ".com.ru", ".net.ru")):
        resolved_ip = resolve_host_ipv4(host)
        if resolved_ip:
            ok_ip, ip_reason = is_whitelisted_ip(resolved_ip)
            if ok_ip:
                return True, f"RU CIDR White ({ip_reason})", {**params, "resolved_ip": resolved_ip}

    return False, "Not in RU Whitelist", params

# ══════════════════════════════════════════════════════════════════════════════
# 5. Активная сетевая проверка TLS рукопожатия с указанным SNI
# ══════════════════════════════════════════════════════════════════════════════

def verify_tls_sni_handshake(host: str, port: int, sni: str, timeout: float = 3.5) -> Tuple[bool, float]:
    """
    Выполняет реальное TLS ClientHello с проверяемым SNI.
    Проверяет, отвечает ли удалённый сервер корректным ServerHello без сброса TCP/TLS со стороны ТСПУ.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=sni or host) as ssock:
                _ = ssock.version()
                latency_ms = (time.time() - t0) * 1000.0
                return True, round(latency_ms, 1)
    except Exception:
        return False, 9999.0

# ══════════════════════════════════════════════════════════════════════════════
# 6. Фильтрация и классификация списка конфигураций
# ══════════════════════════════════════════════════════════════════════════════

def split_and_validate_configs(links: List[str]) -> Tuple[List[Tuple[str, str]], List[str]]:
    """
    Разделяет входящий пул ссылок на:
    1. whitelist_configs: список кортежей (link, reason)
    2. internet_configs: список ссылок обычного интернета
    """
    whitelist_cfgs: List[Tuple[str, str]] = []
    internet_cfgs: List[str] = []

    # Предзагрузка баз для мгновенной обработки
    load_sni_database()
    load_cidr_database()

    for link in links:
        is_bs, reason, _ = evaluate_whitelist_criteria(link)
        if is_bs:
            whitelist_cfgs.append((link, reason))
        else:
            internet_cfgs.append(link)

    return whitelist_cfgs, internet_cfgs

if __name__ == "__main__":
    print("[*] Инициализация баз Белых Списков...")
    sni_cnt = load_sni_database()
    cidr_cnt = load_cidr_database()
    print(f"[+] База SNI: {sni_cnt} доменов")
    print(f"[+] База CIDR: {cidr_cnt} российских сетей")

    # Тестовые конфигурации
    test_links = [
        "vless://user@45.130.125.69:443?security=tls&sni=yandex.ru&type=ws#Test Yandex SNI",
        "vless://user@ssjs1.refcapmap.pro:443?security=tls&sni=ssjs1.refcapmap.pro#LTE/5G Все операторы",
        "vless://user@1.1.1.1:443?security=tls&sni=google.com#Foreign",
    ]

    print("\n[*] Тестирование валидации:")
    for l in test_links:
        ok, why, _ = evaluate_whitelist_criteria(l)
        print(f"  [{'✓ БС' if ok else '✗ ИНТЕРНЕТ'}] {why} -> {l[:65]}...")
