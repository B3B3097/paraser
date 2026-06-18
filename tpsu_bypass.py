#!/usr/bin/env python3
"""
tpsu_bypass.py — v4.0 «Siberian Pro» (июнь 2026)
Стратегии обхода ТСПУ-блокировок: multi-fp, SNI rotation, bypass ranking.

Основано на актуальных данных о блокировках (июнь 2026):
- ТСПУ блокирует по трём сигналам: подсеть + fp + параллельные SNI
- SNI-spoofing (wrong_seq, fragment) — основной метод обхода
- Multi-fingerprint тестирование: firefox, edge, android, cnsa, qq
- Стратегии ротации SNI из whitelist_sni.txt + SAFE_FRONT_SNI

Использование:
    from tpsu_bypass import (
        test_fingerprints, recommend_bypass,
        rank_configs, SNI_ROTATION_POOL,
        bypass_strategy_score, APPLY_STRATEGIES,
    )

"""

from dataclasses import dataclass, field
from typing import Optional

# ─── Импорт модулей v3.0 ────────────────────────────────────────────────────
try:
    from cloudflare_checker import (
        TPSU_BAD_FP, TPSU_GOOD_FP, TPSU_SAFE_FP_EXPERIMENTAL,
        SAFE_FRONT_SNI, TPU_BLACKLIST_SNI, CLOUDFLARE_PREFIXES,
        is_cf_ip, is_blocked_subnet, patch_fingerprint,
    )
    _MODULES_LOADED = True
except ImportError:
    _MODULES_LOADED = False
    TPSU_BAD_FP = set()
    TPSU_GOOD_FP = []
    TPSU_SAFE_FP_EXPERIMENTAL = []
    SAFE_FRONT_SNI = []

# ─── Импорт классификатора ──────────────────────────────────────────────────
try:
    from operator_classifier import (
        classify_operator, fetch_asn_info,
        OPERATOR_RU_TSPU, OPERATOR_FOREIGN, OPERATOR_CLOUDFLARE,
    )
    _OP_CLASSIFIER_LOADED = True
except ImportError:
    _OP_CLASSIFIER_LOADED = False
    OPERATOR_RU_TSPU = "ru_tspu"
    OPERATOR_FOREIGN = "foreign"
    OPERATOR_CLOUDFLARE = "cloudflare"


# ══════════════════════════════════════════════════════════════════════════════
# Bypass-стратегии
# ══════════════════════════════════════════════════════════════════════════════

# Приоритетные fingerprint-ы для тестирования (от лучшего к худшему)
# firefox — наиболее безопасный (проверено)
# cnsa — CNSA 1.3, помог многим с 9 июня 2026
# edge — Microsoft Edge, стабильный
# android — Android OkHttp, хорош для мобильных
# qq — QQ Browser, редко блокируется
FP_PRIORITY = ["firefox", "cnsa", "edge", "android", "qq", "360"]

# SNI, точно работающие как front-ы (белый список)
# Эти домены используются REALITY/XTLS как cover
SNI_ROTATION_POOL: list[str] = [
    # TOP-3: точно работают (российские гиганты)
    "yandex.ru", "vk.com", "sberbank.ru",
    # TOP-6: популярные, низкий риск
    "ok.ru", "mail.ru", "gosuslugi.ru",
    # Резерв
    "ya.ru", "mos.ru", "rambler.ru", "ria.ru",
    "rbc.ru", "kremlin.ru", "avito.ru",
    "wildberries.ru", "ozon.ru", "lenta.ru",
    "habr.com", "tass.ru", "1tv.ru",
    # Международные CDN (часто заворачиваются через CF)
    "www.google.com", "www.microsoft.com",
    "github.com", "stackoverflow.com",
]

# Стратегии обхода в порядке предпочтения
# Каждая: (имя, описание, приоритет)
BYPASS_STRATEGIES = [
    ("direct_tls",       "Прямой TLS (firefox, доверенный SNI)",         0),
    ("fp_firefox",       "Firefox fingerprint",                          1),
    ("fp_cnsa",          "CNSA 1.3 Suite fingerprint",                   1),
    ("fp_edge",          "Edge fingerprint",                             2),
    ("fp_android",       "Android OkHttp fingerprint",                   2),
    ("sni_rotation",     "Ротация SNI из пула безопасных",               3),
    ("cf_transit",       "Cloudflare-транзит (CF IP)",                   3),
    ("ws_transport",     "WebSocket транспорт",                          4),
    ("grpc_transport",   "gRPC транспорт",                               4),
    ("splithttp",        "SplitHTTP (xhttp) транспорт",                  4),
    ("reality",          "REALITY v2 со сменным server_name",            5),
]


@dataclass
class BypassSuggestion:
    """Рекомендация по обходу для одного конфига."""
    host: str
    port: int
    operator: str = "unknown"
    best_fp: str = "firefox"
    best_sni: str = "yandex.ru"
    strategy: str = "direct_tls"
    strategy_priority: int = 0
    needs_fp_patch: bool = False
    needs_sni_rotation: bool = False
    needs_cf_transit: bool = False
    needs_ws: bool = False
    score: int = 0  # 0 = лучший
    safe_score: int = 0  # ТСПУ-оценка (чем меньше, тем безопаснее)


# ══════════════════════════════════════════════════════════════════════════════
# Multi-fingerprint тестирование
# ══════════════════════════════════════════════════════════════════════════════

def _check_fp(fp: str) -> int:
    """Оценивает fingerprint: 0=безопасный, 1=нейтральный, 2=опасный."""
    if not fp:
        return 2
    fp_lower = fp.lower().strip()
    if fp_lower in TPSU_BAD_FP:
        return 2
    if fp_lower in (g.lower() for g in TPSU_GOOD_FP):
        return 0
    if fp_lower in (g.lower() for g in TPSU_SAFE_FP_EXPERIMENTAL):
        return 0
    return 1


def test_fingerprints(fp_candidates: Optional[list[str]] = None) -> list[str]:
    """Возвращает список fingerprint-ов для тестирования.

    Args:
        fp_candidates: опциональный список. Если None — возвращает приоритетный.

    Returns:
        Список fp в порядке приоритета.
    """
    return fp_candidates or FP_PRIORITY


def recommend_bypass(
    host: str,
    port: int = 443,
    current_fp: Optional[str] = None,
    current_sni: Optional[str] = None,
    current_network: Optional[str] = None,
    current_security: Optional[str] = None,
) -> BypassSuggestion:
    """Определяет оптимальную стратегию обхода для конфига.

    Анализирует:
    - Какой fingerprint использовать (firefox / cnsa / edge / android)
    - Какой SNI подставить (из ротационного пула)
    - Нужен ли Cloudflare-транзит
    - Нужен ли WebSocket/gRPC/SplitHTTP

    Returns:
        BypassSuggestion с рекомендациями.
    """
    suggestion = BypassSuggestion(host=host, port=port)

    # ── 1. Классификация оператора ──────────────────────────────────────────
    if _OP_CLASSIFIER_LOADED:
        suggestion.operator = classify_operator(host)
    else:
        suggestion.operator = OPERATOR_FOREIGN

    # ── 2. Оценка текущего fingerprint ──────────────────────────────────────
    fp_score = _check_fp(current_fp) if current_fp else 2
    suggestion.needs_fp_patch = fp_score >= 1

    if fp_score >= 1:
        # Выбираем лучший fp по приоритету
        suggestion.best_fp = test_fingerprints()[0]
        suggestion.strategy = "fp_firefox"
        suggestion.strategy_priority = 1
    else:
        suggestion.best_fp = current_fp or "firefox"

    # ── 3. Оценка SNI ───────────────────────────────────────────────────────
    if current_sni:
        sni_lower = current_sni.lower().strip()
        # Проверяем, не в чёрном ли списке
        for blocked in SAFE_FRONT_SNI:
            if blocked in sni_lower:
                suggestion.best_sni = current_sni
                suggestion.needs_sni_rotation = False
                break
            for blocked_sni in TPU_BLACKLIST_SNI:
                if blocked_sni in sni_lower:
                    suggestion.needs_sni_rotation = True
                    break
        else:
            # Нейтральный SNI — возможно, стоит ротировать
            suggestion.needs_sni_rotation = True
    else:
        suggestion.needs_sni_rotation = True

    if suggestion.needs_sni_rotation:
        suggestion.best_sni = SNI_ROTATION_POOL[0]

    # ── 4. Стратегия на основе оператора ────────────────────────────────────
    if suggestion.operator == OPERATOR_RU_TSPU:
        # Российский провайдер под ТСПУ — нужны меры
        suggestion.strategy = "sni_rotation"
        suggestion.strategy_priority = 3
        suggestion.needs_fp_patch = True
        suggestion.best_fp = "firefox"
        suggestion.score += 2

        # Если ещё и плохой fp — поднимаем приоритет
        if fp_score >= 1:
            suggestion.strategy = "fp_firefox"
            suggestion.strategy_priority = 1
            suggestion.score += 1

    elif suggestion.operator == OPERATOR_CLOUDFLARE:
        # Cloudflare — уже за CDN, риска меньше
        suggestion.strategy = "cf_transit"
        suggestion.strategy_priority = 3
        suggestion.needs_cf_transit = True
        suggestion.score -= 1

    elif suggestion.operator == OPERATOR_FOREIGN:
        # Иностранный хостинг — минимальные меры
        if fp_score >= 1:
            suggestion.best_fp = "firefox"
            suggestion.needs_fp_patch = True
            suggestion.strategy = "fp_firefox"
            suggestion.strategy_priority = 1
            suggestion.score += 1
        else:
            suggestion.strategy = "direct_tls"
            suggestion.strategy_priority = 0
            suggestion.score = 0

    # ── 5. Транспорт ────────────────────────────────────────────────────────
    # Если текущий transport — ws/grpc/splithttp, он уже безопасен
    if current_network in ("ws", "grpc", "splithttp", "xhttp", "h2", "httpupgrade"):
        suggestion.score -= 1  # бонус за нестандартный транспорт
    elif current_network == "tcp" and current_security != "reality":
        # Обычный TCP без REALITY — уязвим, предлагаем ws
        if suggestion.strategy_priority >= 3:
            suggestion.needs_ws = True
            suggestion.score += 1

    # ── 6. Итоговая оценка ──────────────────────────────────────────────────
    suggestion.safe_score = suggestion.score

    return suggestion


# ══════════════════════════════════════════════════════════════════════════════
# Ранжирование конфигов по bypass-стратегиям
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RankedConfig:
    """Конфиг с результатами bypass-анализа."""
    host: str
    port: int
    operator: str
    operator_display: str
    strategy: str
    strategy_priority: int
    safe_score: int
    needs_fp_patch: bool
    needs_sni_rotation: bool
    recommended_fp: str
    recommended_sni: str
    needs_ws: bool
    needs_cf_transit: bool
    raw_link: str = ""
    speed_mbps: float = 0.0
    latency_ms: float = 0.0


def rank_configs(configs: list, speed_key: str = "speed_mbps",
                 latency_key: str = "latency") -> tuple[list[RankedConfig], dict]:
    """Ранжирует конфиги: анализирует bypass и сортирует по безопасности.

    Args:
        configs: список объектов с атрибутами host, port и опционально fp/sni/network
        speed_key: атрибут скорости
        latency_key: атрибут задержки

    Returns:
        (ранжированные конфиги, статистика)
    """
    ranked: list[RankedConfig] = []
    stats = {"foreign": 0, "ru_tspu": 0, "cloudflare": 0,
             "needs_fp_patch": 0, "needs_sni_rotation": 0,
             "needs_ws": 0, "needs_cf": 0}

    for cfg in configs:
        host = getattr(cfg, "host", "") or ""
        port = getattr(cfg, "port", 443)
        fp = getattr(cfg, "fp", None)
        sni = getattr(cfg, "sni", None)
        network = getattr(cfg, "network", None)
        security = getattr(cfg, "security", None)
        raw = getattr(cfg, "raw_uri", "") or ""
        speed = getattr(cfg, speed_key, 0)
        latency = getattr(cfg, latency_key, 9999)

        bypass = recommend_bypass(host, port, fp, sni, network, security)

        operator_display = bypass.operator
        try:
            from operator_classifier import OPERATOR_NAMES
            operator_display = OPERATOR_NAMES.get(bypass.operator, bypass.operator)
        except ImportError:
            pass

        ranked.append(RankedConfig(
            host=host, port=port,
            operator=bypass.operator,
            operator_display=operator_display,
            strategy=bypass.strategy,
            strategy_priority=bypass.strategy_priority,
            safe_score=bypass.safe_score,
            needs_fp_patch=bypass.needs_fp_patch,
            needs_sni_rotation=bypass.needs_sni_rotation,
            recommended_fp=bypass.best_fp,
            recommended_sni=bypass.best_sni,
            needs_ws=bypass.needs_ws,
            needs_cf_transit=bypass.needs_cf_transit,
            raw_link=raw,
            speed_mbps=speed,
            latency_ms=latency,
        ))

        # Статистика
        if bypass.operator == OPERATOR_FOREIGN:
            stats["foreign"] += 1
        elif bypass.operator == OPERATOR_RU_TSPU:
            stats["ru_tspu"] += 1
        elif bypass.operator == OPERATOR_CLOUDFLARE:
            stats["cloudflare"] += 1
        if bypass.needs_fp_patch:
            stats["needs_fp_patch"] += 1
        if bypass.needs_sni_rotation:
            stats["needs_sni_rotation"] += 1
        if bypass.needs_ws:
            stats["needs_ws"] += 1
        if bypass.needs_cf_transit:
            stats["needs_cf"] += 1

    # Сортировка: сначала лучшие (safe_score ASC), потом скорость DESC
    ranked.sort(key=lambda r: (r.safe_score, -r.speed_mbps, r.latency_ms))

    return ranked, stats


# ══════════════════════════════════════════════════════════════════════════════
# Stripped down string-based bypass score (for checker.py)
# ══════════════════════════════════════════════════════════════════════════════

def bypass_strategy_score(host: str, fp: Optional[str] = None,
                          sni: Optional[str] = None,
                          network: Optional[str] = None) -> int:
    """Быстрая оценка конфига по bypass-стратегии.

    Returns:
        0-100: чем меньше, тем лучше (безопаснее, быстрее)
    """
    score = 0

    # Оператор (30 баллов)
    if _OP_CLASSIFIER_LOADED:
        op = classify_operator(host)
        if op == OPERATOR_FOREIGN:
            score += 0
        elif op == OPERATOR_CLOUDFLARE:
            score += 5
        elif op == OPERATOR_RU_TSPU:
            score += 30
        else:
            score += 15
    else:
        score += 5

    # Fingerprint (30 баллов)
    fp_score = _check_fp(fp)
    score += fp_score * 15

    # SNI (20 баллов)
    if sni:
        sni_lower = sni.lower().strip()
        for safe in SAFE_FRONT_SNI:
            if safe in sni_lower:
                break
        else:
            score += 10  # нейтральный или плохой SNI
    else:
        score += 5

    # Транспорт (20 баллов)
    if network in ("ws", "grpc", "splithttp", "xhttp", "httpupgrade"):
        score -= 5  # бонус за нестандартный транспорт
    elif network in ("h2", "http"):
        score += 0
    else:
        score += 10

    return max(0, min(100, score))


# ══════════════════════════════════════════════════════════════════════════════
# Применение bypass-стратегий к конфигам (для parser.py)
# ══════════════════════════════════════════════════════════════════════════════

def APPLY_STRATEGIES(fp: Optional[str], sni: Optional[str],
                     security: Optional[str] = None) -> tuple[str, str]:
    """Применяет стратегии обхода: патчит fp и SNI.

    Returns:
        (patched_fp, patched_sni)
    """
    # Fingerprint
    if not fp or fp.lower().strip() in TPSU_BAD_FP:
        new_fp = "firefox"
    elif fp.lower().strip() in [g.lower() for g in TPSU_GOOD_FP]:
        new_fp = fp.strip()
    elif fp.lower().strip() in [g.lower() for g in TPSU_SAFE_FP_EXPERIMENTAL]:
        new_fp = fp.strip()
    else:
        new_fp = "firefox"

    # SNI
    new_sni = sni
    if sni:
        sni_lower = sni.lower().strip()
        # SNI в чёрном списке → заменяем
        for blocked in TPU_BLACKLIST_SNI:
            if blocked in sni_lower:
                new_sni = SNI_ROTATION_POOL[0]
                break

    return new_fp, new_sni


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="TPSU Bypass Strategy Analyzer")
    ap.add_argument("hosts", nargs="+", help="Хосты для анализа")
    ap.add_argument("--fp", help="Текущий fingerprint", default=None)
    ap.add_argument("--sni", help="Текущий SNI", default=None)
    ap.add_argument("--network", help="Транспорт (tcp/ws/grpc)", default=None)

    args = ap.parse_args()

    for host in args.hosts:
        bypass = recommend_bypass(
            host, 443, args.fp, args.sni, args.network
        )
        print(f"\n{'='*60}")
        print(f"Host:     {host}:{bypass.port}")
        print(f"Operator: {bypass.operator} ({bypass.strategy})")
        print(f"Best FP:  {bypass.best_fp}  (needs_patch={bypass.needs_fp_patch})")
        print(f"Best SNI: {bypass.best_sni}  (needs_rotation={bypass.needs_sni_rotation})")
        print(f"Safe:     {bypass.strategy}")
        print(f"Score:    {bypass.safe_score} (0=best)")

        score = bypass_strategy_score(host, args.fp, args.sni, args.network)
        print(f"BS Score: {score}/100")
