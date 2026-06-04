#!/usr/bin/env python3
"""
VLESS Config Parser & Checker for GitHub Actions
3-stage pipeline:
  Stage 1 — TCP check     (all configs, fast, 80 concurrent)
  Stage 2 — TLS check     (TCP-passing configs, 40 concurrent)
  Stage 3 — Xray real check (TLS/TCP survivors, 10 concurrent via xray binary)
Output: top 200 working configs sorted by latency.
"""

import asyncio
import base64
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone

# ─── Tunable constants ────────────────────────────────────────────────────────

MAX_OUTPUT      = 200    # maximum working configs to keep
TCP_TIMEOUT     = 5      # seconds
TLS_TIMEOUT     = 8      # seconds
XRAY_TIMEOUT    = 15     # seconds per real check
TCP_CONCURRENCY = 80
TLS_CONCURRENCY = 40
XRAY_CONCURRENCY = 10   # xray processes in parallel
FETCH_TIMEOUT   = 20     # seconds per source fetch

# Name template for each config
CONFIG_NAME = "ОСТАТЬСЯ НА СВЯЗИ 🛜"

# Test URL for Xray connectivity (Google generate_204 — always returns HTTP 204)
TEST_URL = "http://www.gstatic.com/generate_204"

# Path to xray binary (set by workflow via $XRAY_PATH env var)
XRAY_PATH = os.environ.get("XRAY_PATH", "/tmp/xray")


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class ParsedVless:
    uuid: str
    host: str
    port: int
    name: str
    raw_uri: str
    sni: Optional[str] = None
    path: Optional[str] = None
    network: Optional[str] = None
    security: Optional[str] = None
    flow: Optional[str] = None

@dataclass
class CheckedConfig:
    cfg: ParsedVless
    tcp_ok: bool = False
    tls_ok: Optional[bool] = None   # None = not checked
    xray_ok: Optional[bool] = None  # None = not checked
    latency_ms: float = 9999.0
    stage: str = "tcp"              # which stage passed: tcp / tls / xray


# ─── VLESS Parsing ─────────────────────────────────────────────────────────────

def parse_vless_uri(uri: str) -> Optional[ParsedVless]:
    uri = uri.strip()
    if not uri.startswith("vless://"):
        return None
    try:
        without_scheme = uri[len("vless://"):]
        hash_idx = without_scheme.find("#")
        name = ""
        if hash_idx >= 0:
            try:
                name = urllib.parse.unquote(without_scheme[hash_idx + 1:])
            except Exception:
                name = without_scheme[hash_idx + 1:]
            main_part = without_scheme[:hash_idx]
        else:
            main_part = without_scheme

        at_idx = main_part.find("@")
        if at_idx < 0:
            return None

        uuid = main_part[:at_idx]
        rest = main_part[at_idx + 1:]

        q_idx = rest.find("?")
        host_port = rest[:q_idx] if q_idx >= 0 else rest
        query_str = rest[q_idx + 1:] if q_idx >= 0 else ""

        if host_port.startswith("["):
            close_bracket = host_port.find("]")
            if close_bracket < 0:
                return None
            host = host_port[1:close_bracket]
            port_part = host_port[close_bracket + 1:]
            port = int(port_part[1:] if port_part.startswith(":") else port_part)
        else:
            last_colon = host_port.rfind(":")
            if last_colon < 0:
                return None
            host = host_port[:last_colon]
            port = int(host_port[last_colon + 1:])

        if not host or not (1 <= port <= 65535):
            return None
        if not uuid or len(uuid) < 10:
            return None

        params = dict(pair.split("=", 1) for pair in query_str.split("&") if "=" in pair)

        return ParsedVless(
            uuid=uuid, host=host, port=port, name=name, raw_uri=uri,
            sni=params.get("sni"),
            path=params.get("path"),
            network=params.get("type") or params.get("network"),
            security=params.get("security") or params.get("tls"),
            flow=params.get("flow"),
        )
    except Exception:
        return None


def extract_vless_from_text(text: str) -> list[ParsedVless]:
    results, seen = [], set()
    for line in re.split(r"[\r\n\s]+", text):
        line = line.strip()
        if not line.startswith("vless://"):
            continue
        parsed = parse_vless_uri(line)
        if parsed:
            key = f"{parsed.uuid}@{parsed.host}:{parsed.port}"
            if key not in seen:
                seen.add(key)
                results.append(parsed)
    return results


def try_decode_base64(text: str) -> str:
    try:
        decoded = base64.b64decode(text.strip() + "==").decode("utf-8", errors="ignore")
        if any(p in decoded for p in ("vless://", "vmess://", "trojan://")):
            return decoded
    except Exception:
        pass
    return text


# ─── Geo / Flag lookup ─────────────────────────────────────────────────────────

_geo_cache: dict[str, str] = {}


def country_code_to_flag(code: str) -> str:
    try:
        return "".join(chr(ord(c) + 127397) for c in code.upper())
    except Exception:
        return "🌐"


def get_host_flag(host: str) -> str:
    if host in _geo_cache:
        return _geo_cache[host]
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{host}?fields=countryCode",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            code = data.get("countryCode", "")
            flag = country_code_to_flag(code) if code else "🌐"
    except Exception:
        flag = "🌐"
    _geo_cache[host] = flag
    return flag


def rebuild_uri_with_name(raw_uri: str, name: str) -> str:
    hash_idx = raw_uri.find("#")
    base = raw_uri[:hash_idx] if hash_idx >= 0 else raw_uri
    return f"{base}#{urllib.parse.quote(name)}"


# ─── GitHub URL resolution ─────────────────────────────────────────────────────

def github_repo_to_raw_urls(url: str) -> list[str]:
    if "raw.githubusercontent.com" in url:
        return [url]
    if url.startswith("://github.com"):
        url = "https:" + url
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    if parsed.netloc not in ("github.com", "www.github.com"):
        return [url]

    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(path_parts) < 2:
        return []

    owner, repo = path_parts[0], path_parts[1]

    if len(path_parts) > 3 and path_parts[2] in ("blob", "raw"):
        branch = path_parts[3]
        file_path = "/".join(path_parts[4:])
        return [f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"]

    candidates = []
    for branch in ["main", "master"]:
        for f in [
            "vless.txt", "configs.txt", "config.txt", "sub.txt",
            "subscription.txt", "proxies.txt", "nodes.txt",
            "free.txt", "vpn.txt", "proxy.txt",
            "output/vless.txt", "output/configs.txt",
            "data/vless.txt", "subs/vless.txt",
        ]:
            candidates.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{f}")
    return candidates[:6]


def fetch_url(url: str, timeout: int = FETCH_TIMEOUT) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(10 * 1024 * 1024)
            return try_decode_base64(raw.decode("utf-8", errors="ignore"))
    except Exception:
        return None


def fetch_configs_from_source(url: str) -> list[ParsedVless]:
    for candidate_url in github_repo_to_raw_urls(url):
        text = fetch_url(candidate_url)
        if text:
            configs = extract_vless_from_text(text)
            if configs:
                return configs
    return []


# ─── Stage 1: TCP check (async) ───────────────────────────────────────────────

async def _tcp_check(host: str, port: int, timeout: float) -> tuple[bool, float]:
    start = asyncio.get_event_loop().time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        latency = (asyncio.get_event_loop().time() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, latency
    except Exception:
        return False, (asyncio.get_event_loop().time() - start) * 1000


async def run_tcp_stage(
    configs: list[ParsedVless],
    concurrency: int = TCP_CONCURRENCY,
    timeout: float = TCP_TIMEOUT,
) -> list[CheckedConfig]:
    sem = asyncio.Semaphore(concurrency)
    results: list[CheckedConfig] = []

    async def check_one(cfg: ParsedVless) -> None:
        async with sem:
            ok, lat = await _tcp_check(cfg.host, cfg.port, timeout)
            results.append(CheckedConfig(cfg=cfg, tcp_ok=ok, latency_ms=lat, stage="tcp"))

    await asyncio.gather(*[check_one(c) for c in configs])
    return results


# ─── Stage 2: TLS check (sync, threaded) ──────────────────────────────────────

def _tls_check(host: str, port: int, sni: Optional[str], timeout: float) -> tuple[bool, float]:
    start = time.time()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or host) as ssock:
                ssock.do_handshake()
                return True, (time.time() - start) * 1000
    except Exception:
        return False, (time.time() - start) * 1000


def run_tls_stage(
    checked: list[CheckedConfig],
    concurrency: int = TLS_CONCURRENCY,
    timeout: float = TLS_TIMEOUT,
) -> list[CheckedConfig]:
    """
    TLS check only for configs that:
    - passed TCP
    - have security=tls or security=reality, OR port 443/8443
    Configs that don't meet the TLS criteria keep their TCP result as-is.
    """
    tls_candidates = [
        c for c in checked
        if c.tcp_ok and (
            c.cfg.security in ("tls", "reality")
            or c.cfg.port in (443, 8443, 2053, 2083, 2087, 2096)
        )
    ]
    plain_passing = [
        c for c in checked
        if c.tcp_ok and c not in tls_candidates
    ]

    print(f"    TLS candidates: {len(tls_candidates)}, plain TCP-only: {len(plain_passing)}")

    tls_results: list[CheckedConfig] = []

    def check_one(c: CheckedConfig) -> CheckedConfig:
        ok, lat = _tls_check(c.cfg.host, c.cfg.port, c.cfg.sni, timeout)
        c.tls_ok = ok
        if ok:
            c.latency_ms = lat
            c.stage = "tls"
        return c

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(check_one, c): c for c in tls_candidates}
        for fut in as_completed(futures):
            tls_results.append(fut.result())

    # Merge: TLS-checked + plain TCP passing
    return tls_results + plain_passing


# ─── Stage 3: Xray real check ─────────────────────────────────────────────────

def _build_xray_config(cfg: ParsedVless, socks_port: int) -> dict:
    stream: dict = {}

    net = cfg.network or "tcp"
    stream["network"] = net

    if net == "ws":
        stream["wsSettings"] = {"path": cfg.path or "/"}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": cfg.path or ""}
    elif net in ("h2", "http"):
        stream["httpSettings"] = {"path": cfg.path or "/"}
    elif net == "xhttp":
        stream["xhttpSettings"] = {"path": cfg.path or "/", "mode": "auto"}

    if cfg.security in ("tls", "reality"):
        stream["security"] = cfg.security
        stream["tlsSettings"] = {
            "serverName": cfg.sni or cfg.host,
            "allowInsecure": True,
            "fingerprint": "chrome",
        }
    
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": socks_port,
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": cfg.host,
                        "port": cfg.port,
                        "users": [{
                            "id": cfg.uuid,
                            "flow": cfg.flow or "",
                            "encryption": "none",
                        }],
                    }]
                },
                "streamSettings": stream,
            },
            {"tag": "direct", "protocol": "freedom"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "outboundTag": "proxy", "port": "0-65535"}],
        },
    }


def _wait_port(port: int, retries: int = 25, delay: float = 0.15) -> bool:
    for _ in range(retries):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
            s.close()
            return True
        except Exception:
            time.sleep(delay)
    return False


def xray_check_one(cfg: ParsedVless, xray_bin: str, timeout: int = XRAY_TIMEOUT) -> tuple[bool, float]:
    """Start xray with this config on a random SOCKS port and fetch TEST_URL."""
    socks_port = random.randint(20000, 59999)
    xray_cfg = _build_xray_config(cfg, socks_port)

    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    try:
        json.dump(xray_cfg, tmp)
        tmp.close()
        cfg_path = tmp.name

        proc = subprocess.Popen(
            [xray_bin, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not _wait_port(socks_port):
            proc.terminate()
            return False, 9999.0

        start = time.time()
        try:
            result = subprocess.run(
                [
                    "curl", "-s", "-o", "/dev/null",
                    "-w", "%{http_code}",
                    "--proxy", f"socks5://127.0.0.1:{socks_port}",
                    "--max-time", str(timeout),
                    "--connect-timeout", "5",
                    TEST_URL,
                ],
                capture_output=True,
                timeout=timeout + 3,
                text=True,
            )
            latency = (time.time() - start) * 1000
            ok = result.returncode == 0 and result.stdout.strip() == "204"
            return ok, latency
        except Exception:
            return False, 9999.0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


def run_xray_stage(
    candidates: list[CheckedConfig],
    xray_bin: str,
    concurrency: int = XRAY_CONCURRENCY,
    timeout: int = XRAY_TIMEOUT,
) -> list[CheckedConfig]:
    """Run real connectivity test through xray binary."""
    results: list[CheckedConfig] = []

    def check_one(c: CheckedConfig) -> CheckedConfig:
        ok, lat = xray_check_one(c.cfg, xray_bin, timeout)
        c.xray_ok = ok
        if ok:
            c.latency_ms = lat
            c.stage = "xray"
        return c

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(check_one, c): c for c in candidates}
        done = 0
        for fut in as_completed(futures):
            done += 1
            if done % 20 == 0:
                print(f"    Xray: {done}/{len(candidates)}")
            results.append(fut.result())

    return results


# ─── Helpers ──────────────────────────────────────────────────────────────────

def read_sources(path: str = "source.txt") -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] {path} not found")
        sys.exit(1)
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]


def is_working(c: CheckedConfig) -> bool:
    """Config is working if it passed xray (best), or TLS, or TCP."""
    if c.xray_ok is True:
        return True
    if c.xray_ok is None and c.tls_ok is True:
        return True
    if c.xray_ok is None and c.tls_ok is None and c.tcp_ok:
        return True
    return False


# ─── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"[{ts}] VLESS Parser v3 starting...")
    print(f"  Max output: {MAX_OUTPUT} configs")

    xray_available = os.path.isfile(XRAY_PATH) and os.access(XRAY_PATH, os.X_OK)
    print(f"  Xray binary: {'✓ ' + XRAY_PATH if xray_available else '✗ not found — stage 3 skipped'}")

    sources = read_sources("source.txt")
    print(f"  Sources: {len(sources)}")

    # ── Fetch ─────────────────────────────────────────────────────────────────
    all_configs: list[ParsedVless] = []
    seen_keys: set[str] = set()

    for i, url in enumerate(sources, 1):
        fetched = fetch_configs_from_source(url)
        added = 0
        for cfg in fetched:
            key = f"{cfg.uuid}@{cfg.host}:{cfg.port}"
            if key not in seen_keys:
                seen_keys.add(key)
                all_configs.append(cfg)
                added += 1
        if added:
            print(f"  [{i}/{len(sources)}] +{added}  total={len(all_configs)}  {url[:60]}")

    print(f"\n  Total unique configs: {len(all_configs)}")
    if not all_configs:
        print("[WARN] No configs found.")
        return

    # ── Stage 1: TCP ──────────────────────────────────────────────────────────
    print(f"\n── Stage 1: TCP check (concurrency={TCP_CONCURRENCY}, timeout={TCP_TIMEOUT}s) ──")
    tcp_results = await run_tcp_stage(all_configs, TCP_CONCURRENCY, TCP_TIMEOUT)
    tcp_passing = [c for c in tcp_results if c.tcp_ok]
    print(f"  TCP passing: {len(tcp_passing)} / {len(all_configs)}")

    # ── Stage 2: TLS ──────────────────────────────────────────────────────────
    print(f"\n── Stage 2: TLS check (concurrency={TLS_CONCURRENCY}, timeout={TLS_TIMEOUT}s) ──")
    tls_results = run_tls_stage(tcp_results, TLS_CONCURRENCY, TLS_TIMEOUT)

    # Configs that passed TCP and (TLS if applicable)
    stage2_passing = [c for c in tls_results if is_working(c)]
    stage2_passing.sort(key=lambda c: c.latency_ms)
    print(f"  After stage 2: {len(stage2_passing)} working configs")

    # ── Stage 3: Xray real check ──────────────────────────────────────────────
    final_working: list[CheckedConfig]

    if xray_available:
        # Feed top 400 by latency into xray (cap to avoid spending too long)
        xray_input = stage2_passing[:400]
        print(f"\n── Stage 3: Xray real check (concurrency={XRAY_CONCURRENCY}, timeout={XRAY_TIMEOUT}s) ──")
        print(f"  Testing {len(xray_input)} candidates through xray...")
        xray_results = run_xray_stage(xray_input, XRAY_PATH, XRAY_CONCURRENCY, XRAY_TIMEOUT)
        xray_passing = [c for c in xray_results if c.xray_ok is True]
        xray_passing.sort(key=lambda c: c.latency_ms)
        print(f"  Xray confirmed: {len(xray_passing)} / {len(xray_input)}")
        final_working = xray_passing
    else:
        print("\n── Stage 3: skipped (no xray binary) ──")
        final_working = stage2_passing

    # Keep only top MAX_OUTPUT
    final_working = final_working[:MAX_OUTPUT]
    print(f"\n  Final: {len(final_working)} configs (max {MAX_OUTPUT})")

    # ── Geo lookup + build URIs ───────────────────────────────────────────────
    print(f"\n  Geo lookup for {len(final_working)} configs...")
    output_lines: list[str] = []
    for idx, c in enumerate(final_working, 1):
        if idx % 50 == 0:
            print(f"    {idx}/{len(final_working)}")
        flag = get_host_flag(c.cfg.host)
        name = f"{flag} {CONFIG_NAME}"
        output_lines.append(rebuild_uri_with_name(c.cfg.raw_uri, name))

    # ── Write files ───────────────────────────────────────────────────────────
    with open("OSTATSYA_NA_SVYAZI.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines) + "\n")

    b64 = base64.b64encode("\n".join(output_lines).encode("utf-8")).decode("ascii")
    with open("OSTATSYA_NA_SVYAZI_base64.txt", "w", encoding="utf-8") as f:
        f.write(b64 + "\n")

    stage_counts = {
        "tcp":  sum(1 for c in final_working if c.stage == "tcp"),
        "tls":  sum(1 for c in final_working if c.stage == "tls"),
        "xray": sum(1 for c in final_working if c.stage == "xray"),
    }
    stats = {
        "updated_at":    datetime.now(timezone.utc).isoformat(),
        "sources_count": len(sources),
        "total_fetched": len(all_configs),
        "tcp_passing":   len(tcp_passing),
        "tls_passing":   len([c for c in tls_results if c.tls_ok is True]),
        "xray_passing":  len([c for c in (xray_results if xray_available else []) if c.xray_ok is True]),
        "final_count":   len(final_working),
        "stage_counts":  stage_counts,
        "xray_used":     xray_available,
        "success_rate":  round(len(final_working) / len(all_configs) * 100, 1) if all_configs else 0,
    }
    with open("stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"""
  Files written:
    OSTATSYA_NA_SVYAZI.txt       — {len(final_working)} configs
    OSTATSYA_NA_SVYAZI_base64.txt — base64
    stats.json

  Stage breakdown of final {len(final_working)} configs:
    TCP only : {stage_counts['tcp']}
    TLS      : {stage_counts['tls']}
    Xray real: {stage_counts['xray']}
  Done ✓
""")


if __name__ == "__main__":
    asyncio.run(main())
