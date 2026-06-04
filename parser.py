#!/usr/bin/env python3
"""
VLESS Config Parser & Checker for GitHub Actions
Reads source.txt, fetches configs from all sources, checks TCP connectivity,
writes working configs to OSTATSYA_NA_SVYAZI.txt and base64 version.
"""

import asyncio
import base64
import re
import socket
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timezone

# ─── Constants ────────────────────────────────────────────────────────────────

TCP_TIMEOUT = 5       # seconds per connection attempt
CONCURRENCY = 80      # parallel TCP checks
FETCH_TIMEOUT = 20    # seconds for HTTP fetch
CONFIG_NAME = "ОСТАНЕТСЯ НА СВЯЗИ 🛜"

# GitHub repo URLs to auto-detect raw VLESS files
GITHUB_VLESS_PATTERNS = [
    r"vless\.txt", r"configs\.txt", r"config\.txt", r"sub\.txt",
    r"vless$", r"configs$", r"subscription", r"sub$",
    r"proxy", r"nodes", r"free", r"vpn",
]

# ─── VLESS Parsing ─────────────────────────────────────────────────────────────

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
            uuid=uuid,
            host=host,
            port=port,
            name=name,
            raw_uri=uri,
            sni=params.get("sni"),
            path=params.get("path"),
            network=params.get("type") or params.get("network"),
            security=params.get("security") or params.get("tls"),
            flow=params.get("flow"),
        )
    except Exception:
        return None


def extract_vless_from_text(text: str) -> list[ParsedVless]:
    results = []
    seen = set()
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


# ─── GitHub URL Resolution ─────────────────────────────────────────────────────

import urllib.parse


def github_repo_to_raw_urls(url: str) -> list[str]:
    """Convert a GitHub repo URL to potential raw content URLs."""
    # Already a raw URL
    if "raw.githubusercontent.com" in url:
        return [url]

    # Fix broken URLs
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
    # If it's a deep path (direct file), convert to raw
    if len(path_parts) > 3 and path_parts[2] in ("blob", "raw"):
        branch = path_parts[3]
        file_path = "/".join(path_parts[4:])
        return [f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"]

    # Try common file locations in repo
    candidates = []
    common_branches = ["main", "master"]
    common_files = [
        "vless.txt", "configs.txt", "config.txt", "sub.txt",
        "subscription.txt", "proxies.txt", "nodes.txt",
        "free.txt", "vpn.txt", "proxy.txt",
        "output/vless.txt", "output/configs.txt", "result/vless.txt",
        "data/vless.txt", "subs/vless.txt",
    ]
    for branch in common_branches:
        for f in common_files:
            candidates.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{f}")

    return candidates[:6]  # limit per repo


# ─── Fetching ──────────────────────────────────────────────────────────────────

def fetch_url(url: str, timeout: int = FETCH_TIMEOUT) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(10 * 1024 * 1024)  # 10MB limit
            text = raw.decode("utf-8", errors="ignore")
            return try_decode_base64(text)
    except Exception:
        return None


def fetch_configs_from_source(url: str) -> list[ParsedVless]:
    candidates = github_repo_to_raw_urls(url)
    for candidate_url in candidates:
        text = fetch_url(candidate_url)
        if text:
            configs = extract_vless_from_text(text)
            if configs:
                return configs
    return []


# ─── TCP Checking ──────────────────────────────────────────────────────────────

async def check_tcp(host: str, port: int, timeout: float = TCP_TIMEOUT) -> tuple[bool, float]:
    start = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        latency = asyncio.get_event_loop().time() - start
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, latency * 1000
    except Exception:
        return False, (asyncio.get_event_loop().time() - start) * 1000


async def check_batch(configs: list[ParsedVless], concurrency: int = CONCURRENCY) -> list[tuple[ParsedVless, bool, float]]:
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def check_one(cfg: ParsedVless):
        async with semaphore:
            ok, latency = await check_tcp(cfg.host, cfg.port)
            results.append((cfg, ok, latency))

    await asyncio.gather(*[check_one(c) for c in configs])
    return results


# ─── Name Building ─────────────────────────────────────────────────────────────

def rebuild_uri_with_name(raw_uri: str, name: str) -> str:
    hash_idx = raw_uri.find("#")
    base = raw_uri[:hash_idx] if hash_idx >= 0 else raw_uri
    return f"{base}#{urllib.parse.quote(name)}"


# ─── Main ──────────────────────────────────────────────────────────────────────

def read_sources(path: str = "source.txt") -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] {path} not found")
        sys.exit(1)

    urls = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


async def main():
    print(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}] VLESS Parser starting...")

    sources = read_sources("source.txt")
    print(f"  Sources loaded: {len(sources)}")

    # Fetch all configs
    all_configs: list[ParsedVless] = []
    seen_keys: set[str] = set()

    for i, source_url in enumerate(sources, 1):
        print(f"  [{i}/{len(sources)}] Fetching: {source_url[:80]}")
        fetched = fetch_configs_from_source(source_url)
        added = 0
        for cfg in fetched:
            key = f"{cfg.uuid}@{cfg.host}:{cfg.port}"
            if key not in seen_keys:
                seen_keys.add(key)
                all_configs.append(cfg)
                added += 1
        if added:
            print(f"           +{added} configs (total: {len(all_configs)})")

    print(f"\n  Total unique configs fetched: {len(all_configs)}")

    if not all_configs:
        print("[WARN] No configs found. Exiting without updating files.")
        return

    # Check TCP connectivity
    print(f"\n  Checking TCP connectivity (concurrency={CONCURRENCY}, timeout={TCP_TIMEOUT}s)...")
    check_results = await check_batch(all_configs, CONCURRENCY)

    working = [(cfg, lat) for cfg, ok, lat in check_results if ok]
    working.sort(key=lambda x: x[1])  # sort by latency ASC

    print(f"  Working: {len(working)} / {len(all_configs)}")

    # Build output URIs
    output_lines = []
    for cfg, lat in working:
        named_uri = rebuild_uri_with_name(cfg.raw_uri, CONFIG_NAME)
        output_lines.append(named_uri)

    # Write OSTATSYA_NA_SVYAZI.txt
    with open("OSTATSYA_NA_SVYAZI.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines) + "\n")

    # Write base64 version
    b64 = base64.b64encode("\n".join(output_lines).encode("utf-8")).decode("ascii")
    with open("OSTATSYA_NA_SVYAZI_base64.txt", "w", encoding="utf-8") as f:
        f.write(b64 + "\n")

    # Write stats.json
    import json
    stats = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "sources_count": len(sources),
        "total_fetched": len(all_configs),
        "working": len(working),
        "failed": len(all_configs) - len(working),
        "success_rate": round(len(working) / len(all_configs) * 100, 1) if all_configs else 0,
    }
    with open("stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"\n  Files updated:")
    print(f"    OSTATSYA_NA_SVYAZI.txt      — {len(working)} working configs")
    print(f"    OSTATSYA_NA_SVYAZI_base64.txt — base64 encoded")
    print(f"    stats.json                  — run statistics")
    print(f"\n  Done! Success rate: {stats['success_rate']}%")


if __name__ == "__main__":
    asyncio.run(main())
