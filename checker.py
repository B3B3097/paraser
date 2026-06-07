#!/usr/bin/env python3
import base64
import html
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
import tarfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit
from urllib.request import Request, urlopen
import socket

import requests

from config import INTERNET_SUBS_POOL, WHITELISTED_SUBS_POOL, CONCURRENT_THREADS_CHECK_DEFAULT, INTERNET_CFGS_COUNT, WHITELISTED_CFGS_COUNT, MAX_LINKS_TO_CHECK_INTERNET, MAX_LINKS_TO_CHECK_WHITELIST

TEST_CONNECT_TIMEOUT = 2
TEST_READ_TIMEOUT = 4
TEST_URL = "https://speed.cloudflare.com/__down?bytes=204800"
SOCKS_PORT_MIN = 20000
CONCURRENT_DEFAULT = CONCURRENT_THREADS_CHECK_DEFAULT
MIN_XRAY_START_TIMEOUT = 1.0

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
XRAY_BIN_DIR = os.path.join(PROJECT_DIR, "xray_bin")

GH_TOKEN = os.environ.get("GITHUB_TOKEN", "")
_GH_HEADERS = {"User-Agent": "vless-checker/2.0"}
if GH_TOKEN:
    _GH_HEADERS["Authorization"] = f"Bearer {GH_TOKEN}"

def get_xray_download_url() -> str:
    os_type = platform.system().lower()
    arch = platform.machine().lower()
    if os_type == "darwin": os_name = "macos"
    elif os_type == "windows": os_name = "windows"
    else: os_name = "linux"
    if arch in ("amd64", "x86_64"): arch_name = "64"
    elif arch in ("arm64", "aarch64"): arch_name = "arm64-v8a"
    else: arch_name = "32"
    api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    req = Request(api_url, headers={"User-Agent": "v2ray-downloader"})
    try:
        with urlopen(req, timeout=10) as r:
            release_data = json.loads(r.read().decode())
        target_asset = f"Xray-{os_name}-{arch_name}".lower()
        print(f"[*] Ищем релиз: {target_asset}")
        for asset in release_data.get("assets", []):
            name = asset.get("name", "").lower()
            if target_asset in name and (name.endswith(".zip") or name.endswith(".gz")):
                return asset["browser_download_url"]
    except Exception as e:
        raise RuntimeError(f"Не удалось получить данные о релизах Xray: {e}")
    raise RuntimeError(f"Не найдена сборка Xray для вашей системы: {os_name} ({arch_name})")

def setup_xray_bin() -> str:
    os_ext = ".exe" if sys.platform == "win32" else ""
    xray_path = os.path.join(XRAY_BIN_DIR, f"xray{os_ext}")
    if os.path.exists(xray_path):
        return xray_path
    print("[*] Ядро Xray не найдено локально. Запуск автоматической загрузки...")
    os.makedirs(XRAY_BIN_DIR, exist_ok=True)
    download_url = get_xray_download_url()
    print(f"[+] Скачивание архива: {download_url}")
    tmp_file = os.path.join(XRAY_BIN_DIR, "xray_archive.tmp")
    req = Request(download_url, headers={"User-Agent": "v2ray-downloader"})
    try:
        with urlopen(req, timeout=30) as response, open(tmp_file, "wb") as out_file:
            shutil.copyfileobj(response, out_file)
        print("[*] Распаковка ядра...")
        if download_url.endswith(".zip"):
            with zipfile.ZipFile(tmp_file, 'r') as zip_ref: zip_ref.extractall(XRAY_BIN_DIR)
        elif download_url.endswith((".tar.gz", ".tgz")):
            with tarfile.open(tmp_file, "r:gz") as tar_ref: tar_ref.extractall(XRAY_BIN_DIR)
        if sys.platform != "win32" and os.path.exists(xray_path):
            os.chmod(xray_path, 0o755)
        print("[+] Ядро Xray успешно установлено локально!")
        return xray_path
    finally:
        if os.path.exists(tmp_file): os.remove(tmp_file)

def _json_query_value(value: str) -> dict | None:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None

def _decode_base64_text(value: str) -> str:
    value = value.strip()
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value).decode("utf-8", errors="replace")

def _build_stream_settings(query: dict) -> dict:
    network = query.get("type", "tcp")
    security = query.get("security", "none")
    stream_settings = {"network": network}
    if security != "none":
        stream_settings["security"] = security
    _add_transport_settings(stream_settings, query)
    _add_security_settings(stream_settings, query)
    return stream_settings

def _add_transport_settings(stream_settings: dict, query: dict) -> None:
    network = stream_settings["network"]
    path = query.get("path")
    host = query.get("host")
    if network == "ws":
        ws_settings = {}
        if path: ws_settings["path"] = path
        if host: ws_settings["headers"] = {"Host": host}
        if ws_settings: stream_settings["wsSettings"] = ws_settings
    elif network in ("http", "h2"):
        http_settings = {}
        if path: http_settings["path"] = path
        if host: http_settings["host"] = [host]
        if http_settings: stream_settings["httpSettings"] = http_settings
    elif network == "grpc":
        grpc_settings = {}
        service_name = query.get("serviceName") or path
        if service_name: grpc_settings["serviceName"] = service_name.lstrip("/")
        if query.get("authority"): grpc_settings["authority"] = query["authority"]
        if grpc_settings: stream_settings["grpcSettings"] = grpc_settings
    elif network == "xhttp":
        xhttp_settings = {}
        if host: xhttp_settings["host"] = host
        if path: xhttp_settings["path"] = path
        if query.get("mode"): xhttp_settings["mode"] = query["mode"]
        if query.get("extra"):
            extra = _json_query_value(query["extra"])
            if extra is not None: xhttp_settings["extra"] = extra
        if query.get("downloadSettings"):
            dl = _json_query_value(query["downloadSettings"])
            if dl is not None: xhttp_settings["downloadSettings"] = dl
        if xhttp_settings: stream_settings["xhttpSettings"] = xhttp_settings
    elif network in ("tcp", "raw"):
        header_type = query.get("headerType")
        if header_type: stream_settings["tcpSettings"] = {"header": {"type": header_type}}
    elif network in ("kcp", "mkcp"):
        kcp_settings = {}
        if query.get("seed"): kcp_settings["seed"] = query["seed"]
        if query.get("headerType"): kcp_settings["header"] = {"type": query["headerType"]}
        if kcp_settings: stream_settings["kcpSettings"] = kcp_settings
    elif network == "quic":
        quic_settings = {}
        if query.get("quicSecurity"): quic_settings["security"] = query["quicSecurity"]
        if query.get("key"): quic_settings["key"] = query["key"]
        if query.get("headerType"): quic_settings["header"] = {"type": query["headerType"]}
        if quic_settings: stream_settings["quicSettings"] = quic_settings
    elif network == "httpupgrade":
        httpupgrade_settings = {}
        if host: httpupgrade_settings["host"] = host
        if path: httpupgrade_settings["path"] = path
        if httpupgrade_settings: stream_settings["httpupgradeSettings"] = httpupgrade_settings

def _add_security_settings(stream_settings: dict, query: dict) -> None:
    security = stream_settings.get("security")
    if security == "reality":
        reality_settings = {}
        mapping = {"sni": "serverName", "fp": "fingerprint", "pbk": "publicKey", "sid": "shortId", "spx": "spiderX"}
        for source, target in mapping.items():
            if query.get(source): reality_settings[target] = query[source]
        if reality_settings: stream_settings["realitySettings"] = reality_settings
    elif security == "tls":
        tls_settings = {}
        if query.get("sni"): tls_settings["serverName"] = query["sni"]
        if query.get("fp"): tls_settings["fingerprint"] = query["fp"]
        if query.get("alpn"): tls_settings["alpn"] = [item for item in query["alpn"].split(",") if item]
        if query.get("allowInsecure"): tls_settings["allowInsecure"] = query["allowInsecure"].lower() == "true"
        if tls_settings: stream_settings["tlsSettings"] = tls_settings

def _parse_vless_link(link: str) -> tuple[str, dict] | None:
    try:
        parsed = urlsplit(link)
        port = parsed.port
    except ValueError:
        return None
    if not parsed.username or not parsed.hostname or port is None:
        return None
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    remark = unquote(parsed.fragment) if parsed.fragment else "Untitled"
    user = {"id": unquote(parsed.username), "encryption": query.get("encryption", "none")}
    if query.get("flow"): user["flow"] = query["flow"]
    outbound = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": parsed.hostname, "port": port, "users": [user]}]},
        "streamSettings": _build_stream_settings(query),
    }
    return remark, outbound

def _parse_trojan_link(link: str) -> tuple[str, dict] | None:
    try:
        parsed = urlsplit(link)
        port = parsed.port
    except ValueError:
        return None
    if not parsed.username or not parsed.hostname or port is None:
        return None
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    remark = unquote(parsed.fragment) if parsed.fragment else "Untitled"
    outbound = {
        "protocol": "trojan",
        "settings": {"servers": [{"address": parsed.hostname, "port": port, "password": unquote(parsed.username)}]},
        "streamSettings": _build_stream_settings(query),
    }
    return remark, outbound

def _parse_shadowsocks_link(link: str) -> tuple[str, dict] | None:
    try:
        parsed = urlsplit(link)
        port = parsed.port
    except ValueError:
        return None
    if not parsed.hostname or port is None:
        return None
    user_info = unquote(parsed.username or "")
    if ":" not in user_info:
        try: user_info = _decode_base64_text(user_info)
        except Exception: return None
    if ":" not in user_info:
        return None
    method, password = user_info.split(":", 1)
    remark = unquote(parsed.fragment) if parsed.fragment else "Untitled"
    outbound = {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": parsed.hostname, "port": port, "method": method, "password": password}]},
    }
    return remark, outbound

def _parse_vmess_link(link: str) -> tuple[str, dict] | None:
    try:
        raw_config = _decode_base64_text(link.removeprefix("vmess://"))
        config = json.loads(raw_config)
        port = int(config["port"])
        address = config["add"]
        user_id = config["id"]
    except Exception:
        return None
    query = {
        "type": config.get("net") or "tcp",
        "security": config.get("tls") or "none",
        "path": config.get("path", ""),
        "host": config.get("host", ""),
        "sni": config.get("sni", ""),
        "fp": config.get("fp", ""),
        "alpn": config.get("alpn", ""),
        "headerType": config.get("type", ""),
        "mode": config.get("mode", ""),
    }
    outbound = {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": address, "port": port, "users": [{"id": user_id, "alterId": int(config.get("aid") or 0), "security": config.get("scy") or "auto"}]}]},
        "streamSettings": _build_stream_settings(query),
    }
    return config.get("ps") or "Untitled", outbound

def convert_link_via_xray(link: str, xray_path: str | None = None) -> tuple[str, dict] | None:
    link = link.strip()
    if not link: return None
    if link.startswith("vless://"): return _parse_vless_link(link)
    if link.startswith("trojan://"): return _parse_trojan_link(link)
    if link.startswith("ss://"): return _parse_shadowsocks_link(link)
    if link.startswith("vmess://"): return _parse_vmess_link(link)
    return None

def wait_for_port(port: int, timeout: float = 1.0) -> bool:
    start_time = time.perf_counter()
    while time.perf_counter() - start_time < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except (ConnectionRefusedError, socket.timeout):
            time.sleep(0.05)
    return False

def check_single_config(outbound: dict, port: int, xray_path: str) -> tuple[float, float]:
    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
    }
    fd, config_path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(config, f)
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        proc = subprocess.Popen(
            [xray_path, "run", "-config", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags
        )
        if not wait_for_port(port, timeout=MIN_XRAY_START_TIMEOUT):
            if proc.poll() is None:
                proc.terminate(); proc.wait()
            return float('inf'), 0.0
        if proc.poll() is not None:
            return float('inf'), 0.0
        proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
        t0 = time.perf_counter()
        latency = float('inf')
        downloaded_bytes = 0
        t_start_download = None
        try:
            with requests.get(
                TEST_URL, proxies=proxies,
                timeout=(TEST_CONNECT_TIMEOUT, TEST_READ_TIMEOUT),
                headers={"User-Agent": "Mozilla/5.0 v2ray-checker"},
                stream=True,
            ) as r:
                if r.status_code >= 400:
                    return float('inf'), 0.0
                t_first_byte = time.perf_counter()
                latency = (t_first_byte - t0) * 1000
                t_start_download = time.perf_counter()
                for chunk in r.iter_content(chunk_size=4096):
                    if chunk: downloaded_bytes += len(chunk)
                t_end_download = time.perf_counter()
        except Exception:
            return float('inf'), 0.0
        finally:
            if proc.poll() is None:
                proc.terminate(); proc.wait()
        if t_start_download and downloaded_bytes > 0:
            download_duration = t_end_download - t_start_download
            if download_duration > 0:
                speed_kbps = (downloaded_bytes / 1024) / download_duration
                return latency, speed_kbps
    finally:
        try: os.unlink(config_path)
        except OSError: pass
    return float('inf'), 0.0

def _gh_tree_raw_urls(repo_url: str) -> list[str]:
    """Для GitHub-репозитория возвращает список raw-URL файлов с прокси."""
    try:
        parts = [p for p in repo_url.rstrip("/").split("/") if p]
        gh_idx = next((i for i, p in enumerate(parts) if "github.com" in p), None)
        if gh_idx is None or len(parts) < gh_idx + 3:
            return []
        owner = parts[gh_idx + 1]
        repo  = parts[gh_idx + 2]
    except Exception:
        return []

    VLESS_KEYWORDS = ["vless","vmess","trojan","proxy","config","sub","node","free","vpn","server","link","bypass","rkn","clash"]

    def score_path(path: str) -> int:
        low = path.lower()
        if not any(low.endswith(s) for s in (".txt", ".base64", ".list")):
            return 0
        score = sum(2 for kw in VLESS_KEYWORDS if kw in low)
        score -= path.count("/")
        return score

    for branch in ("main", "master"):
        try:
            req = Request(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1",
                headers=_GH_HEADERS,
            )
            with urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            if "tree" not in data:
                continue
            scored = []
            for item in data["tree"]:
                if item.get("type") != "blob":
                    continue
                s = score_path(item["path"])
                if s > 0:
                    scored.append((s, item["path"]))
            if not scored:
                continue
            scored.sort(key=lambda x: -x[0])
            base = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}"
            return [f"{base}/{p}" for _, p in scored[:5]]
        except Exception:
            continue

    # фоллбэк: стандартные имена файлов
    results = []
    for branch in ("main", "master"):
        for fname in ("vless.txt", "configs.txt", "config.txt", "sub.txt", "subscription.txt", "proxies.txt", "v2ray.txt"):
            results.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{fname}")
    return results

def parse_subscription(source: str | None) -> list[str]:
    """Загружает подписку по ссылке или разбирает сырую строку."""
    if not source:
        return []
    source = source.strip()
    if not source:
        return []

    # GitHub-репозиторий → получаем raw-файлы через tree API
    if re.match(r"https?://(www\.)?github\.com/[^/]+/[^/]+/?$", source):
        all_links: list[str] = []
        for raw_url in _gh_tree_raw_urls(source):
            all_links.extend(parse_subscription(raw_url))
            if all_links:
                break
        return all_links

    if source.startswith(("http://", "https://")):
        try:
            req = Request(source, headers={"User-Agent": "v2ray-checker"})
            with urlopen(req, timeout=10) as r:
                source = r.read().decode("utf-8", errors="replace")
        except Exception as e:
            print(f"  [ОШИБКА] Не удалось загрузить подписку: {e}")
            return []

    if not source.startswith(("vless://", "vmess://", "trojan://", "ss://")):
        try:
            missing_padding = len(source) % 4
            if missing_padding: source += '=' * (4 - missing_padding)
            source = base64.b64decode(source).decode("utf-8", errors="replace")
        except Exception:
            pass

    source = html.unescape(source)
    pattern = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s<>'\"]+")
    return [match.group(0).strip() for match in pattern.finditer(source)]

def load_sources_txt() -> list[str]:
    """Читает source.txt и возвращает список URL-источников."""
    src_path = os.path.join(PROJECT_DIR, "source.txt")
    if not os.path.exists(src_path):
        return []
    urls = []
    with open(src_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("://"):
                line = "https:" + line
            urls.append(line)
    print(f"[+] source.txt: загружено {len(urls)} источников")
    return urls

def check_configs(links: list[tuple[str, dict, str]], xray_path: str) -> list[tuple[float, float, str, str]]:
    valid_configs = []
    links = [item for item in links if item is not None]
    if not links:
        return valid_configs
    with ThreadPoolExecutor(max_workers=CONCURRENT_DEFAULT) as executor:
        futures = {
            executor.submit(check_single_config, outbound, SOCKS_PORT_MIN + idx, xray_path): (remark, original_link)
            for idx, (remark, outbound, original_link) in enumerate(links)
        }
        for future in as_completed(futures):
            remark, link = futures[future]
            try:
                latency, speed = future.result()
                if latency != float('inf') and speed > 0:
                    speed_str = f"{speed / 1024:.2f} MB/s" if speed >= 1024 else f"{speed:.0f} KB/s"
                    print(f"  [OK] {remark:<30} | Скор: {speed_str:<10} | Зад: {int(latency)} мс")
                    valid_configs.append((speed, latency, remark, link))
                else:
                    print(f"  [FAIL] {remark:<30}")
            except Exception as e:
                print(f"  [ОШИБКА] {remark}: {e}")
    valid_configs.sort(key=lambda x: x[0], reverse=True)
    return valid_configs

def parse_proxy_links(raw_links: list[str]) -> list[tuple[str, dict, str]]:
    parsed_links = []
    for link in raw_links:
        parsed = convert_link_via_xray(link)
        if parsed is None:
            continue
        remark, outbound = parsed
        parsed_links.append((remark, outbound, link))
    return parsed_links

def save_results(links: list[str], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        for link in links:
            f.write(f"{link}\n")

@lru_cache(maxsize=2048)
def detect_country(address: str) -> str:
    try:
        ip = socket.gethostbyname(address)
    except Exception:
        return "Unknown"
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        data = r.json()
        if not data.get("success", False):
            return "Unknown"
        return data.get("country_code") or "Unknown"
    except Exception:
        return "Unknown"

def get_country_emoji(country_code: str) -> str:
    if country_code == "Unknown":
        return "❓"
    try:
        return chr(127397 + ord(country_code[0])) + chr(127397 + ord(country_code[1]))
    except Exception:
        return "❓"

def get_link_address(link: str) -> str:
    parsed = convert_link_via_xray(link)
    if parsed is None:
        return ""
    _, outbound = parsed
    settings = outbound.get("settings", {})
    if outbound.get("protocol") in ("vless", "vmess"):
        vnext = settings.get("vnext") or []
        return vnext[0].get("address", "") if vnext else ""
    servers = settings.get("servers") or []
    return servers[0].get("address", "") if servers else ""

def set_link_remark(link: str, remark: str) -> str:
    if link.startswith("vmess://"):
        try:
            config = json.loads(_decode_base64_text(link.removeprefix("vmess://")))
            config["ps"] = remark
            encoded = base64.urlsafe_b64encode(
                json.dumps(config, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii").rstrip("=")
            return f"vmess://{encoded}"
        except Exception:
            return link
    try:
        parsed = urlsplit(link)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, quote(remark, safe="")))
    except Exception:
        return link

def add_country_to_remarks(valid_links: list[tuple[float, float, str, str]], prefix: str) -> list[tuple[float, float, str, str]]:
    renamed_links = []
    for idx, (speed, latency, _remark, link) in enumerate(valid_links, 1):
        address = get_link_address(link)
        country = detect_country(address)
        country_emoji = get_country_emoji(country)
        speed_str = f"{speed / 1024:.1f}MB/s" if speed >= 1024 else f"{speed:.0f}KB/s"
        new_remark = f"{country_emoji} {prefix}#{idx} {speed_str} {latency:.0f}ms"
        renamed_links.append((speed, latency, new_remark, set_link_remark(link, new_remark)))
    return renamed_links

def main():
    try:
        xray_path = setup_xray_bin()
    except Exception as e:
        print(f"[КРИТИЧЕСКАЯ ОШИБКА] Не удалось настроить Xray: {e}")
        sys.exit(1)

    print("Источники из .env:")
    for url in INTERNET_SUBS_POOL:
        print(f"  - internet: {url}")
    for url in WHITELISTED_SUBS_POOL:
        print(f"  - whitelist: {url}")

    # Дополнительные источники из source.txt
    extra_sources = load_sources_txt()

    print("\n[+] Загрузка подписок из .env пулов...")
    raw_links_internet = []
    raw_links_whitelist = []
    for url in INTERNET_SUBS_POOL:
        raw_links_internet.extend(parse_subscription(url))
    for url in WHITELISTED_SUBS_POOL:
        raw_links_whitelist.extend(parse_subscription(url))

    # Загружаем наши источники из source.txt в интернет-пул
    if extra_sources:
        print(f"\n[+] Загрузка {len(extra_sources)} источников из source.txt...")
        seen_keys: set[str] = set()
        extra_links: list[str] = []
        for i, url in enumerate(extra_sources, 1):
            fetched = parse_subscription(url)
            new_count = 0
            for link in fetched:
                k = link[:80]
                if k not in seen_keys:
                    seen_keys.add(k)
                    extra_links.append(link)
                    new_count += 1
            if new_count > 0 and i % 50 == 0:
                print(f"  [{i}/{len(extra_sources)}] собрано {len(extra_links)} ссылок")
        raw_links_internet.extend(extra_links)
        print(f"  Из source.txt добавлено: {len(extra_links)} ссылок")

    # Дедупликация
    seen: set[str] = set()
    dedup_internet: list[str] = []
    for link in raw_links_internet:
        k = link[:80]
        if k not in seen:
            seen.add(k)
            dedup_internet.append(link)
    raw_links_internet = dedup_internet

    valid_links_internet = []
    valid_links_whitelist = []

    if raw_links_internet:
        print(f"\n[+] Загружено {len(raw_links_internet)} ссылок из интернет-пула.")
        raw_links_internet = raw_links_internet[:MAX_LINKS_TO_CHECK_INTERNET]
        print(f"\n[+] Проверка {len(raw_links_internet)} ссылок из интернет-пула...")
        valid_links_internet = check_configs(parse_proxy_links(raw_links_internet), xray_path)[:INTERNET_CFGS_COUNT]

    if raw_links_whitelist:
        print(f"\n[+] Загружено {len(raw_links_whitelist)} ссылок из вайтлиста.")
        raw_links_whitelist = raw_links_whitelist[:MAX_LINKS_TO_CHECK_WHITELIST]
        print(f"\n[+] Проверка {len(raw_links_whitelist)} ссылок из вайтлиста...")
        valid_links_whitelist = check_configs(parse_proxy_links(raw_links_whitelist), xray_path)[:WHITELISTED_CFGS_COUNT]

    valid_links_internet.sort(key=lambda x: x[0], reverse=True)
    valid_links_whitelist.sort(key=lambda x: x[0], reverse=True)

    print("\n[+] Определение страны по IP для рабочих ссылок...")
    valid_links_internet  = add_country_to_remarks(valid_links_internet,  "ОСТАТЬСЯ НА СВЯЗИ 🌐")
    valid_links_whitelist = add_country_to_remarks(valid_links_whitelist, "ОСТАТЬСЯ НА СВЯЗИ ⭐")

    print("\n" + "=" * 60)
    print(f"\n[РЕЗУЛЬТАТ] Рабочих ссылок из интернет-пула: {len(valid_links_internet)}")
    print(f"[РЕЗУЛЬТАТ] Рабочих ссылок из вайтлиста:    {len(valid_links_whitelist)}")
    print("=" * 60)

    if valid_links_internet:
        print("\n🏆 Топ самых быстрых серверов:")
        for rank, (speed, latency, remark, link) in enumerate(valid_links_internet, 1):
            speed_str = f"{speed / 1024:.2f} MB/s" if speed >= 1024 else f"{speed:.0f} KB/s"
            print(f"  {rank}. [{speed_str:<10} | {int(latency)} мс] {remark}")

    if valid_links_whitelist:
        print("\n🔒 Рабочие ссылки из вайтлиста:")
        for rank, (speed, latency, remark, link) in enumerate(valid_links_whitelist, 1):
            speed_str = f"{speed / 1024:.2f} MB/s" if speed >= 1024 else f"{speed:.0f} KB/s"
            print(f"  {rank}. [{speed_str:<10} | {int(latency)} мс] {remark}")

    if valid_links_internet:
        output_internet = os.path.join(PROJECT_DIR, "valid_internet_links.txt")
        save_results([link for _, _, _, link in valid_links_internet], output_internet)
        print(f"\n[+] Интернет-ссылки сохранены: {output_internet}")

    if valid_links_whitelist:
        output_whitelist = os.path.join(PROJECT_DIR, "valid_whitelist_links.txt")
        save_results([link for _, _, _, link in valid_links_whitelist], output_whitelist)
        print(f"\n[+] Вайтлист-ссылки сохранены: {output_whitelist}")

    # Финальный файл подписки
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    final_lines = [
        "#profile-title: ОСТАТЬСЯ НА СВЯЗИ🛜",
        "#profile-update-interval: 1",
        f"#announce: ОСТАТЬСЯ НА СВЯЗИ | Авто-обновление | {ts}",
        ""
    ]
    if valid_links_whitelist:
        for _, _, _, link in valid_links_whitelist:
            final_lines.append(link)
    if valid_links_internet:
        for _, _, _, link in valid_links_internet:
            final_lines.append(link)

    output_sub = os.path.join(PROJECT_DIR, "v2ray_sub.txt")
    with open(output_sub, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))
    print(f"[+] Финальный файл подписки: {output_sub}")
    print(f"    Всего конфигов: {len(valid_links_internet) + len(valid_links_whitelist)}")

if __name__ == "__main__":
    main()
