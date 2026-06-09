#!/usr/bin/env python3
"""
VLESS Config Parser & Checker — v10 (GitHub Actions)
Stage 1: TCP  →  Stage 2: TLS  →  Stage 3: sing-box (primary) + Xray (fallback)
Bonus: whitelist SNI/IP check — white configs sorted first

Changes in v9 vs v8:
  - Stage 3 tries sing-box FIRST (better REALITY/flow support), Xray as fallback
  - _singbox_cfg(): generates correct sing-box 1.x JSON (tls, utls, reality, transports)
  - _run_core(): generic runner works with both cores (same port-wait / speed-test logic)
  - _core_one(): sing-box → Xray fallback per config
  - Checked.core field: tracks which binary confirmed the config
  - stats.json: singbox_hits + xray_hits breakdown
"""

import asyncio, base64, ipaddress, json, os, re, socket, ssl
import subprocess, sys, tempfile, time, urllib.request, urllib.parse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timezone

import requests as req_lib
from requests.exceptions import RequestException

# ═══════════════════════════ tunables ════════════════════════════════════════

MAX_XRAY   = 200
MAX_TCPTLS = 500

TCP_CONCURRENCY  = 80
TLS_CONCURRENCY  = 40
XRAY_CONCURRENCY = 12

TCP_TIMEOUT   = 5
TLS_TIMEOUT   = 8
XRAY_TIMEOUT  = 15
FETCH_TIMEOUT = 20

CONFIG_NAME    = "ОСТАТЬСЯ НА СВЯЗИ 🛜"
SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=1048576"  # 1 MB — точнее 200KB
FALLBACK_URL   = "http://cp.cloudflare.com/"
FALLBACK_URL2  = "http://speedtest.tele2.net/1MB.zip"
MIN_SPEED_MBPS = 0.05   # минимум ~50 KB/s — фильтр мёртвых конфигов
CHUNK_SIZE     = 4096

XRAY_PATH    = os.environ.get("XRAY_PATH",    "/tmp/xray")
SINGBOX_PATH = os.environ.get("SINGBOX_PATH", "/tmp/sing-box")
GH_TOKEN     = os.environ.get("GITHUB_TOKEN", "")

# ═══════════════════════════ data model ══════════════════════════════════════

@dataclass
class Vless:
    uuid:     str
    host:     str
    port:     int
    name:     str
    raw_uri:  str
    sni:      Optional[str] = None
    path:     Optional[str] = None
    network:  Optional[str] = None
    security: Optional[str] = None
    flow:     Optional[str] = None
    pbk:      Optional[str] = None
    sid:      Optional[str] = None
    fp:       Optional[str] = None

@dataclass
class Checked:
    cfg:        Vless
    tcp_ok:     bool           = False
    tls_ok:     Optional[bool] = None
    xray_ok:    Optional[bool] = None
    white_ok:   bool           = False
    latency:    float          = 9999.0
    speed_mbps: float          = 0.0
    stage:      str            = "tcp"
    core:       str            = ""        # "singbox" | "xray" | ""

# ═══════════════════════════ whitelist ═══════════════════════════════════════

_sni_set:   set[str]        = set()
_net_index: dict[int, list] = {}

def _load_whitelist() -> tuple[int, int]:
    sni_count = net_count = 0
    try:
        with open("whitelist_sni.txt", encoding="utf-8") as f:
            for line in f:
                d = line.strip().lower()
                if d: _sni_set.add(d)
        sni_count = len(_sni_set)
    except FileNotFoundError:
        print("  [WARN] whitelist_sni.txt not found")
    try:
        with open("whitelist_cidr.txt", encoding="utf-8") as f:
            for line in f:
                cidr = line.strip()
                if not cidr: continue
                try:
                    net   = ipaddress.ip_network(cidr, strict=False)
                    first = net.network_address.packed[0]
                    _net_index.setdefault(first, []).append(net)
                    net_count += 1
                except ValueError:
                    pass
    except FileNotFoundError:
        print("  [WARN] whitelist_cidr.txt not found")
    return sni_count, net_count

def _is_white_ip(host: str) -> bool:
    try:
        addr  = ipaddress.ip_address(host)
        first = addr.packed[0]
        return any(addr in net for net in _net_index.get(first, []))
    except ValueError:
        return False

def check_whitelist(cfg: Vless) -> bool:
    sni  = (cfg.sni  or "").lower()
    host = cfg.host.lower()
    if sni  and sni  in _sni_set: return True
    if host and host in _sni_set: return True
    return _is_white_ip(cfg.host)

# ═══════════════════════════ vless parsing ═══════════════════════════════════

def parse_uri(uri: str) -> Optional[Vless]:
    uri = uri.strip()
    if not uri.startswith("vless://"): return None
    try:
        body = uri[8:]
        hi   = body.find("#")
        name = urllib.parse.unquote(body[hi+1:]) if hi >= 0 else ""
        main = body[:hi] if hi >= 0 else body
        ai   = main.find("@")
        if ai < 0: return None
        uuid = main[:ai]
        rest = main[ai+1:]
        qi   = rest.find("?")
        hp   = rest[:qi] if qi >= 0 else rest
        qs   = rest[qi+1:] if qi >= 0 else ""

        if hp.startswith("["):
            cb = hp.find("]")
            if cb < 0: return None
            host = hp[1:cb]; port = int(hp[cb+2:])
        else:
            lc = hp.rfind(":")
            if lc < 0: return None
            host = hp[:lc]; port = int(hp[lc+1:])

        if not host or not (1 <= port <= 65535): return None
        if not uuid or len(uuid) < 10: return None

        p = {}
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                p[k] = urllib.parse.unquote(v)

        return Vless(
            uuid=uuid, host=host, port=port, name=name, raw_uri=uri,
            sni     = p.get("sni")                              or None,
            path    = p.get("path")                             or None,
            network = p.get("type") or p.get("network")        or None,
            security= (p.get("security") or p.get("tls") or "").lower() or None,
            flow    = p.get("flow") or None,
            pbk     = p.get("pbk")  or None,
            sid     = p.get("sid")  or None,
            fp      = p.get("fp")   or None,
        )
    except Exception:
        return None

def extract_from_text(text: str) -> list[Vless]:
    out, seen = [], set()
    for line in re.split(r"[\r\n\s]+", text):
        line = line.strip()
        if not line.startswith("vless://"): continue
        v = parse_uri(line)
        if v:
            k = f"{v.uuid}@{v.host}:{v.port}"
            if k not in seen:
                seen.add(k); out.append(v)
    return out

def try_b64(text: str) -> str:
    try:
        d = base64.b64decode(text.strip() + "==").decode("utf-8", errors="ignore")
        if any(s in d for s in ("vless://", "vmess://", "trojan://")): return d
    except Exception: pass
    return text

# ═══════════════════════════ github url discovery ════════════════════════════

_GH_HEADERS: dict = {"User-Agent": "vless-parser/9.0"}
if GH_TOKEN:
    _GH_HEADERS["Authorization"] = f"Bearer {GH_TOKEN}"

VLESS_KEYWORDS = [
    "vless","vmess","trojan","proxy","config","sub","node",
    "free","vpn","server","link","bypass","rkn","clash",
]

def _score_path(path: str) -> int:
    low = path.lower()
    if not any(low.endswith(s) for s in (".txt", ".base64", ".list", ".html")): return 0
    score  = sum(2 for kw in VLESS_KEYWORDS if kw in low)
    score -= path.count("/")
    return score

def _gh_tree_candidates(owner: str, repo: str) -> list[str]:
    for branch in ("main", "master", "HEAD"):
        try:
            r = urllib.request.Request(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1",
                headers=_GH_HEADERS,
            )
            with urllib.request.urlopen(r, timeout=10) as resp:
                data = json.loads(resp.read())
            if "tree" not in data: continue
            scored: list[tuple[int, str]] = []
            for item in data["tree"]:
                if item.get("type") != "blob": continue
                s = _score_path(item["path"])
                if s > 0: scored.append((s, item["path"]))
            if not scored: continue
            scored.sort(key=lambda x: -x[0])
            base = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}"
            return [f"{base}/{urllib.parse.quote(path)}" for _, path in scored]
        except Exception:
            continue
    candidates = []
    for branch in ("main", "master"):
        for fname in (
            "vless.txt","configs.txt","config.txt","sub.txt","subscription.txt",
            "proxies.txt","nodes.txt","free.txt","vpn.txt","proxy.txt",
            "output/vless.txt","output/configs.txt","result/vless.txt",
            "data/vless.txt","subs/vless.txt","v2ray.txt","links.txt",
        ):
            candidates.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{fname}")
    return candidates

def resolve_urls(url: str) -> list[str]:
    if "raw.githubusercontent.com" in url: return [url]
    if url.startswith("://"): url = "https" + url
    if not url.startswith("http"): url = "https://" + url
    parsed  = urllib.parse.urlparse(url)
    netloc  = parsed.netloc.lower()
    if netloc not in ("github.com", "www.github.com"): return [url]
    parts   = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2: return []
    owner, repo = parts[0], parts[1]
    if len(parts) > 3 and parts[2] in ("blob", "raw"):
        branch    = parts[3]
        file_path = "/".join(parts[4:])
        return [f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"]
    return _gh_tree_candidates(owner, repo)

# ═══════════════════════════ fetching ════════════════════════════════════════

def fetch(url: str) -> Optional[str]:
    try:
        r = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(r, timeout=FETCH_TIMEOUT) as resp:
            raw = resp.read(20 * 1024 * 1024)
            return try_b64(raw.decode("utf-8", errors="ignore"))
    except Exception:
        return None

def fetch_source(url: str) -> list[Vless]:
    # Собираем конфиги из ВСЕХ файлов источника (для github-репо — из всех найденных
    # .txt), а не только из первого непустого, с дедупликацией.
    out: list[Vless] = []
    seen: set[str] = set()
    for cand in resolve_urls(url):
        text = fetch(cand)
        if not text:
            continue
        for v in extract_from_text(text):
            k = f"{v.uuid}@{v.host}:{v.port}"
            if k not in seen:
                seen.add(k)
                out.append(v)
    return out

# ═══════════════════════════ geo / naming ════════════════════════════════════

_geo_cache: dict[str, str] = {}

def _flag(code: str) -> str:
    try: return "".join(chr(ord(c) + 127397) for c in code.upper())
    except: return "🌐"

def get_flag(host: str) -> str:
    if host in _geo_cache: return _geo_cache[host]
    try:
        r = urllib.request.Request(
            f"http://ip-api.com/json/{host}?fields=countryCode",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(r, timeout=3) as resp:
            code = json.loads(resp.read()).get("countryCode", "")
            f    = _flag(code) if code else "🌐"
    except Exception:
        f = "🌐"
    _geo_cache[host] = f
    return f

def named_uri(cfg: Vless, flag: str, white: bool, speed_mbps: float = 0.0) -> str:
    star = "⭐ " if white else ""
    spd  = f" {speed_mbps:.1f}MB/s" if speed_mbps >= MIN_SPEED_MBPS else ""
    name = f"{star}{flag}{spd} {CONFIG_NAME}"
    return f"{cfg.raw_uri.split('#')[0]}#{urllib.parse.quote(name)}"

# ═══════════════════════════ stage 1: tcp (async) ════════════════════════════

async def _tcp(host: str, port: int, timeout: float) -> tuple[bool, float]:
    t0 = asyncio.get_event_loop().time()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        ms = (asyncio.get_event_loop().time() - t0) * 1000
        w.close()
        try: await w.wait_closed()
        except: pass
        return True, ms
    except Exception:
        return False, (asyncio.get_event_loop().time() - t0) * 1000

async def stage_tcp(cfgs: list[Vless]) -> list[Checked]:
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    out: list[Checked] = []
    async def one(c: Vless) -> None:
        async with sem:
            ok, ms = await _tcp(c.host, c.port, TCP_TIMEOUT)
            out.append(Checked(cfg=c, tcp_ok=ok, latency=ms, stage="tcp"))
    await asyncio.gather(*[one(c) for c in cfgs])
    return out

# ═══════════════════════════ stage 2: tls (threaded) ═════════════════════════

_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode    = ssl.CERT_NONE

def _tls(host: str, port: int, sni: Optional[str], timeout: float) -> tuple[bool, float]:
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with _TLS_CTX.wrap_socket(raw, server_hostname=sni or host) as s:
                s.do_handshake()
                return True, (time.time() - t0) * 1000
    except Exception:
        return False, (time.time() - t0) * 1000

def _needs_tls(c: Checked) -> bool:
    if c.cfg.security in ("tls", "reality"): return True
    return c.cfg.port in (443, 8443, 2053, 2083, 2087, 2096)

def stage_tls(tcp_results: list[Checked]) -> list[Checked]:
    tls_cands  = [c for c in tcp_results if c.tcp_ok and _needs_tls(c)]
    plain_pass = [c for c in tcp_results if c.tcp_ok and not _needs_tls(c)]
    print(f"    TLS candidates: {len(tls_cands)}  plain TCP: {len(plain_pass)}")

    tls_out: list[Checked] = []
    def one(c: Checked) -> Checked:
        ok, ms = _tls(c.cfg.host, c.cfg.port, c.cfg.sni, TLS_TIMEOUT)
        c.tls_ok = ok
        if ok: c.latency, c.stage = ms, "tls"
        return c

    with ThreadPoolExecutor(max_workers=TLS_CONCURRENCY) as ex:
        for res in as_completed({ex.submit(one, c): c for c in tls_cands}):
            tls_out.append(res.result())
    return tls_out + plain_pass

# ═══════════════════════════ stage 3: sing-box + xray ════════════════════════

# ── sing-box config builder ───────────────────────────────────────────────────

def _singbox_cfg(cfg: Vless, port: int) -> dict:
    """Build sing-box 1.x JSON config for a VLESS outbound."""
    outbound: dict = {
        "type":    "vless",
        "tag":     "proxy",
        "server":  cfg.host,
        "server_port": cfg.port,
        "uuid":    cfg.uuid,
    }

    if cfg.flow:
        outbound["flow"] = cfg.flow

    sec = cfg.security or ""
    if sec in ("tls", "reality"):
        tls_obj: dict = {
            "enabled":     True,
            "server_name": cfg.sni or cfg.host,
            "insecure":    True,
            "utls": {
                "enabled":     True,
                "fingerprint": cfg.fp or "chrome",
            },
        }
        if sec == "reality":
            tls_obj["reality"] = {
                "enabled":    True,
                "public_key": cfg.pbk or "",
                "short_id":   cfg.sid or "",
            }
        outbound["tls"] = tls_obj

    net = cfg.network or "tcp"
    if net == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": cfg.path or "/",
            "headers": {"Host": cfg.sni or cfg.host},
        }
    elif net == "grpc":
        outbound["transport"] = {
            "type":         "grpc",
            "service_name": cfg.path or "",
        }
    elif net in ("h2", "http"):
        outbound["transport"] = {
            "type": "http",
            "path": cfg.path or "/",
            "host": [cfg.sni or cfg.host],
        }
    elif net in ("xhttp", "splithttp"):
        outbound["transport"] = {
            "type": "splithttp",
            "path": cfg.path or "/",
            "host": cfg.sni or cfg.host,
        }
    elif net == "httpupgrade":
        outbound["transport"] = {
            "type": "httpupgrade",
            "path": cfg.path or "/",
            "host": cfg.sni or cfg.host,
        }

    return {
        "log": {"level": "warn"},
        "inbounds": [{
            "type":        "socks",
            "listen":      "127.0.0.1",
            "listen_port": port,
        }],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "proxy"},
    }

# ── xray config builder ───────────────────────────────────────────────────────

def _xray_cfg(cfg: Vless, port: int) -> dict:
    stream: dict = {}
    net = cfg.network or "tcp"
    stream["network"] = net

    if net == "ws":
        stream["wsSettings"] = {"path": cfg.path or "/"}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": cfg.path or ""}
    elif net in ("h2", "http"):
        stream["httpSettings"] = {"path": cfg.path or "/"}
    elif net in ("xhttp", "splithttp"):
        stream["xhttpSettings"] = {"path": cfg.path or "/", "mode": "auto"}

    sec = cfg.security or ""
    if sec == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName":  cfg.sni or cfg.host,
            "fingerprint": cfg.fp  or "chrome",
            "publicKey":   cfg.pbk or "",
            "shortId":     cfg.sid or "",
        }
    elif sec == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName":    cfg.sni or cfg.host,
            "allowInsecure": True,
            "fingerprint":   cfg.fp  or "chrome",
        }

    user: dict = {"id": cfg.uuid, "encryption": "none"}
    if cfg.flow:
        user["flow"] = cfg.flow

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks", "protocol": "socks",
            "listen": "127.0.0.1", "port": port,
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [
            {
                "tag": "proxy", "protocol": "vless",
                "settings": {"vnext": [{
                    "address": cfg.host, "port": cfg.port,
                    "users": [user],
                }]},
                "streamSettings": stream,
            },
            {"tag": "direct", "protocol": "freedom"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "outboundTag": "proxy", "port": "0-65535"}],
        },
    }

# ── thread-safe port allocator ────────────────────────────────────────────────

_port_lock = threading.Lock()
_port_val  = [21000]

def _alloc_port() -> int:
    with _port_lock:
        p = _port_val[0]
        _port_val[0] = p + 1 if p < 50999 else 21000
        return p

def _wait_port(port: int, tries: int = 80, delay: float = 0.15) -> bool:
    for _ in range(tries):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.15)
            s.close(); return True
        except Exception:
            time.sleep(delay)
    return False

# ── speed test via socks5h ────────────────────────────────────────────────────

def _speed_test(port: int) -> tuple[bool, float, float]:
    """
    Download 200 KB via local SOCKS5h proxy.
    socks5h = DNS resolves through the proxy (critical for many configs).
    Returns (ok, latency_to_first_byte_ms, speed_mbps).
    """
    proxies = {
        "http":  f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
    for url in (SPEED_TEST_URL, FALLBACK_URL, FALLBACK_URL2):
        t_start = time.time()
        try:
            resp = req_lib.get(
                url, proxies=proxies, stream=True,
                timeout=(8, XRAY_TIMEOUT), verify=False,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True,
            )
            if resp.status_code not in (200, 204):
                resp.close(); continue

            t_first = time.time()
            latency_ms = (t_first - t_start) * 1000
            downloaded = 0
            for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                downloaded += len(chunk)

            t_end    = time.time()
            duration = t_end - t_first
            speed    = (downloaded / 1024 / 1024) / duration if duration > 0.01 else 0.0
            return True, latency_ms, speed
        except RequestException:
            continue
        except Exception:
            continue
    return False, 9999.0, 0.0

# ── core runner (generic for both sing-box and xray) ─────────────────────────

_core_errors: list[str] = []
_core_errors_lock = threading.Lock()

def _run_core(
    cfg: Vless,
    binary: str,
    cfg_builder,          # callable: (Vless, int) -> dict
    label: str,
) -> tuple[bool, float, float]:
    """
    Start `binary` with a temp config, wait for SOCKS port, run speed test.
    Returns (ok, latency_ms, speed_mbps).
    """
    port = _alloc_port()
    tmp  = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    proc = None
    try:
        json.dump(cfg_builder(cfg, port), tmp); tmp.close()

        proc = subprocess.Popen(
            [binary, "run", "-c", tmp.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.8)

        if not _wait_port(port):
            _, stderr_b = (proc.communicate(timeout=3) if proc else (b"", b""))
            err = (stderr_b or b"").decode("utf-8", errors="ignore").strip()
            with _core_errors_lock:
                if len(_core_errors) < 10 and err:
                    noise = ("Penetrates","[Warning]","[Info]","goroutine",
                             "accepted","rejected","dialing","level=warn","level=info")
                    if not any(x in err for x in noise):
                        _core_errors.append(f"[{label}] {err[:280]}")
            return False, 9999.0, 0.0

        return _speed_test(port)

    finally:
        if proc:
            try: proc.terminate()
            except: pass
            try: proc.wait(timeout=3)
            except:
                try: proc.kill()
                except: pass
        try: os.unlink(tmp.name)
        except: pass

# ── per-config checker: sing-box first → xray fallback ───────────────────────

def _core_one(cfg: Vless, sb_bin: Optional[str], xr_bin: Optional[str]) -> tuple[bool, float, float, str]:
    """Returns (ok, latency_ms, speed_mbps, core_name)."""
    # REALITY: public key is mandatory for both cores
    if cfg.security == "reality" and not cfg.pbk:
        return False, 9999.0, 0.0, ""

    # ── try sing-box first ────────────────────────────────────────────────────
    if sb_bin:
        ok, lat, spd = _run_core(cfg, sb_bin, _singbox_cfg, "singbox")
        if ok and spd >= MIN_SPEED_MBPS:
            return True, lat, spd, "singbox"

    # ── fallback: xray ────────────────────────────────────────────────────────
    if xr_bin:
        ok, lat, spd = _run_core(cfg, xr_bin, _xray_cfg, "xray")
        if ok and spd >= MIN_SPEED_MBPS:
            return True, lat, spd, "xray"

    return False, 9999.0, 0.0, ""

def stage_check(candidates: list[Checked], sb_bin: Optional[str], xr_bin: Optional[str]) -> list[Checked]:
    out: list[Checked] = []
    done = 0

    def one(c: Checked) -> Checked:
        ok, lat, spd, core = _core_one(c.cfg, sb_bin, xr_bin)
        c.xray_ok    = ok
        c.speed_mbps = spd
        c.core       = core
        if ok:
            c.latency = lat
            c.stage   = "xray"
        return c

    with ThreadPoolExecutor(max_workers=XRAY_CONCURRENCY) as ex:
        futures = {ex.submit(one, c): c for c in candidates}
        for fut in as_completed(futures):
            done += 1
            res = fut.result()
            out.append(res)
            if done % 20 == 0:
                ok_cnt  = sum(1 for x in out if x.xray_ok)
                sb_cnt  = sum(1 for x in out if x.core == "singbox")
                xr_cnt  = sum(1 for x in out if x.core == "xray")
                avg_spd = (
                    sum(x.speed_mbps for x in out if x.xray_ok) / ok_cnt
                    if ok_cnt else 0.0
                )
                print(f"    [{done}/{len(candidates)}] confirmed={ok_cnt} "
                      f"(sb={sb_cnt} xr={xr_cnt})  avg={avg_spd:.2f} MB/s")

    if _core_errors:
        print(f"  [Core errors — {len(_core_errors)} captured]")
        for e in _core_errors[:5]:
            print(f"    {e[:200]}")
    return out

# ═══════════════════════════ helpers ═════════════════════════════════════════

def read_sources() -> list[str]:
    try:
        with open("source.txt", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except FileNotFoundError:
        print("[ERROR] source.txt not found"); sys.exit(1)

def is_tcptls(c: Checked) -> bool:
    if c.tls_ok is True: return True
    if c.tls_ok is None and c.tcp_ok: return True
    return False

def write_list(configs: list[Checked], fname: str, limit: int, sub_name: str = CONFIG_NAME) -> int:
    # Сортируем: сначала whitelisted, потом по скорости (если есть) иначе по latency
    has_speed = any(c.speed_mbps >= MIN_SPEED_MBPS for c in configs)
    if has_speed:
        configs = sorted(configs, key=lambda c: (0 if c.white_ok else 1, -c.speed_mbps))[:limit]
    else:
        configs = sorted(configs, key=lambda c: (0 if c.white_ok else 1, c.latency))[:limit]
    white_cnt = sum(1 for c in configs if c.white_ok)
    print(f"  Geo lookup for {len(configs)} → {fname} (white: {white_cnt}, speed_sorted={has_speed}) ...")
    lines = []
    for i, c in enumerate(configs, 1):
        if i % 100 == 0: print(f"    {i}/{len(configs)}")
        lines.append(named_uri(c.cfg, get_flag(c.cfg.host), c.white_ok, c.speed_mbps))

    ts       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    b64_name = base64.b64encode(sub_name.encode("utf-8")).decode("ascii")
    header   = (
        f"# !name={sub_name}\n"
        f"# profile-title: base64:{b64_name}\n"
        f"# !desc=Авто-обновление каждый час · {ts} · white:{white_cnt}/{len(configs)}\n"
        f"# !url=https://raw.githubusercontent.com/B3B3097/paraser/main/{fname}\n"
    )
    full = header + "\n".join(lines) + "\n"
    with open(fname, "w", encoding="utf-8") as f: f.write(full)
    b64fname = fname.replace(".txt", "_base64.txt")
    with open(b64fname, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(full.encode("utf-8")).decode("ascii") + "\n")
    return len(lines)

# ═══════════════════════════ main ════════════════════════════════════════════

async def main() -> None:
    print(f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}] VLESS Parser v10")

    sb_ok = os.path.isfile(SINGBOX_PATH) and os.access(SINGBOX_PATH, os.X_OK)
    xr_ok = os.path.isfile(XRAY_PATH)    and os.access(XRAY_PATH, os.X_OK)

    sb_bin = SINGBOX_PATH if sb_ok else None
    xr_bin = XRAY_PATH    if xr_ok else None

    print(f"  sing-box : {'OK ' + SINGBOX_PATH if sb_ok else 'not found'}")
    print(f"  xray     : {'OK ' + XRAY_PATH    if xr_ok else 'not found'}")
    if not sb_ok and not xr_ok:
        print("  [WARN] No proxy core available — Stage 3 will be skipped")
    print(f"  GitHub   : {'authenticated' if GH_TOKEN else 'anonymous (60/h)'}")
    print(f"  Test URL : {SPEED_TEST_URL}")

    sni_cnt, net_cnt = _load_whitelist()
    print(f"  Whitelist: {sni_cnt} SNI domains + {net_cnt} CIDR blocks")

    sources = read_sources()
    print(f"  Sources  : {len(sources)}\n")

    # ── FETCH ─────────────────────────────────────────────────────────────────
    all_cfgs: list[Vless] = []
    seen: set[str]        = set()
    for i, url in enumerate(sources, 1):
        fetched = fetch_source(url)
        added   = 0
        for v in fetched:
            k = f"{v.uuid}@{v.host}:{v.port}"
            if k not in seen:
                seen.add(k); all_cfgs.append(v); added += 1
        if added or (i % 100 == 0):
            print(f"  [{i:>4}/{len(sources)}] +{added:<5} total={len(all_cfgs):<7}  {url[:70]}")

    print(f"\n  Total unique VLESS configs: {len(all_cfgs)}")
    if not all_cfgs:
        print("[WARN] No configs found."); return

    # ── STAGE 1: TCP ──────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"Stage 1 — TCP  (conc={TCP_CONCURRENCY}, timeout={TCP_TIMEOUT}s)")
    tcp_res  = await stage_tcp(all_cfgs)
    tcp_pass = [c for c in tcp_res if c.tcp_ok]
    print(f"  Passing: {len(tcp_pass)} / {len(all_cfgs)}")

    # ── STAGE 2: TLS ──────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"Stage 2 — TLS  (conc={TLS_CONCURRENCY}, timeout={TLS_TIMEOUT}s)")
    tls_res       = stage_tls(tcp_res)
    tls_confirmed = sum(1 for c in tls_res if c.tls_ok)
    tcptls_pass   = sorted([c for c in tls_res if is_tcptls(c)], key=lambda c: c.latency)
    print(f"  TLS confirmed: {tls_confirmed}   TCP+TLS pool: {len(tcptls_pass)}")

    # ── WHITELIST ─────────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("Whitelist check...")
    for c in tcptls_pass:
        c.white_ok = check_whitelist(c.cfg)
    white_cnt = sum(1 for c in tcptls_pass if c.white_ok)
    print(f"  Whitelisted: {white_cnt} / {len(tcptls_pass)}")

    # ── STAGE 3: sing-box + xray ───────────────────────────────────────────────
    confirmed    = 0
    singbox_hits = 0
    xray_hits    = 0
    avg_speed    = 0.0
    check_res: list[Checked] = []

    if sb_ok or xr_ok:
        def core_valid(c: Checked) -> bool:
            return not (c.cfg.security == "reality" and not c.cfg.pbk)

        tls_white  = [c for c in tcptls_pass if c.white_ok and c.tls_ok  and core_valid(c)]
        tls_rest   = [c for c in tcptls_pass if not c.white_ok and c.tls_ok and core_valid(c)]
        plain_rest = [c for c in tcptls_pass if not c.tls_ok              and core_valid(c)]
        check_input = (tls_white + tls_rest + plain_rest)[:600]

        cores_str = " + ".join(filter(None, [
            "sing-box" if sb_ok else "",
            "xray"     if xr_ok else "",
        ]))
        print(f"\n{'─'*60}")
        print(f"Stage 3 — {cores_str}  (conc={XRAY_CONCURRENCY}, timeout={XRAY_TIMEOUT}s)")
        print(f"  Testing {len(check_input)}  "
              f"(tls_white={len(tls_white)}  tls_rest={len(tls_rest)}  plain={len(plain_rest)})")
        print(f"  Method: requests socks5h → {SPEED_TEST_URL}")

        check_res    = stage_check(check_input, sb_bin, xr_bin)
        confirmed    = sum(1 for c in check_res if c.xray_ok)
        singbox_hits = sum(1 for c in check_res if c.core == "singbox")
        xray_hits    = sum(1 for c in check_res if c.core == "xray")
        if confirmed:
            avg_speed = sum(c.speed_mbps for c in check_res if c.xray_ok) / confirmed

        print(f"  Confirmed: {confirmed}  (sing-box={singbox_hits}, xray={xray_hits})  "
              f"avg speed: {avg_speed:.2f} MB/s")
    else:
        print("\n── Stage 3 skipped (no proxy core available) ──")

    # ── OUTPUT ────────────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")

    if confirmed > 0:
        xray_pool = sorted(
            [c for c in check_res if c.xray_ok],
            key=lambda c: (-c.speed_mbps, c.latency),
        )
    else:
        xray_pool = tcptls_pass
        if sb_ok or xr_ok:
            print("  [WARN] Confirmed 0 — falling back to TCP+TLS pool")

    n_xray   = write_list(xray_pool,   "OSTATSYA_NA_SVYAZI.txt",        MAX_XRAY)
    n_tcptls = write_list(tcptls_pass, "OSTATSYA_NA_SVYAZI_tcptls.txt", MAX_TCPTLS)

    stats = {
        "updated_at":       datetime.now(timezone.utc).isoformat(),
        "sources_count":    len(sources),
        "total_fetched":    len(all_cfgs),
        "tcp_passing":      len(tcp_pass),
        "tls_confirmed":    tls_confirmed,
        "xray_confirmed":   confirmed,
        "singbox_hits":     singbox_hits,
        "xray_hits":        xray_hits,
        "avg_speed_mbps":   round(avg_speed, 3),
        "whitelist_sni":    sni_cnt,
        "whitelist_cidr":   net_cnt,
        "whitelisted_pool": white_cnt,
        "output_xray":      n_xray,
        "output_tcptls":    n_tcptls,
        "singbox_used":     sb_ok,
        "xray_used":        xr_ok,
        "xray_fallback":    (sb_ok or xr_ok) and confirmed == 0,
        "success_rate":     round(len(tcp_pass)/len(all_cfgs)*100, 1) if all_cfgs else 0,
    }
    with open("stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    label = (
        f"(sing-box={singbox_hits} xray={xray_hits}, avg {avg_speed:.2f} MB/s)"
        if confirmed > 0 else "(tcp+tls fallback)"
    )
    print(f"""
  OSTATSYA_NA_SVYAZI.txt        — {n_xray} configs  {label}
  OSTATSYA_NA_SVYAZI_tcptls.txt — {n_tcptls} configs
  Done. fetched={len(all_cfgs)} tcp={len(tcp_pass)} tls={tls_confirmed} confirmed={confirmed} white={white_cnt}
""")

if __name__ == "__main__":
    asyncio.run(main())

