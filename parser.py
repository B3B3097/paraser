#!/usr/bin/env python3
"""
VLESS Config Parser & Checker — GitHub Actions edition
─────────────────────────────────────────────────────────
Fetch pipeline:
  • For raw/direct URLs → fetch immediately
  • For GitHub repo URLs → query tree API to find ALL .txt config files

Check pipeline:
  Stage 1 — TCP        (all configs,  80 concurrent, 5 s)
  Stage 2 — TLS        (TCP-passing,  40 concurrent, 8 s)
  Stage 3 — Xray real  (best survivors, 10 concurrent, 15 s via xray binary)

Output:
  OSTATSYA_NA_SVYAZI.txt          top 200 Xray-confirmed  (most reliable)
  OSTATSYA_NA_SVYAZI_base64.txt   same, base64
  OSTATSYA_NA_SVYAZI_tcptls.txt   top 500 TCP+TLS-passed  (more configs)
  OSTATSYA_NA_SVYAZI_tcptls_base64.txt  same, base64
  stats.json
"""

import asyncio, base64, json, os, random, re, socket, ssl
import subprocess, sys, tempfile, time, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timezone

# ═══════════════════════════ tunables ════════════════════════════════════════

MAX_XRAY   = 200   # max configs in Xray-confirmed output
MAX_TCPTLS = 500   # max configs in TCP+TLS output

TCP_CONCURRENCY  = 80
TLS_CONCURRENCY  = 40
XRAY_CONCURRENCY = 10

TCP_TIMEOUT  = 5    # seconds
TLS_TIMEOUT  = 8
XRAY_TIMEOUT = 15
FETCH_TIMEOUT = 20

CONFIG_NAME = "ОСТАТЬСЯ НА СВЯЗИ 🛜"
TEST_URL    = "http://www.gstatic.com/generate_204"
XRAY_PATH   = os.environ.get("XRAY_PATH", "/tmp/xray")

# GitHub token — used for API calls (passed from workflow via GITHUB_TOKEN env)
GH_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# ═══════════════════════════ data model ══════════════════════════════════════

@dataclass
class Vless:
    uuid: str
    host: str
    port: int
    name: str
    raw_uri: str
    sni:  Optional[str] = None
    path: Optional[str] = None
    network:  Optional[str] = None
    security: Optional[str] = None
    flow: Optional[str] = None

@dataclass
class Checked:
    cfg:      Vless
    tcp_ok:   bool  = False
    tls_ok:   Optional[bool] = None   # None = skipped
    xray_ok:  Optional[bool] = None
    latency:  float = 9999.0          # ms
    stage:    str   = "tcp"

# ═══════════════════════════ vless parsing ════════════════════════════════════

def parse_uri(uri: str) -> Optional[Vless]:
    uri = uri.strip()
    if not uri.startswith("vless://"):
        return None
    try:
        body = uri[8:]
        hi   = body.find("#")
        name = urllib.parse.unquote(body[hi+1:]) if hi >= 0 else ""
        main = body[:hi] if hi >= 0 else body

        ai = main.find("@")
        if ai < 0: return None
        uuid = main[:ai]
        rest = main[ai+1:]

        qi = rest.find("?")
        hp = rest[:qi] if qi >= 0 else rest
        qs = rest[qi+1:] if qi >= 0 else ""

        if hp.startswith("["):
            cb = hp.find("]")
            if cb < 0: return None
            host = hp[1:cb]
            port = int(hp[cb+2:])
        else:
            lc = hp.rfind(":")
            if lc < 0: return None
            host = hp[:lc]
            port = int(hp[lc+1:])

        if not host or not (1 <= port <= 65535): return None
        if not uuid or len(uuid) < 10: return None

        p = dict(pair.split("=",1) for pair in qs.split("&") if "=" in pair)
        return Vless(uuid=uuid, host=host, port=port, name=name, raw_uri=uri,
                     sni=p.get("sni"), path=p.get("path"),
                     network=p.get("type") or p.get("network"),
                     security=p.get("security") or p.get("tls"),
                     flow=p.get("flow"))
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
                seen.add(k)
                out.append(v)
    return out

def try_b64(text: str) -> str:
    try:
        d = base64.b64decode(text.strip() + "==").decode("utf-8", errors="ignore")
        if any(s in d for s in ("vless://","vmess://","trojan://")): return d
    except Exception: pass
    return text

# ═══════════════════════════ github url discovery ════════════════════════════

_GH_API_HEADERS = {"User-Agent": "vless-parser/4.0",
                   **({"Authorization": f"Bearer {GH_TOKEN}"} if GH_TOKEN else {})}

VLESS_FILE_KEYWORDS = [
    "vless","vmess","trojan","proxy","config","sub","node",
    "free","vpn","server","link","bypass","rkn",
]
VLESS_FILE_SUFFIXES = (".txt", ".base64", ".list")

def _score_path(path: str) -> int:
    """Higher score = more likely a VLESS config file."""
    low = path.lower()
    if not any(low.endswith(s) for s in VLESS_FILE_SUFFIXES):
        return 0
    score = sum(2 for kw in VLESS_FILE_KEYWORDS if kw in low)
    # penalise deep paths a bit
    score -= path.count("/")
    return score

def _gh_tree_candidates(owner: str, repo: str) -> list[str]:
    """
    Use GitHub tree API to enumerate ALL text files in the repo and return
    raw URLs sorted by likelihood of containing VLESS configs.
    Falls back to common file names if API fails.
    """
    for branch in ("main", "master", "HEAD"):
        try:
            req = urllib.request.Request(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1",
                headers=_GH_API_HEADERS,
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            if "tree" not in data:
                continue

            scored: list[tuple[int,str]] = []
            for item in data["tree"]:
                if item.get("type") != "blob": continue
                s = _score_path(item["path"])
                if s > 0:
                    scored.append((s, item["path"]))

            if not scored:
                continue

            scored.sort(key=lambda x: -x[0])
            base = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}"
            return [f"{base}/{path}" for _, path in scored]

        except Exception:
            continue

    # fallback
    candidates = []
    for branch in ("main", "master"):
        for fname in (
            "vless.txt","configs.txt","config.txt","sub.txt","subscription.txt",
            "proxies.txt","nodes.txt","free.txt","vpn.txt","proxy.txt",
            "output/vless.txt","output/configs.txt","result/vless.txt",
            "data/vless.txt","subs/vless.txt","v2ray.txt","links.txt",
        ):
            candidates.append(
                f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{fname}"
            )
    return candidates

def resolve_urls(url: str) -> list[str]:
    """Resolve any URL (raw, repo link, direct) to a list of candidate raw URLs."""
    # Already raw
    if "raw.githubusercontent.com" in url:
        return [url]
    # Fix malformed
    if url.startswith("://"):
        url = "https:" + url
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    netloc  = parsed.netloc.lower()

    if netloc not in ("github.com", "www.github.com"):
        return [url]   # non-github URL → try as-is

    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return []

    owner, repo = parts[0], parts[1]

    # Direct file link
    if len(parts) > 3 and parts[2] in ("blob", "raw"):
        branch    = parts[3]
        file_path = "/".join(parts[4:])
        return [f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"]

    return _gh_tree_candidates(owner, repo)

# ═══════════════════════════ fetching ════════════════════════════════════════

def fetch(url: str) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            raw = resp.read(20 * 1024 * 1024)   # 20 MB cap
            return try_b64(raw.decode("utf-8", errors="ignore"))
    except Exception:
        return None

def fetch_source(url: str) -> list[Vless]:
    """Fetch a source URL (or repo) and return unique VLESS configs."""
    candidates = resolve_urls(url)
    for cand in candidates:
        text = fetch(cand)
        if text:
            cfgs = extract_from_text(text)
            if cfgs:
                return cfgs
    return []

# ═══════════════════════════ geo / naming ════════════════════════════════════

_geo_cache: dict[str, str] = {}

def _flag(code: str) -> str:
    try:    return "".join(chr(ord(c)+127397) for c in code.upper())
    except: return "🌐"

def get_flag(host: str) -> str:
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
            f    = _flag(code) if code else "🌐"
    except Exception:
        f = "🌐"
    _geo_cache[host] = f
    return f

def named_uri(cfg: Vless, flag: str) -> str:
    name = f"{flag} {CONFIG_NAME}"
    base = cfg.raw_uri.split("#")[0]
    return f"{base}#{urllib.parse.quote(name)}"

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
    sem  = asyncio.Semaphore(TCP_CONCURRENCY)
    out  = []
    async def one(c: Vless):
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
    return c.cfg.security in ("tls", "reality") or c.cfg.port in (
        443, 8443, 2053, 2083, 2087, 2096, 8080, 80
    )

def stage_tls(tcp_results: list[Checked]) -> list[Checked]:
    tls_cands   = [c for c in tcp_results if c.tcp_ok and _needs_tls(c)]
    plain_pass  = [c for c in tcp_results if c.tcp_ok and not _needs_tls(c)]
    print(f"    TLS candidates: {len(tls_cands)}  plain TCP: {len(plain_pass)}")

    tls_out = []
    def one(c: Checked) -> Checked:
        ok, ms  = _tls(c.cfg.host, c.cfg.port, c.cfg.sni, TLS_TIMEOUT)
        c.tls_ok = ok
        if ok: c.latency, c.stage = ms, "tls"
        return c

    with ThreadPoolExecutor(max_workers=TLS_CONCURRENCY) as ex:
        for res in as_completed({ex.submit(one, c): c for c in tls_cands}):
            tls_out.append(res.result())

    return tls_out + plain_pass

# ═══════════════════════════ stage 3: xray (threaded) ════════════════════════

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

    if cfg.security in ("tls", "reality"):
        stream["security"] = cfg.security
        stream["tlsSettings"] = {
            "serverName": cfg.sni or cfg.host,
            "allowInsecure": True,
            "fingerprint": "chrome",
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"tag":"socks","protocol":"socks","listen":"127.0.0.1",
                      "port": port,"settings":{"auth":"noauth","udp":False}}],
        "outbounds": [
            {"tag":"proxy","protocol":"vless",
             "settings":{"vnext":[{"address":cfg.host,"port":cfg.port,
                "users":[{"id":cfg.uuid,"flow":cfg.flow or "","encryption":"none"}]}]},
             "streamSettings": stream},
            {"tag":"direct","protocol":"freedom"},
        ],
        "routing":{"domainStrategy":"AsIs",
                   "rules":[{"type":"field","outboundTag":"proxy","port":"0-65535"}]},
    }

def _wait_port(port: int, tries: int = 30, delay: float = 0.12) -> bool:
    for _ in range(tries):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
            s.close(); return True
        except Exception:
            time.sleep(delay)
    return False

def _xray_one(cfg: Vless, xray_bin: str) -> tuple[bool, float]:
    port = random.randint(20000, 59999)
    tmp  = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    try:
        json.dump(_xray_cfg(cfg, port), tmp); tmp.close()
        proc = subprocess.Popen([xray_bin, "run", "-c", tmp.name],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_port(port):
            proc.terminate(); return False, 9999.0

        t0 = time.time()
        try:
            r = subprocess.run(
                ["curl","-s","-o","/dev/null","-w","%{http_code}",
                 "--proxy", f"socks5://127.0.0.1:{port}",
                 "--max-time", str(XRAY_TIMEOUT),
                 "--connect-timeout","5", TEST_URL],
                capture_output=True, timeout=XRAY_TIMEOUT+3, text=True)
            ms = (time.time() - t0) * 1000
            return r.returncode == 0 and r.stdout.strip() == "204", ms
        except Exception:
            return False, 9999.0
        finally:
            proc.terminate()
            try: proc.wait(timeout=2)
            except Exception: proc.kill()
    finally:
        try: os.unlink(tmp.name)
        except: pass

def stage_xray(candidates: list[Checked], xray_bin: str) -> list[Checked]:
    out  = []
    done = 0
    def one(c: Checked) -> Checked:
        ok, ms  = _xray_one(c.cfg, xray_bin)
        c.xray_ok = ok
        if ok: c.latency, c.stage = ms, "xray"
        return c

    with ThreadPoolExecutor(max_workers=XRAY_CONCURRENCY) as ex:
        futures = {ex.submit(one, c): c for c in candidates}
        for fut in as_completed(futures):
            done += 1
            if done % 25 == 0:
                xok = sum(1 for x in out if x.xray_ok)
                print(f"    Xray {done}/{len(candidates)} — confirmed so far: {xok}")
            out.append(fut.result())
    return out

# ═══════════════════════════ helpers ═════════════════════════════════════════

def read_sources() -> list[str]:
    try:
        with open("source.txt", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    except FileNotFoundError:
        print("[ERROR] source.txt not found"); sys.exit(1)

def is_working(c: Checked) -> bool:
    if c.xray_ok is True: return True
    if c.xray_ok is None and c.tls_ok is True: return True
    if c.xray_ok is None and c.tls_ok is None and c.tcp_ok: return True
    return False

def is_tcptls(c: Checked) -> bool:
    """Passed at least TCP, and TLS if applicable."""
    if c.tls_ok is True: return True
    if c.tls_ok is None and c.tcp_ok: return True
    return False

def write_list(configs: list[Checked], fname: str, limit: int) -> int:
    configs = sorted(configs, key=lambda c: c.latency)[:limit]
    print(f"  Geo lookup for {len(configs)} configs → {fname} ...")
    lines = []
    for i, c in enumerate(configs, 1):
        if i % 100 == 0: print(f"    {i}/{len(configs)}")
        lines.append(named_uri(c.cfg, get_flag(c.cfg.host)))
    with open(fname, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    b64name = fname.replace(".txt", "_base64.txt")
    with open(b64name, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(lines).encode()).decode() + "\n")
    return len(lines)

# ═══════════════════════════ main ════════════════════════════════════════════

async def main() -> None:
    print(f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}] VLESS Parser v4")
    xray_ok = os.path.isfile(XRAY_PATH) and os.access(XRAY_PATH, os.X_OK)
    gh_auth = "✓ authenticated" if GH_TOKEN else "✗ anonymous (60 req/h limit)"
    print(f"  Xray  : {'✓ ' + XRAY_PATH if xray_ok else '✗ not found'}")
    print(f"  GitHub: {gh_auth}")

    sources = read_sources()
    print(f"  Sources: {len(sources)}\n")

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
        if added or (i % 50 == 0):
            print(f"  [{i:>3}/{len(sources)}] +{added:<5} total={len(all_cfgs):<7}  {url[:70]}")

    print(f"\n  Total unique VLESS configs fetched: {len(all_cfgs)}")
    if not all_cfgs:
        print("[WARN] No configs — exiting."); return

    # ── STAGE 1: TCP ──────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"Stage 1 — TCP  (conc={TCP_CONCURRENCY}, timeout={TCP_TIMEOUT}s)")
    tcp_res  = await stage_tcp(all_cfgs)
    tcp_pass = [c for c in tcp_res if c.tcp_ok]
    print(f"  Passing: {len(tcp_pass)} / {len(all_cfgs)}")

    # ── STAGE 2: TLS ──────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"Stage 2 — TLS  (conc={TLS_CONCURRENCY}, timeout={TLS_TIMEOUT}s)")
    tls_res  = stage_tls(tcp_res)
    tcptls_passing = [c for c in tls_res if is_tcptls(c)]
    tcptls_passing.sort(key=lambda c: c.latency)
    tls_confirmed  = sum(1 for c in tls_res if c.tls_ok)
    print(f"  TLS confirmed: {tls_confirmed}   Total TCP+TLS pool: {len(tcptls_passing)}")

    # ── STAGE 3: XRAY ─────────────────────────────────────────────────────────
    xray_confirmed = 0
    xray_res: list[Checked] = []

    if xray_ok:
        # Feed top 600 by latency (avoids burning too much time)
        xray_input = tcptls_passing[:600]
        print(f"\n{'─'*60}")
        print(f"Stage 3 — Xray (conc={XRAY_CONCURRENCY}, timeout={XRAY_TIMEOUT}s)")
        print(f"  Testing {len(xray_input)} candidates ...")
        xray_res       = stage_xray(xray_input, XRAY_PATH)
        xray_confirmed = sum(1 for c in xray_res if c.xray_ok)
        print(f"  Xray confirmed: {xray_confirmed} / {len(xray_input)}")
    else:
        print("\n── Stage 3 skipped (no xray binary) ──")

    # ── WRITE OUTPUT ──────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("Writing output files ...")

    # Xray list (top 200, only xray-confirmed if xray ran, else tcptls)
    if xray_ok and xray_confirmed > 0:
        xray_pool = [c for c in xray_res if c.xray_ok]
    else:
        xray_pool = tcptls_passing

    n_xray   = write_list(xray_pool,   "OSTATSYA_NA_SVYAZI.txt",        MAX_XRAY)
    n_tcptls = write_list(tcptls_passing, "OSTATSYA_NA_SVYAZI_tcptls.txt", MAX_TCPTLS)

    # stats
    stats = {
        "updated_at":     datetime.now(timezone.utc).isoformat(),
        "sources_count":  len(sources),
        "total_fetched":  len(all_cfgs),
        "tcp_passing":    len(tcp_pass),
        "tls_confirmed":  tls_confirmed,
        "xray_confirmed": xray_confirmed,
        "output_xray":    n_xray,
        "output_tcptls":  n_tcptls,
        "xray_used":      xray_ok,
        "success_rate":   round(len(tcp_pass)/len(all_cfgs)*100, 1) if all_cfgs else 0,
    }
    with open("stats.json","w",encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    stage_cnt = {
        k: sum(1 for c in xray_pool[:n_xray] if c.stage==k)
        for k in ("tcp","tls","xray")
    }
    print(f"""
  ✓ OSTATSYA_NA_SVYAZI.txt             — {n_xray} configs (stage: {stage_cnt})
  ✓ OSTATSYA_NA_SVYAZI_base64.txt      — base64
  ✓ OSTATSYA_NA_SVYAZI_tcptls.txt      — {n_tcptls} configs
  ✓ OSTATSYA_NA_SVYAZI_tcptls_base64.txt
  ✓ stats.json
  Done ✓  fetched={len(all_cfgs)}  tcp={len(tcp_pass)}  tls={tls_confirmed}  xray={xray_confirmed}
""")

if __name__ == "__main__":
    asyncio.run(main())
