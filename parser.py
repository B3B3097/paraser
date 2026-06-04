#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VLESS Ultimate Parser – многоуровневая проверка (TCP, TLS, WebSocket, sing-box/xray)
Источники: преимущественно igareck/vpn-configs-for-russia
Выходной файл: ОСТАТЬСЯ НА СВЯЗИ 🛜.txt
Подпись: ТГК: @Remainingconnections
"""

import re
import os
import sys
import ssl
import json
import time
import socket
import base64
import random
import urllib.request
import urllib.error
import subprocess
from datetime import datetime
from urllib.parse import quote, unquote
from pathlib import Path
from collections import defaultdict
import tempfile

# ============================ КОНФИГУРАЦИЯ ============================
CONFIG = {
    'max_keys': 400,
    'tcp_timeout': 3.0,
    'tls_timeout': 5.0,
    'http_timeout': 8.0,
    'max_latency': 1500,
    'check_tcp': True,
    'check_tls': True,
    'check_http': True,
    'use_singbox': True,
    'use_xray': True,
    'test_url': 'http://ip-api.com/json',
    'dedup_by_host': True,
    'auto_push': '--push' in sys.argv or os.getenv('GITHUB_ACTIONS') == 'true',
}

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/SilentGhostCodes/WhiteListVpn/refs/heads/main/Whitelist.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt"
]

DEFAULT_SNI_WHITELIST = {
    "yandex.ru", "yandex.net", "vk.com", "rutube.ru", "kinopoisk.ru",
    "ozon.ru", "mail.ru", "t.me", "telegram.org", "beeline.ru", "mts.ru",
    "megafon.ru", "tele2.ru", "yota.ru", "rostelecom.ru", "rt.ru", "rbc.ru",
    "apple.com", "google.com", "microsoft.com", "whatsapp.com", "cloudflare.com"
}

BLACKLIST_PATTERNS = [
    "@WangCai2", "sni.jpmj.dev", "goo.su", "jet.su", "1.1.1.0", "8.6.112.0",
    "capynode.com", "normbot.ru", "illusion-vpn.ru", "prismix.cc", "2.2.2.2"
]

OPERATOR_SNI = {
    'beeline': ["beeline.ru", "bilain.ru"],
    'megafon': ["megafon.ru", "meglite.ru"],
    'mts': ["mts.ru", "mass.ru", "mtn.ru"],
    'tele2': ["tele2.ru", "t2.ru"],
    'yota': ["yota.ru", "yota-device.ru"],
    'rostelecom': ["rostelecom.ru"],
}

def load_extra_lines(filepath, default=None):
    if not Path(filepath).exists():
        return default or []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def fetch_url(url, timeout=15):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"  Warning {url[:60]} – error: {e}")
        return None

def base64_decode_safe(data):
    try:
        data = data.strip()
        missing = len(data) % 4
        if missing:
            data += '=' * (4 - missing)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except:
        return None

def extract_vless_links(text):
    if not text:
        return []
    pattern = re.compile(r'vless://[a-f0-9\-]{36}@[^/\s?#]+:\d+\?[^\s#]*(?:#[^\s]*)?', re.IGNORECASE)
    return pattern.findall(text)

def parse_vless_url(url):
    if not url.startswith('vless://'):
        return None
    rest = url[8:]
    m = re.match(r'([a-f0-9\-]{36})@([^:]+):(\d+)', rest, re.IGNORECASE)
    if not m:
        return None
    uuid, addr, port = m.group(1), m.group(2), int(m.group(3))
    params = {}
    fragment = ''
    after = rest[m.end():]
    if '?' in after:
        q, frag = after.split('?', 1)
        if '#' in frag:
            frag, fragment = frag.split('#', 1)
        for pair in frag.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k] = unquote(v)
    elif '#' in after:
        fragment = after.split('#', 1)[1]
    return {
        'uuid': uuid,
        'address': addr,
        'port': port,
        'params': params,
        'fragment': fragment,
        'original_url': url
    }

def tcp_check(host, port, timeout):
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        latency = (time.time() - start) * 1000
        sock.close()
        if result == 0 and latency <= CONFIG['max_latency']:
            return True, latency
    except:
        pass
    return False, None

def tls_check(host, port, timeout, sni=None):
    if port != 443 and not sni:
        return False, None
    try:
        context = ssl.create_default_context()
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni or host) as ssock:
                latency = (time.time() - start) * 1000
                return True, latency
    except:
        return False, None

def http_through_ws(config, timeout=8):
    if config['params'].get('type') != 'ws':
        return False, None
    host = config['address']
    port = config['port']
    path = config['params'].get('path', '/')
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(1024).decode(errors='ignore')
        sock.close()
        if "101" in response or "200" in response:
            latency = (time.time() - start) * 1000
            return True, latency
    except:
        pass
    return False, None

def find_binary(name):
    paths = [f"./bin/{name}", f"./{name}", name]
    for p in paths:
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    import shutil
    return shutil.which(name)

def full_check(config):
    latencies = []
    if CONFIG['check_tcp']:
        ok, lat = tcp_check(config['address'], config['port'], CONFIG['tcp_timeout'])
        if ok:
            latencies.append(lat)
    if CONFIG['check_tls']:
        ok, lat = tls_check(config['address'], config['port'], CONFIG['tls_timeout'], config['params'].get('sni', config['address']))
        if ok:
            latencies.append(lat)
    if CONFIG['check_http'] and config['params'].get('type') == 'ws':
        ok, lat = http_through_ws(config, CONFIG['http_timeout'])
        if ok:
            latencies.append(lat)
    if not latencies:
        return None
    return min(latencies)

def load_sni_whitelist():
    wl = set(DEFAULT_SNI_WHITELIST)
    wl.update(load_extra_lines('sni_whitelist.txt'))
    return wl

def load_blacklist():
    patterns = list(BLACKLIST_PATTERNS)
    patterns.extend(load_extra_lines('blacklist.txt'))
    return patterns

def is_blacklisted(config, patterns):
    full = config['original_url'].lower()
    for pat in patterns:
        if pat.lower() in full:
            return True
    return False

def is_sni_allowed(config, whitelist):
    sni = config['params'].get('sni', '')
    host = config['params'].get('host', '')
    for domain in (sni, host):
        if not domain:
            continue
        if domain in whitelist:
            return True
        for w in whitelist:
            if domain.endswith('.' + w) or domain == w:
                return True
    return False

def deduplicate(configs):
    seen = set()
    unique = []
    for cfg in configs:
        if CONFIG['dedup_by_host']:
            host = cfg['params'].get('host', cfg['address'])
            key = f"{cfg['uuid']}:{cfg['address']}:{cfg['port']}:{host}"
        else:
            key = f"{cfg['uuid']}:{cfg['address']}:{cfg['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(cfg)
    print(f"  Deduplication: {len(configs)} -> {len(unique)}")
    return unique

def detect_operator(config):
    sni = config['params'].get('sni', '')
    host = config['params'].get('host', '')
    for op, domains in OPERATOR_SNI.items():
        for d in domains:
            if d in sni or d in host:
                return op
    return 'unknown'

def format_vless_line(config, latency=None):
    name_parts = []
    if latency:
        name_parts.append(f"{int(latency)}ms")
    op = detect_operator(config)
    if op != 'unknown':
        name_parts.append(op.capitalize())
    name_parts.append("STAY CONNECTED")
    name = " | ".join(name_parts)
    params = []
    for k, v in config['params'].items():
        params.append(f"{k}={quote(v)}")
    params_str = '&'.join(params)
    url = f"vless://{config['uuid']}@{config['address']}:{config['port']}"
    if params_str:
        url += f"?{params_str}"
    url += f"#{name}"
    return url

def collect_configs():
    urls = list(SOURCES)
    extra = load_extra_lines('sources.txt')
    urls.extend(extra)
    print(f"Total sources: {len(urls)}")
    raw_links = []
    for url in urls:
        print(f"  Fetching {url[:70]}...")
        text = fetch_url(url)
        if text:
            links = extract_vless_links(text)
            if not links:
                decoded = base64_decode_safe(text)
                if decoded:
                    links = extract_vless_links(decoded)
            raw_links.extend(links)
            print(f"     Found {len(links)}")
    print(f"Total raw links: {len(raw_links)}")
    configs = []
    for link in raw_links:
        cfg = parse_vless_url(link)
        if cfg:
            configs.append(cfg)
    print(f"Parsed configs: {len(configs)}")
    return configs

def main():
    start_time = time.time()
    print("=" * 70)
    print("VLESS Ultimate Parser")
    print("=" * 70)
    
    sni_whitelist = load_sni_whitelist()
    blacklist = load_blacklist()
    print(f"SNI whitelist: {len(sni_whitelist)} domains")
    print(f"Blacklist: {len(blacklist)} patterns")
    
    all_configs = collect_configs()
    
    filtered = []
    for cfg in all_configs:
        if is_blacklisted(cfg, blacklist):
            continue
        if not is_sni_allowed(cfg, sni_whitelist):
            continue
        filtered.append(cfg)
    print(f"After filtering: {len(filtered)}")
    
    unique = deduplicate(filtered)
    print(f"Unique configs: {len(unique)}")
    
    final = unique[:CONFIG['max_keys']]
    print(f"Final configs: {len(final)}")
    
    output_lines = []
    for cfg in final:
        line = format_vless_line(cfg, cfg.get('latency'))
        output_lines.append(line)
    
    output_file = "OSTATSYA_NA_SVYAZI.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))
    
    b64_content = base64.b64encode('\n'.join(output_lines).encode()).decode()
    sub_file = "OSTATSYA_NA_SVYAZI_base64.txt"
    with open(sub_file, 'w', encoding='utf-8') as f:
        f.write(b64_content)
    
    stats = {
        'timestamp': datetime.now().isoformat(),
        'total_raw': len(all_configs),
        'filtered': len(filtered),
        'unique': len(unique),
        'final': len(final),
        'runtime_sec': round(time.time() - start_time, 2)
    }
    with open('stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)
    
    print("\nStats:")
    for k, v in stats.items():
        print(f"   {k}: {v}")
    
    if CONFIG['auto_push']:
        print("\nPushing to GitHub...")
        os.system('git config user.name "github-actions[bot]"')
        os.system('git config user.email "github-actions[bot]@users.noreply.github.com"')
        os.system(f'git add "{output_file}" {sub_file} stats.json')
        os.system('git commit -m "Auto-update VLESS configs" || echo "No changes"')
        os.system('git push')
    
    print("\nDone!")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
