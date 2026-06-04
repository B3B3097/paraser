#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VLESS MegaParser с реальной HTTP-проверкой через sing-box/xray
Полная версия со всеми функциями
Название подписки: ОСТАТЬСЯ НА СВЯЗИ 🛜
"""

import os
import sys
import re
import json
import time
import socket
import ssl
import base64
import urllib.request
import urllib.parse
import urllib.error
import subprocess
import tempfile
import shutil
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, unquote, parse_qs

# ============================ КОНФИГУРАЦИЯ ============================
CONFIG = {
    'max_configs': 500,
    'tcp_timeout': 2.0,
    'http_timeout': 8.0,
    'max_latency': 2000,
    'max_threads': 30,
    'check_tcp': True,
    'check_http': True,
    'use_singbox': True,
    'use_xray': True,
    'test_url': 'https://www.google.com/generate_204',
    'test_url_fallback': 'http://ip-api.com/json',
    'auto_push': '--push' in sys.argv or os.getenv('GITHUB_ACTIONS') == 'true',
    'bin_dir': './bin',
    'verbose': '--verbose' in sys.argv or os.getenv('GITHUB_ACTIONS') == 'true',
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
    "megafon.ru", "tele2.ru", "yota.ru", "rostelecom.ru", "rt.ru",
    "apple.com", "google.com", "microsoft.com", "whatsapp.com",
    "cloudflare.com", "amazonaws.com", "akamaiedged.net"
}

BLACKLIST_PATTERNS = [
    "@WangCai2", "sni.jpmj.dev", "goo.su", "jet.su", "1.1.1.0",
    "8.6.112.0", "capynode.com", "normbot.ru", "illusion-vpn.ru",
    "prismix.cc", "2.2.2.2", "badvpn.com"
]

OPERATOR_SNI = {
    'beeline': ["beeline.ru", "bilain.ru"],
    'megafon': ["megafon.ru", "meglite.ru"],
    'mts': ["mts.ru", "mass.ru", "mtn.ru"],
    'tele2': ["tele2.ru", "t2.ru"],
    'yota': ["yota.ru", "yota-device.ru"],
    'rostelecom': ["rostelecom.ru"],
}

# Исправленные флаги стран (все эмодзи полные)
COUNTRY_FLAGS = {
    'US': '🇺🇸', 'GB': '🇬🇧', 'DE': '🇩🇪', 'FR': '🇫🇷', 'NL': '🇳🇱',
    'CA': '🇨🇦', 'AU': '🇦🇺', 'JP': '🇯🇵', 'SG': '🇸🇬', 'KR': '🇰🇷',
    'RU': '🇷🇺', 'UA': '🇺🇦', 'PL': '🇵🇱', 'IT': '🇮🇹', 'ES': '🇪🇸',
    'TR': '🇹🇷', 'IN': '🇮🇳', 'BR': '🇧🇷', 'MX': '🇲🇽', 'AR': '🇦🇷',
    'CN': '🇨🇳', 'HK': '🇭🇰', 'TW': '🇹🇼', 'FI': '🇫🇮', 'SE': '🇸🇪',
    'NO': '🇳🇴', 'DK': '🇩🇰', 'CH': '🇨🇭', 'AT': '🇦🇹', 'BE': '🇧🇪',
    'IE': '🇮🇪', 'PT': '🇵🇹', 'GR': '🇬🇷', 'CZ': '🇨🇿', 'RO': '🇷🇴',
    'HU': '🇭🇺', 'BG': '🇧🇬', 'HR': '🇭🇷', 'RS': '🇷🇸', 'SK': '🇸🇰',
    'IL': '🇮🇱', 'AE': '🇦🇪', 'SA': '🇸🇦', 'EG': '🇪🇬', 'ZA': '🇿🇦',
    'KZ': '🇰🇿', 'BY': '🇧🇾', 'MD': '🇲🇩', 'UZ': '🇺🇿', 'GE': '🇬🇪',
    'AM': '🇦🇲', 'AZ': '🇦🇿', 'LT': '🇱🇹', 'LV': '🇱🇻', 'EE': '🇪🇪',
}

SUBSCRIPTION_NAME = "ОСТАТЬСЯ НА СВЯЗИ 🛜"

stats_lock = threading.Lock()
stats = {
    'total_checked': 0,
    'tcp_passed': 0,
    'http_passed': 0,
    'failed': 0
}

def log(message):
    """Вывод лога с временной меткой"""
    if CONFIG['verbose']:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}", flush=True)

def load_extra_lines(filepath, default=None):
    """Загрузка дополнительных строк из файла"""
    if not Path(filepath).exists():
        return default or []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file_handle:
            return [line.strip() for line in file_handle if line.strip() and not line.startswith('#')]
    except Exception:
        return default or []

def fetch_url(url, timeout=15):
    """Получение содержимого URL"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as error:
        log(f"⚠️  Ошибка загрузки {url[:60]}: {error}")
        return None

def base64_decode_safe(data):
    """Безопасное декодирование base64"""
    try:
        data = data.strip()
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return None

def extract_vless_links(text):
    """Извлечение VLESS ссылок из текста"""
    if not text:
        return []
    pattern = re.compile(
        r'vless://[a-f0-9-]{36}@[^\s?#/]+:\d+[^\s#]*(?:#[^\s]*)?',
        re.IGNORECASE
    )
    return pattern.findall(text)

def parse_vless_url(url):
    """Парсинг VLESS URL в словарь параметров"""
    if not url or not url.startswith('vless://'):
        return None

    try:
        rest = url[8:]
        match = re.match(r'([a-f0-9-]{36})@', rest, re.IGNORECASE)
        if not match:
            return None

        uuid = match.group(1)
        rest = rest[match.end():]

        if '?' in rest:
            host_port = rest.split('?')[0]
            query_string = rest.split('?')[1]
        else:
            host_port = rest
            query_string = ''

        fragment = ''
        if '#' in host_port:
            host_port, fragment = host_port.rsplit('#', 1)
        if '#' in query_string:
            query_string, fragment_part = query_string.split('#', 1)
            if not fragment:
                fragment = fragment_part

        if ':' not in host_port:
            return None

        host, port = host_port.rsplit(':', 1)
        port = int(port)

        params = {}
        if query_string:
            parsed_params = parse_qs(query_string)
            for key, values in parsed_params.items():
                params[key] = unquote(values[0]) if values else ''

        return {
            'uuid': uuid,
            'address': host,
            'port': port,
            'params': params,
            'fragment': unquote(fragment) if fragment else '',
            'original_url': url
        }
    except Exception as error:
        log(f"⚠️  Ошибка парсинга URL: {error}")
        return None

def tcp_check(host, port, timeout):
    """TCP проверка порта"""
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        latency = (time.time() - start_time) * 1000
        sock.close()

        if result == 0 and latency <= CONFIG['max_latency']:
            return True, latency
    except Exception:
        pass
    return False, None

def get_country_flag(ip):
    """Получение флага страны по IP"""
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            country_code = data.get('countryCode', '')
            return COUNTRY_FLAGS.get(country_code, '🏴')
    except Exception:
        return '🏴'

def download_and_install_binaries():
    """Скачивание и установка sing-box и xray"""
    bin_dir = Path(CONFIG['bin_dir'])
    bin_dir.mkdir(exist_ok=True)

    log("📥 Проверка наличия бинарников...")

    import platform
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == 'linux':
        if machine in ['x86_64', 'amd64']:
            arch = 'amd64'
        elif machine in ['aarch64', 'arm64']:
            arch = 'arm64'
        elif machine in ['armv7l', 'armv6l']:
            arch = 'armv7'
        else:
            arch = 'amd64'
    else:
        arch = 'amd64'

    singbox_url = f"https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-{arch}.tar.gz"
    xray_url = f"https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-{arch}.zip"

    singbox_path = bin_dir / 'sing-box'
    xray_path = bin_dir / 'xray'

    if not singbox_path.exists() or not os.access(singbox_path, os.X_OK):
        log(f"📥 Скачивание sing-box ({arch})...")
        try:
            import tarfile
            temp_file = bin_dir / 'singbox.tar.gz'
            urllib.request.urlretrieve(singbox_url, temp_file)
            with tarfile.open(temp_file, 'r:gz') as tar:
                tar.extractall(bin_dir)
            temp_file.unlink()
            singbox_path.chmod(0o755)
            log("✓ sing-box установлен")
        except Exception as error:
            log(f"⚠️  Ошибка установки sing-box: {error}")
            singbox_path = None
    else:
        log("✓ sing-box уже установлен")

    if not xray_path.exists() or not os.access(xray_path, os.X_OK):
        log(f"📥 Скачивание xray ({arch})...")
        try:
            import zipfile
            temp_file = bin_dir / 'xray.zip'
            urllib.request.urlretrieve(xray_url, temp_file)
            with zipfile.ZipFile(temp_file, 'r') as zip_ref:
                zip_ref.extractall(bin_dir)
            temp_file.unlink()
            xray_path.chmod(0o755)
            log("✓ xray установлен")
        except Exception as error:
            log(f"⚠️  Ошибка установки xray: {error}")
            xray_path = None
    else:
        log("✓ xray уже установлен")

    return singbox_path, xray_path

def get_free_port():
    """Получение свободного порта"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('', 0))
        sock.listen(1)
        port = sock.getsockname()[1]
    return port

def generate_singbox_config(config_data, http_port):
    """Генерация конфигурации sing-box"""
    params = config_data['params']
    security = params.get('security', 'none')
    network = params.get('type', 'tcp')

    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": config_data['address'],
        "server_port": config_data['port'],
        "uuid": config_data['uuid'],
        "flow": params.get('flow', '')
    }

    if security == 'tls':
        outbound['tls'] = {
            "enabled": True,
            "server_name": params.get('sni', params.get('host', config_data['address'])),
            "insecure": True,
            "utls": {
                "enabled": True,
                "fingerprint": params.get('fp', 'chrome')
            }
        }
    elif security == 'reality':
        outbound['tls'] = {
            "enabled": True,
            "server_name": params.get('sni', params.get('host', config_data['address'])),
            "reality": {
                "enabled": True,
                "public_key": params.get('pbk', ''),
                "short_id": params.get('sid', '')
            },
            "utls": {
                "enabled": True,
                "fingerprint": params.get('fp', 'chrome')
            }
        }

    if network == 'ws':
        outbound['transport'] = {
            "type": "ws",
            "path": params.get('path', '/'),
            "headers": {
                "Host": params.get('host', params.get('sni', config_data['address']))
            }
        }
    elif network == 'grpc':
        outbound['transport'] = {
            "type": "grpc",
            "service_name": params.get('serviceName', '')
        }
    elif network == 'http':
        outbound['transport'] = {
            "type": "http",
            "host": [params.get('host', params.get('sni', config_data['address']))],
            "path": params.get('path', '/')
        }

    config = {
        "log": {"level": "fatal"},
        "inbounds": [
            {
                "type": "http",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": http_port
            }
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"outbound": "proxy"}]}
    }

    return config

def generate_xray_config(config_data, http_port):
    """Генерация конфигурации xray"""
    params = config_data['params']
    security = params.get('security', 'none')
    network = params.get('type', 'tcp')

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": config_data['address'],
                    "port": config_data['port'],
                    "users": [
                        {
                            "id": config_data['uuid'],
                            "encryption": "none",
                            "flow": params.get('flow', '')
                        }
                    ]
                }
            ]
        },
        "streamSettings": {
            "network": network,
            "security": security
        },
        "tag": "proxy"
    }

    stream_settings = outbound['streamSettings']

    if security == 'tls':
        stream_settings['tlsSettings'] = {
            "serverName": params.get('sni', params.get('host', config_data['address'])),
            "allowInsecure": True
        }
    elif security == 'reality':
        stream_settings['realitySettings'] = {
            "serverName": params.get('sni', params.get('host', config_data['address'])),
            "publicKey": params.get('pbk', ''),
            "shortId": params.get('sid', ''),
            "fingerprint": params.get('fp', 'chrome')
        }

    if network == 'ws':
        stream_settings['wsSettings'] = {
            "path": params.get('path', '/'),
            "headers": {
                "Host": params.get('host', params.get('sni', config_data['address']))
            }
        }
    elif network == 'tcp' and params.get('headerType') == 'http':
        stream_settings['tcpSettings'] = {
            "header": {
                "type": "http",
                "request": {
                    "headers": {
                        "Host": [params.get('host', params.get('sni', config_data['address']))]
                    }
                }
            }
        }
    elif network == 'grpc':
        stream_settings['grpcSettings'] = {
            "serviceName": params.get('serviceName', '')
        }
    elif network == 'http':
        stream_settings['httpSettings'] = {
            "host": [params.get('host', params.get('sni', config_data['address']))],
            "path": params.get('path', '/')
        }

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "port": http_port,
                "protocol": "http",
                "listen": "127.0.0.1",
                "settings": {"timeout": 0}
            }
        ],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
    }

    return config

def test_with_singbox(config_data, timeout):
    """HTTP проверка через sing-box"""
    singbox_path = Path(CONFIG['bin_dir']) / 'sing-box'
    if not singbox_path.exists():
        return False, None

    http_port = get_free_port()
    config = generate_singbox_config(config_data, http_port)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as config_file:
        json.dump(config, config_file)
        config_path = config_file.name

    process = None
    try:
        process = subprocess.Popen(
            [str(singbox_path), 'run', '-c', config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(0.8)  # даём время на запуск

        if process.poll() is not None:
            return False, None

        start_time = time.time()
        proxy_url = f"http://127.0.0.1:{http_port}"

        proxy_handler = urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        opener = urllib.request.build_opener(proxy_handler)
        opener.addheaders = [('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')]

        # Первая попытка
        try:
            req = urllib.request.Request(CONFIG['test_url'])
            response = opener.open(req, timeout=timeout)
            if response.status in (200, 204):
                latency = (time.time() - start_time) * 1000
                if latency <= CONFIG['max_latency']:
                    return True, latency
        except Exception:
            pass

        # Вторая попытка (fallback)
        try:
            req = urllib.request.Request(CONFIG['test_url_fallback'])
            response = opener.open(req, timeout=timeout)
            if response.status == 200:
                latency = (time.time() - start_time) * 1000
                if latency <= CONFIG['max_latency']:
                    return True, latency
        except Exception:
            pass

        return False, None

    except Exception as error:
        log(f"⚠️  Ошибка sing-box: {error}")
        return False, None
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        try:
            os.unlink(config_path)
        except Exception:
            pass

def test_with_xray(config_data, timeout):
    """HTTP проверка через xray"""
    xray_path = Path(CONFIG['bin_dir']) / 'xray'
    if not xray_path.exists():
        return False, None

    http_port = get_free_port()
    config = generate_xray_config(config_data, http_port)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as config_file:
        json.dump(config, config_file)
        config_path = config_file.name

    process = None
    try:
        process = subprocess.Popen(
            [str(xray_path), 'run', '-c', config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(1.0)  # xray может стартовать чуть дольше

        if process.poll() is not None:
            return False, None

        start_time = time.time()
        proxy_url = f"http://127.0.0.1:{http_port}"

        proxy_handler = urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        opener = urllib.request.build_opener(proxy_handler)
        opener.addheaders = [('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')]

        try:
            req = urllib.request.Request(CONFIG['test_url'])
            response = opener.open(req, timeout=timeout)
            if response.status in (200, 204):
                latency = (time.time() - start_time) * 1000
                if latency <= CONFIG['max_latency']:
                    return True, latency
        except Exception:
            pass

        try:
            req = urllib.request.Request(CONFIG['test_url_fallback'])
            response = opener.open(req, timeout=timeout)
            if response.status == 200:
                latency = (time.time() - start_time) * 1000
                if latency <= CONFIG['max_latency']:
                    return True, latency
        except Exception:
            pass

        return False, None

    except Exception as error:
        log(f"⚠️  Ошибка xray: {error}")
        return False, None
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        try:
            os.unlink(config_path)
        except Exception:
            pass

def full_check(config_data):
    """Полная проверка конфигурации"""
    global stats

    tcp_latency = None
    http_latency = None

    if CONFIG['check_tcp']:
        tcp_ok, tcp_latency = tcp_check(
            config_data['address'],
            config_data['port'],
            CONFIG['tcp_timeout']
        )

        if not tcp_ok:
            with stats_lock:
                stats['failed'] += 1
            return None

        with stats_lock:
            stats['tcp_passed'] += 1

    if CONFIG['check_http']:
        http_ok = False
        if CONFIG['use_singbox']:
            http_ok, http_latency = test_with_singbox(config_data, CONFIG['http_timeout'])
        if not http_ok and CONFIG['use_xray']:
            http_ok, http_latency = test_with_xray(config_data, CONFIG['http_timeout'])

        if not http_ok:
            with stats_lock:
                stats['failed'] += 1
            return None

        with stats_lock:
            stats['http_passed'] += 1

        return http_latency

    # Если проверка HTTP отключена, возвращаем задержку TCP
    return tcp_latency

def is_blacklisted(config_data, blacklist):
    """Проверка на черный список"""
    full_url = config_data['original_url'].lower()
    for pattern in blacklist:
        if pattern.lower() in full_url:
            return True
    return False

def is_sni_allowed(config_data, whitelist):
    """Проверка разрешенных SNI"""
    sni = config_data['params'].get('sni', '')
    host = config_data['params'].get('host', '')

    for domain in [sni, host]:
        if not domain:
            continue
        if domain in whitelist:
            return True
        for allowed_domain in whitelist:
            if domain.endswith('.' + allowed_domain):
                return True
    return False

def deduplicate_configs(configs):
    """Удаление дубликатов"""
    seen = set()
    unique = []

    for config in configs:
        key = f"{config['uuid']}:{config['address']}:{config['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(config)

    log(f"🔄 Дедупликация: {len(configs)} -> {len(unique)}")
    return unique

def detect_operator(config_data):
    """Определение мобильного оператора"""
    sni = config_data['params'].get('sni', '')
    host = config_data['params'].get('host', '')

    for operator, domains in OPERATOR_SNI.items():
        for domain in domains:
            if domain in sni or domain in host:
                return operator
    return 'unknown'

def format_vless_line(config_data, latency=None, country_flag='🏴'):
    """Форматирование итоговой VLESS ссылки"""
    name_parts = []

    if latency:
        name_parts.append(f"{int(latency)}ms")

    operator = detect_operator(config_data)
    if operator != 'unknown':
        name_parts.append(operator.capitalize())

    name_parts.append(f"{country_flag} {SUBSCRIPTION_NAME}")

    name = " | ".join(name_parts)

    params = []
    for key, value in config_data['params'].items():
        params.append(f"{key}={quote(value)}")
    params_string = '&'.join(params)

    url = f"vless://{config_data['uuid']}@{config_data['address']}:{config_data['port']}"
    if params_string:
        url += f"?{params_string}"
    url += f"#{quote(name)}"

    return url

def load_sources():
    """Загрузка источников из source.txt"""
    sources_file = Path('source.txt')
    if sources_file.exists():
        with open(sources_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        log(f"📚 Загружено {len(urls)} источников из source.txt")
        return urls
    return []

def collect_all_configs():
    """Сбор всех конфигураций из источников"""
    urls = list(SOURCES)
    extra_sources = load_sources()
    urls.extend(extra_sources)

    log(f"📚 Всего источников: {len(urls)}")

    all_links = []
    for i, url in enumerate(urls, 1):
        log(f"📥 [{i}/{len(urls)}] Загрузка: {url[:70]}...")
        content = fetch_url(url)

        if content:
            links = extract_vless_links(content)

            if not links:
                decoded = base64_decode_safe(content)
                if decoded:
                    links = extract_vless_links(decoded)

            all_links.extend(links)
            log(f"  ✓ Найдено VLESS: {len(links)}")

    log(f"📊 Всего сырых ссылок: {len(all_links)}")

    configs = []
    for link in all_links:
        config = parse_vless_url(link)
        if config:
            configs.append(config)

    log(f"✅ Распаршено конфигураций: {len(configs)}")
    return configs

def main():
    """Основная функция"""
    start_time = time.time()

    log("=" * 70)
    log(f"VLESS MegaParser - {SUBSCRIPTION_NAME}")
    log("=" * 70)

    log("🔧 Установка ядер...")
    singbox_path, xray_path = download_and_install_binaries()

    if not singbox_path and not xray_path:
        log("❌ Не удалось установить ни одно ядро!")
        sys.exit(1)

    log(f"✓ Sing-box: {'найден' if singbox_path else 'не найден'}")
    log(f"✓ Xray: {'найден' if xray_path else 'не найден'}")
    log("")

    sni_whitelist = set(DEFAULT_SNI_WHITELIST)
    sni_whitelist.update(load_extra_lines('sni_whitelist.txt'))

    blacklist = list(BLACKLIST_PATTERNS)
    blacklist.extend(load_extra_lines('blacklist.txt'))

    log(f"📋 SNI whitelist: {len(sni_whitelist)} доменов")
    log(f"🚫 Blacklist: {len(blacklist)} паттернов")
    log("")

    all_configs = collect_all_configs()

    if not all_configs:
        log("❌ Не найдено конфигураций!")
        return

    log("🔍 Фильтрация...")
    filtered_configs = []
    for config in all_configs:
        if is_blacklisted(config, blacklist):
            continue
        if not is_sni_allowed(config, sni_whitelist):
            continue
        filtered_configs.append(config)

    log(f"✅ После фильтрации: {len(filtered_configs)}")

    unique_configs = deduplicate_configs(filtered_configs)
    log(f"🎯 Уникальных: {len(unique_configs)}")

    final_configs = unique_configs[:CONFIG['max_configs']]
    log(f"📦 Финальных: {len(final_configs)}")
    log("")

    log("🚀 Запуск проверки...")
    log("")

    results = []
    total = len(final_configs)

    with ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
        futures = {
            executor.submit(full_check, config): config
            for config in final_configs
        }

        completed = 0
        for future in as_completed(futures):
            completed += 1
            config = futures[future]

            try:
                latency = future.result()

                if latency is not None:
                    config['latency'] = latency
                    country_flag = get_country_flag(config['address'])
                    config['flag'] = country_flag
                    results.append(config)

                    operator = detect_operator(config)
                    log(f"[{completed}/{total}] ✅ {country_flag} {config['address']}:{config['port']} - {int(latency)}ms {operator}")
                else:
                    if completed % 10 == 0:
                        log(f"[{completed}/{total}] ⏳ Обработка...")

            except Exception as error:
                log(f"[{completed}/{total}] ❌ Ошибка: {error}")

    results.sort(key=lambda x: x.get('latency', 9999))

    output_lines = []
    for config in results:
        line = format_vless_line(
            config,
            config.get('latency'),
            config.get('flag', '🏴')
        )
        output_lines.append(line)

    output_file = "OSTATSYA_NA_SVYAZI.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))

    base64_content = base64.b64encode(
        '\n'.join(output_lines).encode('utf-8')
    ).decode('utf-8')

    base64_file = "OSTATSYA_NA_SVYAZI_base64.txt"
    with open(base64_file, 'w', encoding='utf-8') as f:
        f.write(base64_content)

    runtime = time.time() - start_time
    statistics = {
        'timestamp': datetime.now().isoformat(),
        'total_raw': len(all_configs),
        'filtered': len(filtered_configs),
        'unique': len(unique_configs),
        'final': len(final_configs),
        'working': len(results),
        'tcp_passed': stats['tcp_passed'],
        'http_passed': stats['http_passed'],
        'failed': stats['failed'],
        'runtime_seconds': round(runtime, 2),
        'subscription_name': SUBSCRIPTION_NAME
    }

    with open('stats.json', 'w', encoding='utf-8') as f:
        json.dump(statistics, f, indent=2, ensure_ascii=False)

    log("")
    log("=" * 70)
    log("📊 СТАТИСТИКА")
    log("=" * 70)
    for key, value in statistics.items():
        log(f"  {key}: {value}")

    log("")
    log(f"💾 Результаты сохранены:")
    log(f"  - {output_file}")
    log(f"  - {base64_file}")
    log(f"  - stats.json")
    log("=" * 70)

    if CONFIG['auto_push']:
        log("")
        log("📤 Push в GitHub...")
        os.system('git config user.name "github-actions[bot]"')
        os.system('git config user.email "github-actions[bot]@users.noreply.github.com"')
        os.system(f'git add "{output_file}" "{base64_file}" stats.json')
        os.system('git diff --quiet && git diff --staged --quiet || git commit -m "Auto-update: ОСТАТЬСЯ НА СВЯЗИ 🛜"')
        os.system('git push')
        log("✓ Push завершен")

    log("")
    log("✅ Готово!")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log("\n⚠️  Остановлено пользователем")
        sys.exit(0)
    except Exception as error:
        log(f"\n❌ Критическая ошибка: {error}")
        import traceback
        traceback.print_exc()
        sys.exit(1)