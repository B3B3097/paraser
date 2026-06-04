#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VLESS Parser с реальной HTTP-проверкой через Xray / Sing-box
ТГК: @Remainingconnections
Подпись: ОСТАТЬСЯ НА СВЯЗИ 🛜
"""

import os
import re
import json
import time
import socket
import base64
import urllib.request
import urllib.parse
import tempfile
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= КОНФИГУРАЦИЯ =================
CONFIG = {
    'source_file': 'source.txt',          # файл со списком URL подписок
    'input_file': 'input.txt',            # не используется, оставлено для совместимости
    'output_file': 'output.txt',          # результат (рабочие конфиги)
    'test_url': 'https://www.google.com', # URL для проверки через прокси
    'ip_api': 'http://ip-api.com/json/',  # API для определения страны по IP
    'max_threads': 30,                    # количество потоков
    'http_timeout': 8,                    # таймаут HTTP-запроса через прокси
    'tcp_timeout': 2,                     # таймаут TCP-пинга
    'check_tcp': True,                    # предварительная TCP-проверка
    'use_singbox': True,                  # использовать sing-box
    'use_xray': True,                     # использовать xray
    'save_failed': False,                 # не сохранять нерабочие
    'subscription_name': 'ОСТАТЬСЯ НА СВЯЗИ 🛜',  # название подписки
    'add_flags': True                     # добавлять флаг страны
}

# Маппинг кодов стран к эмодзи-флагам
COUNTRY_FLAGS = {
    'US': '🇺🇸', 'GB': '🇬🇧', 'DE': '🇩🇪', 'FR': '🇫🇷', 'NL': '🇳🇱',
    'CA': '🇨🇦', 'AU': '🇦🇺', 'JP': '🇯🇵', 'SG': '🇸🇬', 'KR': '🇰🇷',
    'RU': '🇷🇺', 'UA': '🇺🇦', 'PL': '🇵🇱', 'IT': '🇮🇹', 'ES': '🇪🇸',
    'TR': '🇹🇷', 'IN': '🇮🇳', 'BR': '🇧🇷', 'MX': '🇲🇽', 'AR': '🇦🇷',
    'CN': '🇨🇳', 'HK': '🇭🇰', 'TW': '🇹🇼', 'FI': '🇫🇮', 'SE': '🇸🇪',
    'NO': '🇳🇴', 'DK': '🇩🇰', 'CH': '🇨🇭', 'AT': '🇦🇹', 'BE': '🇧🇪',
    'IE': '🇮🇪', 'PT': '🇵🇹', 'GR': '🇬🇷', 'CZ': '🇨🇿', 'RO': '🇷🇴',
    'HU': '🇭🇺', 'BG': '🇧🇬', 'HR': '🇭🇷', 'RS': '🇷🇸', 'SK': '🇸🇰',
    'IL': '🇮🇱', 'AE': '🇦🇪', 'SA': '🇸🇦', 'EG': '🇪🇬', 'ZA': '🇿🇦'
}

# ================= ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =================

def find_binary(name):
    """Поиск бинарного файла ядра (в ./bin, в текущей папке, в PATH)"""
    names = [name, f"{name}.exe"] if os.name == 'nt' else [name]
    for n in names:
        # Проверяем локальные пути
        paths = [f"./bin/{n}", f"./{n}", n]
        for p in paths:
            if os.path.exists(p) and (os.access(p, os.X_OK) or os.name == 'nt'):
                return p
    # Поиск через shutil.which
    import shutil
    return shutil.which(name)

def get_free_port():
    """Возвращает свободный TCP-порт"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def wait_for_port(port, timeout=5):
    """Ожидание, когда порт начнёт слушать (для прокси)"""
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex(('127.0.0.1', port)) == 0:
                sock.close()
                return True
            sock.close()
        except:
            pass
        time.sleep(0.2)
    return False

def get_country_flag(ip):
    """Получение флага страны по IP-адресу"""
    if not CONFIG['add_flags']:
        return ''
    try:
        req = urllib.request.Request(
            f"{CONFIG['ip_api']}{ip}",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            country_code = data.get('countryCode', '')
            return COUNTRY_FLAGS.get(country_code, '🏴')
    except:
        return '🏴'

def tcp_check(host, port, timeout=2):
    """Быстрая TCP-проверка доступности порта"""
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        latency = (time.time() - start) * 1000
        sock.close()
        return result == 0, latency
    except:
        return False, None

# ================= ГЕНЕРАЦИЯ КОНФИГОВ ДЛЯ ЯДЕР =================

def generate_xray_config(cfg, http_port):
    """Генерация временного конфига для Xray"""
    params = cfg['params']
    security = params.get('security', 'none')
    net = params.get('type', 'tcp')
    
    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": cfg['address'],
                "port": cfg['port'],
                "users": [{
                    "id": cfg['uuid'],
                    "encryption": "none",
                    "flow": params.get('flow', '')
                }]
            }]
        },
        "streamSettings": {
            "network": net,
            "security": security
        },
        "tag": "proxy"
    }
    
    ss = outbound["streamSettings"]
    if security == "tls":
        ss["tlsSettings"] = {
            "serverName": params.get('sni', cfg['address']),
            "allowInsecure": True
        }
    elif security == "reality":
        ss["realitySettings"] = {
            "serverName": params.get('sni', cfg['address']),
            "publicKey": params.get('pbk', ''),
            "shortId": params.get('sid', ''),
            "fingerprint": params.get('fp', 'chrome')
        }
        
    if net == "ws":
        ss["wsSettings"] = {
            "path": params.get('path', '/'),
            "headers": {"Host": params.get('host', params.get('sni', cfg['address']))}
        }
    elif net == "tcp" and params.get('headerType') == 'http':
        ss["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {"headers": {"Host": params.get('host', params.get('sni', cfg['address']))}}
            }
        }
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": params.get('serviceName', '')}
    elif net == "http":
        ss["httpSettings"] = {
            "host": [params.get('host', params.get('sni', cfg['address']))],
            "path": params.get('path', '/')
        }
        
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": http_port,
            "protocol": "http",
            "listen": "127.0.0.1",
            "settings": {"timeout": 0}
        }],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
    }

def generate_singbox_config(cfg, http_port):
    """Генерация временного конфига для Sing-box"""
    params = cfg['params']
    security = params.get('security', 'none')
    net = params.get('type', 'tcp')
    
    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": cfg['address'],
        "server_port": cfg['port'],
        "uuid": cfg['uuid'],
        "flow": params.get('flow', '')
    }
    
    if security == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": params.get('sni', cfg['address']),
            "insecure": True,
            "utls": {
                "enabled": True,
                "fingerprint": params.get('fp', 'chrome')
            }
        }
    elif security == "reality":
        outbound["tls"] = {
            "enabled": True,
            "server_name": params.get('sni', cfg['address']),
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
        
    if net == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": params.get('path', '/'),
            "headers": {"Host": params.get('host', params.get('sni', cfg['address']))}
        }
    elif net == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": params.get('serviceName', '')
        }
    elif net == "http":
        outbound["transport"] = {
            "type": "http",
            "host": [params.get('host', params.get('sni', cfg['address']))],
            "path": params.get('path', '/')
        }
        
    return {
        "log": {"level": "silent"},
        "inbounds": [{
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "listen_port": http_port
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}]
    }

def test_with_core(cfg, core_name):
    """
    Реальная проверка через ядро (Xray или Sing-box).
    Возвращает (успех, задержка_мс).
    """
    http_port = get_free_port()
    
    if core_name == 'xray':
        config = generate_xray_config(cfg, http_port)
        binary = find_binary('xray')
        cmd = [binary, "run", "-c"]
    else:
        config = generate_singbox_config(cfg, http_port)
        binary = find_binary('sing-box')
        cmd = [binary, "run", "-c"]
        
    if not binary:
        return False, None
        
    # Создаём временный JSON-файл конфигурации
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as f:
        json.dump(config, f)
        config_path = f.name
        
    try:
        # Запускаем ядро
        proc = subprocess.Popen(
            cmd + [config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Ждём, пока HTTP-прокси начнёт слушать
        if not wait_for_port(http_port, timeout=5):
            proc.terminate()
            return False, None
            
        # Делаем HTTP-запрос через прокси
        start_time = time.time()
        proxy_url = f"http://127.0.0.1:{http_port}"
        proxy_handler = urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        opener = urllib.request.build_opener(proxy_handler)
        
        try:
            req = urllib.request.Request(
                CONFIG['test_url'],
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            with opener.open(req, timeout=CONFIG['http_timeout']) as resp:
                if resp.status == 200:
                    latency = (time.time() - start_time) * 1000
                    return True, latency
        except:
            pass
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except:
                proc.kill()
    finally:
        # Удаляем временный файл
        if os.path.exists(config_path):
            os.unlink(config_path)
    return False, None

# ================= ОСНОВНАЯ ЛОГИКА ПРОВЕРКИ =================

def full_check(config):
    """
    Полная проверка конфига:
    - TCP (опционально)
    - Xray (если доступен)
    - Sing-box (если доступен)
    Возвращает задержку в мс или None, если конфиг нерабочий.
    """
    latencies = []
    
    # 1. Быстрая TCP-проверка (отсекает совсем мёртвые)
    if CONFIG['check_tcp']:
        ok, lat = tcp_check(config['address'], config['port'], CONFIG['tcp_timeout'])
        if not ok:
            return None
        latencies.append(lat)
    
    # 2. Проверка через ядра (хотя бы одно должно подтвердить работу)
    core_ok = False
    if CONFIG.get('use_singbox'):
        ok, lat = test_with_core(config, 'sing-box')
        if ok:
            core_ok = True
            latencies.append(lat)
    if not core_ok and CONFIG.get('use_xray'):
        ok, lat = test_with_core(config, 'xray')
        if ok:
            core_ok = True
            latencies.append(lat)
    
    # 3. Если ни одно ядро не подтвердило – конфиг нерабочий
    if not core_ok:
        return None
        
    # Возвращаем минимальную задержку из всех успешных проверок
    return min(latencies)

# ================= ПАРСИНГ VLESS-ССЫЛОК =================

def parse_vless(link):
    """
    Разбирает VLESS-ссылку на компоненты.
    Возвращает словарь с uuid, address, port, params, remark, original.
    """
    try:
        if not link.startswith('vless://'):
            return None
            
        link = link[8:]  # убираем 'vless://'
        parts = link.split('@')
        if len(parts) != 2:
            return None
            
        uuid = parts[0]
        rest = parts[1]
        
        # Извлекаем параметры после '?'
        params_str = ''
        if '?' in rest:
            rest, params_str = rest.split('?')
        
        # Извлекаем remark после '#'
        remark = ''
        if '#' in rest:
            address_port = rest.split('#')[0]
            remark = urllib.parse.unquote(rest.split('#')[1])
        else:
            address_port = rest
            
        # Разделяем адрес и порт
        if ':' in address_port:
            address, port = address_port.rsplit(':', 1)
            port = int(port)
        else:
            return None
            
        # Парсим параметры
        params = {}
        if params_str:
            params = dict(urllib.parse.parse_qsl(params_str))
            
        # Восстанавливаем оригинальную ссылку (для совместимости)
        original = f"vless://{uuid}@{address}:{port}"
        if params_str:
            original += f"?{params_str}"
        if remark:
            original += f"#{urllib.parse.quote(remark)}"
            
        return {
            'uuid': uuid,
            'address': address,
            'port': port,
            'params': params,
            'remark': remark,
            'original': original
        }
    except Exception:
        return None

# ================= ЗАГРУЗКА ПОДПИСОК =================

def download_subscription(url):
    """Скачивает содержимое подписки (поддерживает base64)"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            # Проверяем, не base64 ли это
            if re.match(r'^[A-Za-z0-9+/=]+$', content.strip()):
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    if decoded:
                        content = decoded
                except:
                    pass
            return content
    except Exception as e:
        print(f"  ⚠️ Ошибка скачивания {url}: {e}")
        return None

def parse_subscriptions():
    """Читает source.txt, скачивает каждую подписку и извлекает vless:// ссылки"""
    if not os.path.exists(CONFIG['source_file']):
        print(f"❌ Файл {CONFIG['source_file']} не найден!")
        return []
    
    with open(CONFIG['source_file'], 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    print(f"📥 Найдено источников: {len(urls)}")
    
    all_links = []
    for i, url in enumerate(urls, 1):
        print(f"  [{i}/{len(urls)}] Скачивание: {url[:60]}...")
        content = download_subscription(url)
        if content:
            # Ищем все строки, начинающиеся с vless://
            lines = content.split('\n')
            vless_links = [line.strip() for line in lines if line.strip().startswith('vless://')]
            # Если ничего не нашли в строках, пробуем найти регуляркой по всему тексту
            if not vless_links:
                pattern = re.compile(r'vless://[a-f0-9\-]{36}@[^/\s?#]+:\d+\?[^\s#]*(?:#[^\s]*)?', re.IGNORECASE)
                vless_links = pattern.findall(content)
            all_links.extend(vless_links)
            print(f"    ✓ Найдено VLESS: {len(vless_links)}")
        else:
            print(f"    ✗ Не удалось загрузить")
    return all_links

# ================= ОБРАБОТКА ОДНОГО КОНФИГА (ДЛЯ ПОТОКОВ) =================

def process_link(link):
    """Обрабатывает одну ссылку: парсит, проверяет, возвращает результат с флагом и новым именем"""
    link = link.strip()
    if not link:
        return None
        
    config = parse_vless(link)
    if not config:
        return None
        
    latency = full_check(config)
    if latency is not None:
        # Получаем флаг страны
        flag = get_country_flag(config['address'])
        
        # Формируем новое имя с флагом и названием подписки
        new_remark = f"{flag} {CONFIG['subscription_name']}"
        
        # Пересобираем ссылку с новым remark
        # Убираем старый remark, если он был
        base_url = config['original'].split('#')[0] if '#' in config['original'] else config['original']
        new_link = f"{base_url}#{urllib.parse.quote(new_remark)}"
        
        return {
            'link': new_link,
            'latency': round(latency, 2),
            'address': config['address'],
            'port': config['port'],
            'flag': flag
        }
    return None

# ================= ОСНОВНАЯ ФУНКЦИЯ =================

def main():
    print("=" * 60)
    print("VLESS Parser с реальной HTTP-проверкой (Xray / Sing-box)")
    print("ТГК: @Remainingconnections")
    print("=" * 60)
    
    # Проверяем наличие бинарников
    singbox_found = find_binary('sing-box') is not None
    xray_found = find_binary('xray') is not None
    
    if not singbox_found and not xray_found:
        print("⚠️  Не найдены бинарники sing-box или xray!")
        print("   Скачайте их и поместите в папку ./bin/ или добавьте в PATH")
        print("   Продолжаем без реальной проверки (только TCP)...")
        CONFIG['use_singbox'] = False
        CONFIG['use_xray'] = False
    else:
        print(f"✓ Sing-box: {'найден' if singbox_found else 'не найден'}")
        print(f"✓ Xray: {'найден' if xray_found else 'не найден'}")
    
    print()
    
    # Парсим подписки
    print("📡 Парсинг источников подписок...")
    links = parse_subscriptions()
    
    if not links:
        print("❌ Не найдено ни одной VLESS ссылки!")
        return
    
    # Удаляем дубликаты
    links = list(set(links))
    print(f"\n📊 Всего уникальных ссылок: {len(links)}")
    print(f"🚀 Запуск проверки в {CONFIG['max_threads']} потока(ов)...")
    print()
    
    results = []
    completed = 0
    
    with ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
        futures = {executor.submit(process_link, link): link for link in links}
        
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            
            if result:
                results.append(result)
                # Выводим прогресс с информацией об успешном конфиге
                print(f"[{completed}/{len(links)}] ✓ {result['flag']} {result['address']}:{result['port']} - {result['latency']:.0f}ms")
            else:
                if completed % 10 == 0 or completed == len(links):
                    print(f"[{completed}/{len(links)}] Обработка...")
    
    # Сортируем по задержке (от самых быстрых)
    results.sort(key=lambda x: x['latency'])
    
    # Сохраняем результат
    with open(CONFIG['output_file'], 'w', encoding='utf-8') as f:
        for r in results:
            f.write(f"{r['link']}\n")
    
    print()
    print("=" * 60)
    print(f"✅ Рабочих конфигураций: {len(results)}")
    print(f"💾 Результаты сохранены в {CONFIG['output_file']}")
    print(f"📛 Название подписки: {CONFIG['subscription_name']}")
    print("=" * 60)

if __name__ == '__main__':
    main()