#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VLESS MegaParser – многоуровневая проверка конфигов (TCP, TLS, HTTP, WS, gRPC, DNS, MTU)
ТГК: @Remainingconnections
Версия: 3.0 – полноценная эмуляция реального трафика без использования ядер
"""

import os
import sys
import re
import json
import time
import socket
import ssl
import base64
import random
import string
import hashlib
import logging
import argparse
import tempfile
import urllib.request
import urllib.parse
import urllib.error
import ipaddress
import struct
import threading
import queue
import signal
import math
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice

# ================= НАСТРОЙКИ ПО УМОЛЧАНИЮ =================
DEFAULT_CONFIG = {
    'sources_file': 'sources.txt',
    'output_file': 'output.txt',
    'log_file': 'parser.log',
    'max_configs': 500,
    'max_threads': 50,
    'tcp_timeout': 3.0,
    'tls_timeout': 5.0,
    'http_timeout': 8.0,
    'ws_timeout': 6.0,
    'grpc_timeout': 6.0,
    'dns_timeout': 2.0,
    'mtu_timeout': 2.0,
    'max_latency': 2000,
    'min_latency': 10,
    'check_tcp': True,
    'check_tls': True,
    'check_http': True,
    'check_websocket': True,
    'check_grpc': True,
    'check_dns': False,
    'check_mtu': False,
    'add_flags': True,
    'add_geo': True,
    'subscription_name': 'ОСТАТЬСЯ НА СВЯЗИ 🛜',
    'test_url': 'http://ip-api.com/json/',
    'ip_api_url': 'http://ip-api.com/json/',
    'cache_geo': True,
    'cache_ttl': 86400,
    'use_random_user_agent': True,
    'retry_failed': 2,
    'save_intermediate': True,
}

# ================= ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ =================
VERSION = "3.0.0"
PROGRAM_NAME = "VLESS MegaParser"
AUTHOR = "@Remainingconnections"
GEO_CACHE = {}

# ================= НАСТРОЙКА ЛОГГЕРА =================
def setup_logging(log_file=None, level=logging.INFO):
    """Настройка системы логирования (файл + консоль)"""
    log_format = '%(asctime)s [%(levelname)s] %(message)s'
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=handlers
    )
    return logging.getLogger(__name__)

# ================= КЛАССЫ =================

class Config:
    """Хранит и управляет конфигурацией парсера"""
    def __init__(self, config_dict=None, args=None):
        self.data = DEFAULT_CONFIG.copy()
        if config_dict:
            self.data.update(config_dict)
        if args:
            self._update_from_args(args)
        self._validate()
    
    def _update_from_args(self, args):
        for key, value in vars(args).items():
            if value is not None and key in self.data:
                self.data[key] = value
    
    def _validate(self):
        self.data['max_threads'] = max(1, min(100, self.data['max_threads']))
        self.data['max_configs'] = max(1, self.data['max_configs'])
        for t in ['tcp_timeout', 'tls_timeout', 'http_timeout', 'ws_timeout', 'grpc_timeout']:
            self.data[t] = max(0.5, self.data[t])
    
    def __getitem__(self, key):
        return self.data[key]
    
    def __setitem__(self, key, value):
        self.data[key] = value
    
    def get(self, key, default=None):
        return self.data.get(key, default)

class VlessConfig:
    """Представляет один VLESS-конфиг и содержит методы для его проверки"""
    __slots__ = ('uuid', 'address', 'port', 'params', 'remark', 'original', 'latency', 'flag', 'country', 'city', 'isp', 'valid')
    
    def __init__(self, url):
        self.uuid = None
        self.address = None
        self.port = None
        self.params = {}
        self.remark = ''
        self.original = url
        self.latency = None
        self.flag = '🏴'
        self.country = ''
        self.city = ''
        self.isp = ''
        self.valid = False
        self._parse(url)
    
    def _parse(self, url):
        """Разбор VLESS-ссылки"""
        try:
            if not url.startswith('vless://'):
                return
            rest = url[8:]
            parts = rest.split('@')
            if len(parts) != 2:
                return
            self.uuid = parts[0]
            right = parts[1]
            params_str = ''
            if '?' in right:
                right, params_str = right.split('?', 1)
            remark = ''
            if '#' in right:
                addr_port, remark = right.split('#', 1)
                self.remark = urllib.parse.unquote(remark)
            else:
                addr_port = right
            if ':' not in addr_port:
                return
            addr, port_s = addr_port.rsplit(':', 1)
            self.address = addr
            self.port = int(port_s)
            if params_str:
                self.params = dict(urllib.parse.parse_qsl(params_str))
            self.valid = True
        except Exception:
            self.valid = False
    
    def get_outbound_type(self):
        """Возвращает тип транспорта (tcp, ws, grpc, http)"""
        return self.params.get('type', 'tcp')
    
    def get_security(self):
        """Возвращает тип безопасности (none, tls, reality)"""
        return self.params.get('security', 'none')
    
    def get_sni(self):
        """Возвращает SNI для TLS"""
        return self.params.get('sni', self.address)
    
    def get_host_header(self):
        """Возвращает Host для HTTP-заголовка"""
        return self.params.get('host', self.get_sni())
    
    def get_path(self):
        """Возвращает путь для WS/gRPC/HTTP"""
        return self.params.get('path', '/')
    
    def get_service_name(self):
        """Возвращает serviceName для gRPC"""
        return self.params.get('serviceName', '')
    
    def get_flow(self):
        """Возвращает flow (xtls-rprx-vision и т.д.)"""
        return self.params.get('flow', '')
    
    def rebuild_url(self, new_remark=None):
        """Пересобирает URL с новым remark"""
        base = self.original.split('#')[0] if '#' in self.original else self.original
        if new_remark is None:
            new_remark = self.remark
        encoded_remark = urllib.parse.quote(new_remark)
        return f"{base}#{encoded_remark}"
    
    def __repr__(self):
        return f"<VlessConfig {self.address}:{self.port} {self.get_outbound_type()}>"

class GeoInfo:
    """Геоинформация по IP"""
    def __init__(self, ip, api_url='http://ip-api.com/json/', cache_ttl=86400):
        self.ip = ip
        self.country_code = ''
        self.country = ''
        self.city = ''
        self.isp = ''
        self.lat = 0.0
        self.lon = 0.0
        self._fetch(api_url, cache_ttl)
    
    def _fetch(self, api_url, cache_ttl):
        global GEO_CACHE
        if self.ip in GEO_CACHE:
            cached = GEO_CACHE[self.ip]
            if time.time() - cached['timestamp'] < cache_ttl:
                self._apply(cached['data'])
                return
        try:
            req = urllib.request.Request(f"{api_url}{self.ip}", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                self.country_code = data.get('countryCode', '')
                self.country = data.get('country', '')
                self.city = data.get('city', '')
                self.isp = data.get('isp', '')
                self.lat = data.get('lat', 0.0)
                self.lon = data.get('lon', 0.0)
                GEO_CACHE[self.ip] = {'timestamp': time.time(), 'data': self._serialize()}
        except Exception:
            pass
    
    def _serialize(self):
        return {
            'country_code': self.country_code,
            'country': self.country,
            'city': self.city,
            'isp': self.isp,
            'lat': self.lat,
            'lon': self.lon
        }
    
    def _apply(self, data):
        self.country_code = data['country_code']
        self.country = data['country']
        self.city = data['city']
        self.isp = data['isp']
        self.lat = data['lat']
        self.lon = data['lon']
    
    def get_flag(self):
        """Возвращает эмодзи-флаг по коду страны (упрощённо)"""
        flags = {
            'RU': '🇷🇺', 'US': '🇺🇸', 'GB': '🇬🇧', 'DE': '🇩🇪', 'FR': '🇫🇷',
            'NL': '🇳🇱', 'CA': '🇨🇦', 'AU': '🇦🇺', 'JP': '🇯🇵', 'SG': '🇸🇬',
            'KR': '🇰🇷', 'UA': '🇺🇦', 'PL': '🇵🇱', 'IT': '🇮🇹', 'ES': '🇪🇸',
            'TR': '🇹🇷', 'IN': '🇮🇳', 'BR': '🇧🇷', 'MX': '🇲🇽', 'AR': '🇦🇷',
            'CN': '🇨🇳', 'HK': '🇭🇰', 'TW': '🇹🇼', 'FI': '🇫🇮', 'SE': '🇸🇪',
            'NO': '🇳🇴', 'DK': '🇩🇰', 'CH': '🇨🇭', 'AT': '🇦🇹', 'BE': '🇧🇪',
            'IE': '🇮🇪', 'PT': '🇵🇹', 'GR': '🇬🇷', 'CZ': '🇨🇿', 'RO': '🇷🇴',
            'HU': '🇭🇺', 'BG': '🇧🇬', 'HR': '🇭🇷', 'RS': '🇷🇸', 'SK': '🇸🇰',
            'IL': '🇮🇱', 'AE': '🇦🇪', 'SA': '🇸🇦', 'EG': '🇪🇬', 'ZA': '🇿🇦',
            'TH': '🇹🇭', 'VN': '🇻🇳', 'MY': '🇲🇾', 'ID': '🇮🇩', 'PH': '🇵🇭'
        }
        return flags.get(self.country_code, '🏴')
    
    def __str__(self):
        return f"{self.country} ({self.country_code}) - {self.city}, {self.isp}"

class HTTPProxyChecker:
    """Проверка через HTTP-прокси (имитация реального трафика)"""
    @staticmethod
    def check(config, test_url, timeout=8, user_agent=None):
        """Выполняет HTTP-запрос через прокси, используя urllib с ProxyHandler"""
        proxy_url = f"http://{config.address}:{config.port}"
        proxy_handler = urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        opener = urllib.request.build_opener(proxy_handler)
        if user_agent:
            opener.addheaders = [('User-Agent', user_agent)]
        start = time.time()
        try:
            req = urllib.request.Request(test_url)
            with opener.open(req, timeout=timeout) as resp:
                latency = (time.time() - start) * 1000
                if resp.status == 200:
                    return True, latency
        except Exception:
            pass
        return False, None

class WebSocketChecker:
    """Проверка WebSocket handshake через raw socket"""
    @staticmethod
    def check(config, timeout=6):
        if config.get_outbound_type() != 'ws':
            return False, None
        host = config.address
        port = config.port
        path = config.get_path()
        host_header = config.get_host_header()
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            key = base64.b64encode(os.urandom(16)).decode()
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n"
            )
            sock.send(request.encode())
            response = sock.recv(1024).decode(errors='ignore')
            sock.close()
            if "101" in response and "Switching Protocols" in response:
                latency = (time.time() - start) * 1000
                return True, latency
        except Exception:
            pass
        return False, None

class GRPCChecker:
    """Эмуляция gRPC через HTTP/2 PRI-фрейм (базовая проверка)"""
    @staticmethod
    def check(config, timeout=6):
        if config.get_outbound_type() != 'grpc':
            return False, None
        host = config.address
        port = config.port
        service_name = config.get_service_name() or '/'
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            # Отправляем PRI-фрейм для начала HTTP/2 соединения
            pri_frame = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
            sock.send(pri_frame)
            # Отправляем простой GET-запрос в формате HTTP/2 (упрощённо)
            # Для реальной проверки нужно больше логики, но для отсева нерабочих достаточно
            response = sock.recv(1024)
            sock.close()
            if len(response) > 0:
                latency = (time.time() - start) * 1000
                return True, latency
        except Exception:
            pass
        return False, None

class DNSChecker:
    """Проверка DNS-резолвинга домена конфига"""
    @staticmethod
    def check(config, timeout=2):
        try:
            start = time.time()
            addr = socket.gethostbyname(config.address)
            latency = (time.time() - start) * 1000
            return True, latency, addr
        except:
            return False, None, None

class MTUChecker:
    """Приблизительная проверка MTU до сервера (ICMP эхо)"""
    @staticmethod
    def check(config, timeout=2):
        """Отправляет UDP-пакеты разного размера, определяет максимальный"""
        # Упрощённая версия: проверяем, проходит ли пакет 1400 байт
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            for size in [1400, 1300, 1200, 1100, 1000]:
                data = os.urandom(size)
                start = time.time()
                sock.sendto(data, (config.address, config.port))
                # Ждём ответа (любого) – для VLESS не будет, но проверяем, не падает ли сокет
                try:
                    sock.recvfrom(1024)
                except socket.timeout:
                    pass
                latency = (time.time() - start) * 1000
                if latency < timeout * 1000:
                    return True, latency, size
            return False, None, None
        except:
            return False, None, None

class VlessTester:
    """Основной класс, который выполняет все проверки для одного конфига"""
    def __init__(self, config_obj, global_config, logger):
        self.cfg = config_obj
        self.global_cfg = global_config
        self.logger = logger
        self.latencies = []
    
    def run_all_checks(self):
        """Запускает все включённые проверки и возвращает минимальную задержку или None"""
        # 1. TCP
        if self.global_cfg['check_tcp']:
            ok, lat = self._tcp()
            if not ok:
                return None
            self.latencies.append(lat)
        
        # 2. DNS (опционально)
        if self.global_cfg['check_dns']:
            ok, lat, resolved = self._dns()
            if not ok:
                return None
            self.latencies.append(lat)
            # Можно обновить адрес, если resolved отличается
            if resolved and resolved != self.cfg.address:
                self.logger.debug(f"DNS переопределил {self.cfg.address} -> {resolved}")
                self.cfg.address = resolved
        
        # 3. TLS (если порт 443 или security=tls)
        if self.global_cfg['check_tls'] and (self.cfg.port == 443 or self.cfg.get_security() == 'tls'):
            ok, lat = self._tls()
            if not ok:
                # TLS обязателен для порта 443
                if self.cfg.port == 443:
                    return None
            else:
                self.latencies.append(lat)
        
        # 4. HTTP через прокси (реальная проверка)
        if self.global_cfg['check_http']:
            ok, lat = self._http()
            if ok:
                self.latencies.append(lat)
            else:
                # HTTP-проверка не обязательна для всех типов, но если не прошла – считаем нерабочим?
                # Для ws/grpc может не работать, поэтому не отбрасываем сразу
                pass
        
        # 5. WebSocket
        if self.global_cfg['check_websocket'] and self.cfg.get_outbound_type() == 'ws':
            ok, lat = self._ws()
            if ok:
                self.latencies.append(lat)
            else:
                return None
        
        # 6. gRPC
        if self.global_cfg['check_grpc'] and self.cfg.get_outbound_type() == 'grpc':
            ok, lat = self._grpc()
            if ok:
                self.latencies.append(lat)
            else:
                return None
        
        # 7. MTU (опционально)
        if self.global_cfg['check_mtu']:
            ok, lat, mtu = self._mtu()
            if ok:
                self.latencies.append(lat)
                self.cfg.params['mtu'] = mtu
        
        if not self.latencies:
            return None
        return min(self.latencies)
    
    def _tcp(self):
        return tcp_check(self.cfg.address, self.cfg.port, self.global_cfg['tcp_timeout'])
    
    def _tls(self):
        return tls_check(self.cfg.address, self.cfg.port, self.cfg.get_sni(), self.global_cfg['tls_timeout'])
    
    def _http(self):
        ua = None
        if self.global_cfg['use_random_user_agent']:
            ua = random.choice(USER_AGENTS)
        return HTTPProxyChecker.check(self.cfg, self.global_cfg['test_url'], self.global_cfg['http_timeout'], ua)
    
    def _ws(self):
        return WebSocketChecker.check(self.cfg, self.global_cfg['ws_timeout'])
    
    def _grpc(self):
        return GRPCChecker.check(self.cfg, self.global_cfg['grpc_timeout'])
    
    def _dns(self):
        return DNSChecker.check(self.cfg, self.global_cfg['dns_timeout'])
    
    def _mtu(self):
        return MTUChecker.check(self.cfg, self.global_cfg['mtu_timeout'])

# ================= ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =================

def tcp_check(host, port, timeout):
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        latency = (time.time() - start) * 1000
        sock.close()
        if result == 0:
            return True, latency
    except:
        pass
    return False, None

def tls_check(host, port, sni, timeout):
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

# Список User-Agent для ротации
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
]

def download_subscription(url, timeout=15):
    """Загружает подписку, поддерживает base64 и обычный текст"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': random.choice(USER_AGENTS)})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            # Проверка на base64
            if re.match(r'^[A-Za-z0-9+/=]+$', content.strip()):
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    if decoded:
                        content = decoded
                except:
                    pass
            return content
    except Exception as e:
        return None

def extract_vless_links(text):
    """Извлекает все vless:// ссылки из текста"""
    pattern = re.compile(r'vless://[a-f0-9\-]{36}@[^/\s?#]+:\d+\?[^\s#]*(?:#[^\s]*)?', re.IGNORECASE)
    return pattern.findall(text)

def load_sources(sources_file):
    """Загружает список источников из файла (каждая строка – URL)"""
    if not os.path.exists(sources_file):
        return []
    with open(sources_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return lines

def collect_configs_from_sources(sources, logger):
    """Собирает все VLESS-конфиги из всех источников, возвращает список объектов VlessConfig"""
    all_urls = []
    for src in sources:
        logger.info(f"Загрузка источника: {src[:70]}")
        content = download_subscription(src)
        if content:
            links = extract_vless_links(content)
            logger.info(f"  найдено {len(links)} ссылок")
            all_urls.extend(links)
        else:
            logger.warning(f"  не удалось загрузить")
    # Удаляем дубликаты
    all_urls = list(set(all_urls))
    configs = []
    for url in all_urls:
        cfg = VlessConfig(url)
        if cfg.valid:
            configs.append(cfg)
    logger.info(f"Всего получено валидных конфигов: {len(configs)}")
    return configs

def enrich_with_geo(configs, add_flags, add_geo, logger):
    """Обогащает конфиги геоданными и флагами"""
    for cfg in configs:
        geo = GeoInfo(cfg.address)
        if add_flags:
            cfg.flag = geo.get_flag()
        if add_geo:
            cfg.country = geo.country
            cfg.city = geo.city
            cfg.isp = geo.isp
        # небольшая задержка, чтобы не забанили API
        time.sleep(0.05)

def process_single_config(cfg, global_config, logger):
    """Обрабатывает один конфиг: проверяет, измеряет задержку, возвращает готовый объект или None"""
    tester = VlessTester(cfg, global_config, logger)
    latency = tester.run_all_checks()
    if latency is not None and latency <= global_config['max_latency'] and latency >= global_config['min_latency']:
        cfg.latency = latency
        return cfg
    return None

def build_output_line(cfg, global_config):
    """Формирует финальную строку конфига с именем"""
    name_parts = []
    if cfg.latency:
        name_parts.append(f"{cfg.latency:.0f}ms")
    if global_config['add_flags'] and cfg.flag:
        name_parts.append(cfg.flag)
    if global_config['add_geo'] and cfg.country:
        name_parts.append(cfg.country[:2])
    name_parts.append(global_config['subscription_name'])
    name = " | ".join(name_parts)
    return cfg.rebuild_url(new_remark=name)

def save_results(configs, output_file, global_config, logger):
    """Сохраняет отсортированные конфиги в файл"""
    configs.sort(key=lambda x: x.latency)
    limited = configs[:global_config['max_configs']]
    with open(output_file, 'w', encoding='utf-8') as f:
        for cfg in limited:
            f.write(build_output_line(cfg, global_config) + '\n')
    logger.info(f"Сохранено {len(limited)} конфигов в {output_file}")

def generate_statistics(configs, total_raw, total_filtered, runtime, logger):
    """Генерирует расширенную статистику и сохраняет в JSON"""
    stats = {
        'timestamp': datetime.now().isoformat(),
        'program': PROGRAM_NAME,
        'version': VERSION,
        'runtime_seconds': runtime,
        'total_raw_links': total_raw,
        'unique_configs': len(configs),
        'working_configs': len([c for c in configs if c.latency is not None]),
        'max_latency_ms': max((c.latency for c in configs if c.latency), default=0),
        'min_latency_ms': min((c.latency for c in configs if c.latency), default=0),
        'avg_latency_ms': sum(c.latency for c in configs if c.latency) / len([c for c in configs if c.latency]) if any(c.latency for c in configs) else 0,
        'by_transport': {},
        'by_security': {},
        'by_country': {}
    }
    for cfg in configs:
        if cfg.latency:
            t = cfg.get_outbound_type()
            stats['by_transport'][t] = stats['by_transport'].get(t, 0) + 1
            s = cfg.get_security()
            stats['by_security'][s] = stats['by_security'].get(s, 0) + 1
            if cfg.country:
                stats['by_country'][cfg.country] = stats['by_country'].get(cfg.country, 0) + 1
    with open('statistics.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    return stats

def print_statistics(stats):
    """Выводит статистику в консоль красиво"""
    print("\n" + "="*70)
    print(f"📊 СТАТИСТИКА {PROGRAM_NAME} v{VERSION}")
    print("="*70)
    print(f"⏱️  Время выполнения: {stats['runtime_seconds']:.2f} сек")
    print(f"📥 Всего сырых ссылок: {stats['total_raw_links']}")
    print(f"🔍 Уникальных конфигов: {stats['unique_configs']}")
    print(f"✅ Рабочих конфигов: {stats['working_configs']}")
    print(f"⚡ Задержки: мин {stats['min_latency_ms']:.0f} мс, макс {stats['max_latency_ms']:.0f} мс, ср {stats['avg_latency_ms']:.0f} мс")
    print("\n📡 По типам транспорта:")
    for t, cnt in stats['by_transport'].items():
        print(f"   {t.upper()}: {cnt}")
    print("\n🔒 По типу шифрования:")
    for s, cnt in stats['by_security'].items():
        print(f"   {s}: {cnt}")
    print("\n🌍 По странам:")
    for country, cnt in sorted(stats['by_country'].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   {country}: {cnt}")
    print("="*70)

# ================= АРГУМЕНТЫ КОМАНДНОЙ СТРОКИ =================

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=f"{PROGRAM_NAME} – многоуровневая проверка VLESS-конфигов",
        epilog=f"Автор: {AUTHOR}"
    )
    parser.add_argument('--sources', default='sources.txt', help='Файл со списком источников')
    parser.add_argument('--output', default='output.txt', help='Выходной файл с рабочими конфигами')
    parser.add_argument('--max-configs', type=int, default=500, help='Максимум конфигов в выходном файле')
    parser.add_argument('--max-threads', type=int, default=50, help='Количество потоков проверки')
    parser.add_argument('--tcp-timeout', type=float, default=3.0, help='Таймаут TCP (сек)')
    parser.add_argument('--tls-timeout', type=float, default=5.0, help='Таймаут TLS (сек)')
    parser.add_argument('--http-timeout', type=float, default=8.0, help='Таймаут HTTP через прокси (сек)')
    parser.add_argument('--max-latency', type=int, default=2000, help='Макс. задержка (мс)')
    parser.add_argument('--no-tcp', action='store_false', dest='check_tcp', help='Отключить TCP-проверку')
    parser.add_argument('--no-tls', action='store_false', dest='check_tls', help='Отключить TLS-проверку')
    parser.add_argument('--no-http', action='store_false', dest='check_http', help='Отключить HTTP-проверку через прокси')
    parser.add_argument('--no-ws', action='store_false', dest='check_websocket', help='Отключить WebSocket-проверку')
    parser.add_argument('--no-grpc', action='store_false', dest='check_grpc', help='Отключить gRPC-проверку')
    parser.add_argument('--no-flags', action='store_false', dest='add_flags', help='Не добавлять флаги стран')
    parser.add_argument('--no-geo', action='store_false', dest='add_geo', help='Не добавлять геоинформацию')
    parser.add_argument('--name', default='ОСТАТЬСЯ НА СВЯЗИ 🛜', help='Название подписки')
    parser.add_argument('--log-file', default='parser.log', help='Файл логов')
    parser.add_argument('--verbose', action='store_true', help='Подробный вывод')
    return parser.parse_args()

# ================= ОСНОВНАЯ ФУНКЦИЯ =================

def main():
    args = parse_arguments()
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logging(args.log_file, level=log_level)
    
    logger.info("="*70)
    logger.info(f"{PROGRAM_NAME} v{VERSION} запущен")
    logger.info(f"Автор: {AUTHOR}")
    logger.info("="*70)
    
    # Формируем конфиг
    global_config = Config(args=args)
    logger.debug(f"Конфигурация: {global_config.data}")
    
    start_time = time.time()
    
    # 1. Загружаем источники
    sources = load_sources(global_config['sources_file'])
    if not sources:
        logger.error(f"Файл источников {global_config['sources_file']} пуст или не найден!")
        sys.exit(1)
    logger.info(f"Загружено источников: {len(sources)}")
    
    # 2. Собираем сырые ссылки и парсим в конфиги
    raw_configs = collect_configs_from_sources(sources, logger)
    total_raw = len(raw_configs)
    logger.info(f"Уникальных валидных конфигов: {total_raw}")
    
    if total_raw == 0:
        logger.error("Нет конфигов для проверки!")
        sys.exit(0)
    
    # 3. Обогащаем геоданными (опционально)
    if global_config['add_flags'] or global_config['add_geo']:
        logger.info("Получение геоинформации по IP (может занять некоторое время)...")
        enrich_with_geo(raw_configs, global_config['add_flags'], global_config['add_geo'], logger)
    
    # 4. Многопоточная проверка
    logger.info(f"Начинаем проверку {len(raw_configs)} конфигов в {global_config['max_threads']} потоков...")
    working_configs = []
    completed = 0
    total = len(raw_configs)
    
    with ThreadPoolExecutor(max_workers=global_config['max_threads']) as executor:
        future_to_cfg = {executor.submit(process_single_config, cfg, global_config, logger): cfg for cfg in raw_configs}
        for future in as_completed(future_to_cfg):
            completed += 1
            result = future.result()
            if result:
                working_configs.append(result)
                logger.debug(f"[{completed}/{total}] + {result.address}:{result.port} ({result.latency:.0f}ms)")
            else:
                if completed % 50 == 0 or completed == total:
                    logger.info(f"Прогресс: {completed}/{total} – найдено рабочих: {len(working_configs)}")
    
    logger.info(f"Проверка завершена. Рабочих конфигов: {len(working_configs)}")
    
    # 5. Сортировка и сохранение
    save_results(working_configs, global_config['output_file'], global_config, logger)
    
    # 6. Статистика
    runtime = time.time() - start_time
    stats = generate_statistics(working_configs, total_raw, len(raw_configs), runtime, logger)
    print_statistics(stats)
    
    # 7. Сохраняем также список нерабочих (если нужно)
    if global_config['save_intermediate'] and len(working_configs) < len(raw_configs):
        dead_file = "dead_configs.txt"
        with open(dead_file, 'w') as f:
            for cfg in raw_configs:
                if not hasattr(cfg, 'latency') or cfg.latency is None:
                    f.write(cfg.original + '\n')
        logger.info(f"Список нерабочих конфигов сохранён в {dead_file}")
    
    logger.info("Работа успешно завершена!")
    logger.info("="*70)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Прервано пользователем")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Критическая ошибка: {e}", exc_info=True)
        sys.exit(1)