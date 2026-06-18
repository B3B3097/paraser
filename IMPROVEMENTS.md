# IMPROVEMENTS.md — Улучшения блока проверки Cloudflare (v3.0 «Siberian+»)

Дата: 18 июня 2026
Автор: Nebula AI (автоматическая генерация по запросу @user:henon-semenov)

---

## Источники данных

- Репозиторий `B3B3097/paraser` (checker.py, parser.py, конфиги)
- Статья «О схеме ограничений РКН в июне 2026-го» (Habr, 6 июня 2026, автор hyperion_cs)
- Статья «Заморозка по fingerprint: как ТСПУ в июне 2026 ломает соединения по поведению» (Habr, 15 июня 2026, автор darkisdark)
- Новости о сбоях российских хостингов (3dnews, techora.ru, kod.ru, Verstka, 5–13 июня 2026)
- Файл `ip_list.txt` — 3191 двухоктетный префикс Cloudflare IP
- Официальный список Cloudflare IP: https://www.cloudflare.com/ips-v4
- ASN-базы: ipip.net, ipgeolocation.io

---

## Сводка изменений

### 1. Новые модули (3 файла)

| Файл | Назначение | Ключевые функции |
|------|-----------|-----------------|
| `cloudflare_checker.py` | Ядро: ТСПУ-константы, Cloudflare-пробинг | `is_cf_ip`, `is_blocked_subnet`, `tpsu_config_score`, `probe_cf_front`, `batch_cf_check` |
| `cf_ip_utils.py` | Утилиты работы с Cloudflare IP | `find_cf_ips_in_subnet`, `filter_cf_ips`, `generate_cf_cidrs`, `update_ip_list_from_api` |
| `sni_scanner.py` | Сканер SNI-доменов | `probe_sni`, `scan_sni_list`, `detect_sni_block`, `generate_sni_candidates`, `sni_classification` |

### 2. Обновлённые ТСПУ-константы

#### ASN провайдеров (было 6 → стало 18)

**Изначальные (до июня 2026):**
- `AS197695`, `AS47764`, `AS210079`, `AS60604` — Selectel
- `AS200350`, `AS13238` — Яндекс / Яндекс.Облако

**НОВЫЕ (июнь 2026, затронуты волной с 5 июня):**
- `AS9123`, `AS51789` — TimeWeb / TimewebCloud
- `AS198610`, `AS213533` — Beget
- `AS208677` — Cloud.ru (Cloud Technologies LLC)
- `AS44112` — SpaceWeb
- `AS48642`, `AS49392`, `AS202984` — FirstVDS / FirstByte / FirstDed
- `AS43362` — Majordomo (частично)
- `AS197068` — Qrator Labs (частично)
- `AS29182`, `AS49505` — FirstByte/IHC + Selectel Moscow

#### Подозрительные CIDR (80+ диапазонов)

Расширен список `TPSU_SUSPICIOUS_CIDRS`. Включены диапазоны TimeWeb, Beget, Cloud.ru, SpaceWeb, FirstVDS.

#### Fingerprint-ы

**Плохие (было 7 → стало 14):**
Добавлены: `chrome110`, `safari_auto`, `ios_auto`, `auto`, `none`, `""` (пустой), `default`

**Хорошие (те же):**
`firefox`, `edge`, `android`, `360`, `qq`

**Экспериментальные безопасные (NEW):**
`cnsa`, `opera`, `brave`, `vivaldi`, `duckduckgo` — CNSA 1.3 Suite помог многим пользователям обойти блокировки с 9 июня 2026.

#### SNI-константы

- `SAFE_FRONT_SNI` — 24 гарантированно безопасных домена (yandex.ru, vk.com, sberbank.ru, и др.)
- `TPU_BLACKLIST_SNI` — 15 доменов, триггерящих ТСПУ (cloudflare.com, vpn.com, torproject.org, и др.)

### 3. ТСПУ-модель «Siberian» — улучшения

**Функция `tpsu_config_score()`** — комплексная оценка конфигурации:

```
Сигнал 1: blocked subnet  → вес 2
Сигнал 2: TLS fingerprint → вес 3 (плохой) / 2 (неизвестный)
Сигнал 3: SNI domain      → вес 1
Бонус:   Cloudflare-транзит → -1
```

Шкала:
- 0–1: конфиг безопасен
- 2–3: средний риск (требует патча fp)
- 4–6: высокий риск (подсеть + плохой fp)
- 7+: критический риск (все три сигнала)

**Улучшение `_patch_link_fp()`** — теперь патчит не только плохие fp, но и неизвестные в TLS-конфигах.

**Улучшение `_tpsu_link_score()`** — учитывает экспериментальные безопасные fp (CNSA, Opera, Brave, etc.)

### 4. Cloudflare-пробинг (TCP → TLS → HTTP)

`probe_cf_front()` — трёхстадийная проверка IP:
1. TCP-коннект к порту
2. TLS handshake с несколькими SNI-кандидатами (пробует до успеха)
3. HTTP-запрос к `/cdn-cgi/trace` с проверкой заголовков `CF-RAY` и `Server: cloudflare`

### 5. SNI-сканер

- `probe_sni()` — трёхстадийный пробинг одного SNI на IP
- `detect_sni_block()` — сравнивает TLS-результаты безопасного и целевого SNI для обнаружения DPI-блокировки
- `generate_sni_candidates()` — генерирует кандидатов из whitelist_sni.txt + безопасных фронтов + популярных CDN
- `sni_classification()` — классифицирует SNI как safe/whitelisted/neutral/blacklisted

### 6. IP-утилиты

- `is_cf_ip()` — быстрая проверка принадлежности IP к Cloudflare (LRU-кэш, lookup по двухоктетному префиксу)
- `generate_cf_cidrs()` — генерация /16 CIDR из 3191 префикса
- `update_ip_list_from_api()` — автоматическое обновление ip_list.txt с официального API Cloudflare
- `filter_cf_ips()` — разделение списка IP на Cloudflare/не-Cloudflare

---

## Инструкция по использованию

### Подключение модулей

Все три модуля должны лежать в директории проекта `paraser/` рядом с `checker.py`:

```
paraser/
  checker.py
  cloudflare_checker.py    ← новый
  cf_ip_utils.py           ← новый
  sni_scanner.py           ← новый
  whitelist_sni.txt
  whitelist_cidr.txt
  ...
```

`checker.py` импортирует их опционально (try/except — не ломается при отсутствии).

### CLI-использование

```bash
# Статистика Cloudflare IP
python3 cf_ip_utils.py stats

# Проверить IP на Cloudflare
python3 cf_ip_utils.py check 172.64.1.1

# Обновить ip_list.txt с API Cloudflare
python3 cf_ip_utils.py update

# Сгенерировать CIDR из префиксов
python3 cf_ip_utils.py cidrs --output /tmp/cf_cidrs.txt

# Статистика SNI
python3 sni_scanner.py stats

# Проверить классификацию SNI
python3 sni_scanner.py check vk.com

# Просканировать SNI на Cloudflare IP
python3 sni_scanner.py scan --ip 1.1.1.1 --max-snis 100

# Проверить SNI на ТСПУ-блокировку
python3 sni_scanner.py detect cloudflare.com --ip 1.1.1.1

# Сгенерировать список SNI-кандидатов
python3 sni_scanner.py candidates --output candidates.txt
```

### Программное использование

```python
from cloudflare_checker import (
    is_cf_ip, is_blocked_subnet, tpsu_config_score,
    probe_cf_front, batch_cf_check
)
from cf_ip_utils import find_cf_ips_in_subnet, filter_cf_ips
from sni_scanner import scan_sni_list, detect_sni_block, generate_sni_candidates

# Проверка IP на Cloudflare
if is_cf_ip("172.64.1.1"):
    print("Cloudflare IP")

# Проверка подсети на ТСПУ
if is_blocked_subnet("5.8.1.1"):
    print("Заблокированная подсеть")

# Комплексная оценка конфига
score = tpsu_config_score(fp="chrome", sni="vpn.com", ip_in_blocked_subnet=True)
print(f"ТСПУ-риск: {score}")

# Пробинг Cloudflare-фронта
result = probe_cf_front("1.1.1.1")
print(f"CF Ray: {result.cf_ray}, Latency: {result.total_latency_ms:.0f}ms")

# Поиск CF IP в подсети
cf_ips = find_cf_ips_in_subnet("172.64.0.0/24")

# Фильтрация IP
cf, non_cf = filter_cf_ips(["172.64.1.1", "8.8.8.8", "104.16.1.1"])

# Поиск рабочих SNI-фронтов
candidates = generate_sni_candidates(max_snis=50)
results = scan_sni_list(candidates, ["1.1.1.1"])

# Детект ТСПУ-блокировки
block_test = detect_sni_block("cloudflare.com", "1.1.1.1")
if block_test.blocked:
    print(f"SNI заблокирован! Тип: {block_test.blocking_type}")
```

---

## Обоснование улучшений

1. **Расширение ASN** — с 5 июня 2026 ТСПУ начало блокировать TimeWeb, Beget, Cloud.ru и др. российские дата-центры. Без этого обновления чекер не помечал бы ⚠️ конфиги на этих провайдерах, и пользователи получали бы неработающие подключения.

2. **Расширение fingerprint-ов** — CNSA 1.3 Suite оказался эффективным обходом для многих пользователей. Включение его в список безопасных позволяет не патчить уже хорошие конфиги.

3. **SNI-анализ** — ТСПУ анализирует SNI в ClientHello. Новый сканер позволяет находить домены, которые проходят DPI, и отбрасывать заведомо блокируемые.

4. **Cloudflare-пробинг** — трёхстадийная проверка (TCP → TLS → HTTP) надёжнее простого TCP-коннекта и позволяет отличить «живой Cloudflare IP» от «IP с открытым 443 портом».

5. **Автообновление IP-списка** — Cloudflare периодически меняет диапазоны. Функция `update_ip_list_from_api()` держит `ip_list.txt` актуальным.

---

## Что НЕ изменилось

- Основной пайплайн проверки конфигов в `checker.py` (загрузка подписок → парсинг → Xray-тест → сохранение)
- Парсер VLESS/VMess/Trojan/SS ссылок
- Интеграция с GitHub Actions (`check_and_update.yml`)
- TypeScript-артефакты (API-сервер и фронтенд)

Все изменения обратно совместимы: `checker.py` работает и без новых модулей (graceful fallback через try/except ImportError).
