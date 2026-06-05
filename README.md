# 🛜 ОСТАТЬСЯ НА СВЯЗИ

> Автоматический сборщик и верификатор рабочих VLESS конфигов из сотен публичных GitHub-репозиториев.  
> Обновляется **каждый час**. Три уровня проверки: **TCP → TLS → Xray**.

---

## 📡 Подписки

### ✅ Xray-verified — только реально рабочие (топ 200)

Конфиги прошли реальную проверку через ядро Xray — гарантированно пускают трафик.

```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI.txt
```

Base64:
```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_base64.txt
```

---

### ⚡ TCP+TLS — быстрая проверка (топ 500, больше конфигов)

Конфиги прошли TCP-соединение и TLS-рукопожатие. Больше вариантов, но без гарантии реального трафика.

```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls.txt
```

Base64:
```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls_base64.txt
```

---

> 💡 **Как назвать подписку «ОСТАТЬСЯ НА СВЯЗИ 🛜» в клиенте:**  
> При добавлении подписки введите это название вручную в поле «Имя» / «Группа» / «Profile name».  
> Каждый отдельный конфиг уже называется `🇷🇺 ОСТАТЬСЯ НА СВЯЗИ 🛜` (с флагом страны сервера).

---

## 📲 Клиенты

| Клиент | Платформа | Как добавить |
|--------|-----------|--------------|
| **v2rayNG** | Android | Подписки → + → вставить ссылку → назвать «ОСТАТЬСЯ НА СВЯЗИ 🛜» |
| **Hiddify** | Android / iOS / Win / Mac | Proxies → Add → Subscription link |
| **Nekoray** | Windows / Linux | Программа → Подписки → Добавить |
| **Streisand** | iOS | Добавить конфигурацию → URL |
| **v2rayN** | Windows | Подписки → Управление → Добавить |

---

## ⚙️ Пайплайн проверки

```
source.txt  (~400 источников)
     │
     ├─ raw URL / прямая ссылка  →  fetch immediately
     └─ GitHub repo URL          →  GitHub Tree API → найти все .txt с конфигами
                                                      (без ограничений на число файлов)
     ▼
 Парсинг (plain text + auto base64 decode)  →  дедупликация по uuid@host:port
     │
     ▼
 Stage 1 — TCP check      80 потоков, timeout 5s   → отсев мёртвых хостов
     │
     ▼
 Stage 2 — TLS handshake  40 потоков, timeout 8s   → проверка TLS/REALITY конфигов
     │
     ├──────────────────────────────────────────────────────────────┐
     ▼                                                              ▼
 Stage 3 — Xray real check                          TCP+TLS pool (top 500)
   10 потоков, timeout 15s                          → OSTATSYA_NA_SVYAZI_tcptls.txt
   реальный HTTP 204 через ядро Xray
     │
     ▼
 Геолокация → флаг страны → сортировка по латентности
     │
     ▼
 top 200 → OSTATSYA_NA_SVYAZI.txt
```

**Stage 3** скачивает актуальный [Xray-core](https://github.com/XTLS/Xray-core) и для каждого конфига:
1. Запускает xray с SOCKS5 на локальном порту
2. Делает `curl --proxy socks5://...` к `gstatic.com/generate_204`
3. Если HTTP 204 — конфиг рабочий

---

## 📁 Файлы

| Файл | Описание |
|------|----------|
| `OSTATSYA_NA_SVYAZI.txt` | Xray-verified, топ 200, plain text |
| `OSTATSYA_NA_SVYAZI_base64.txt` | То же, base64 |
| `OSTATSYA_NA_SVYAZI_tcptls.txt` | TCP+TLS verified, топ 500, plain text |
| `OSTATSYA_NA_SVYAZI_tcptls_base64.txt` | То же, base64 |
| `stats.json` | Статистика последнего запуска |
| `source.txt` | Список источников |
| `parser.py` | Парсер (3 стадии) |
| `.github/workflows/vless-parser.yml` | Actions workflow |

---

## 📊 Статистика

[`stats.json`](./stats.json):

```json
{
  "updated_at": "2026-06-04T12:00:00+00:00",
  "sources_count": 400,
  "total_fetched": 80000,
  "tcp_passing": 15000,
  "tls_confirmed": 8000,
  "xray_confirmed": 300,
  "output_xray": 200,
  "output_tcptls": 500,
  "xray_used": true
}
```

---

## ▶️ Запустить вручную

1. **[Actions → VLESS Parser - Hourly Update](../../actions/workflows/vless-parser.yml)**
2. **Run workflow** → настроить параметры → **Run workflow**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `max_xray` | 200 | Макс. конфигов в Xray-выводе |
| `max_tcptls` | 500 | Макс. конфигов в TCP+TLS-выводе |
| `tcp_concurrency` | 80 | Параллельных TCP-проверок |
| `xray_concurrency` | 10 | Параллельных Xray-проверок |
| `xray_timeout` | 15 | Таймаут Xray-проверки (сек) |

---

## ➕ Добавить источник

Откройте [`source.txt`](./source.txt) и добавьте URL на новой строке:
- Прямая ссылка на файл (`https://raw.githubusercontent.com/.../vless.txt`)
- Ссылка на GitHub-репозиторий — скрипт сам найдёт все `.txt` с конфигами через GitHub Tree API
- Подписка в base64

Строки с `#` в начале — комментарии, игнорируются.
