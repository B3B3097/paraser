# 🛜 ОСТАТЬСЯ НА СВЯЗИ

> Автоматический сборщик рабочих VLESS конфигов из сотен публичных репозиториев.  
> Обновляется **каждый час** через GitHub Actions. Проверка в 3 этапа: TCP → TLS → Xray.  
> Максимум **200 лучших** конфигов, отсортированных по скорости.

---

## 📡 Подписка

Вставьте эту ссылку в ваш VPN-клиент как подписку:

```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI.txt
```

**Base64-версия** (для клиентов, которые требуют base64):
```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_base64.txt
```

Конфиги называются по шаблону: `🇷🇺 ОСТАТЬСЯ НА СВЯЗИ 🛜` (флаг страны сервера).

---

## 📲 Поддерживаемые клиенты

| Клиент | Платформа | Как добавить |
|--------|-----------|--------------|
| **v2rayNG** | Android | Подписки → + → вставить ссылку |
| **Hiddify** | Android / iOS / Windows / Mac | Proxies → Add → Subscription link |
| **Nekoray** | Windows / Linux | Программа → Подписки → Добавить |
| **Streisand** | iOS | Добавить конфигурацию → URL |
| **v2rayN** | Windows | Подписки → Управление → Добавить |

---

## ⚙️ Как это работает

```
source.txt (~400 источников)
     │
     ▼
 Парсинг VLESS-конфигов (plain text + base64)
     │
     ▼
Stage 1 — TCP-проверка       (80 потоков, timeout 5s)
     │  отсев недоступных хостов
     ▼
Stage 2 — TLS-проверка       (40 потоков, timeout 8s)
     │  проверка TLS-рукопожатия для конфигов с security=tls/reality
     ▼
Stage 3 — Xray real check    (10 потоков, timeout 15s)
     │  реальный запрос через ядро Xray → gstatic.com/generate_204
     ▼
 Геолокация → флаг страны → сортировка по латентности
     │
     ▼
 Топ 200 конфигов → OSTATSYA_NA_SVYAZI.txt
```

**Stage 3** использует настоящее ядро [Xray-core](https://github.com/XTLS/Xray-core) — конфиг считается рабочим только если через него реально проходит HTTP-запрос. Это исключает конфиги, которые принимают TCP/TLS соединение, но не пропускают трафик.

---

## 📁 Файлы

| Файл | Описание |
|------|----------|
| `OSTATSYA_NA_SVYAZI.txt` | Рабочие VLESS конфиги (plain text) |
| `OSTATSYA_NA_SVYAZI_base64.txt` | То же, в base64 |
| `stats.json` | Статистика последнего запуска |
| `source.txt` | Список источников для парсинга |
| `parser.py` | Скрипт парсера (3 стадии проверки) |
| `.github/workflows/vless-parser.yml` | GitHub Actions workflow |

---

## 📊 Статистика

Актуальная статистика в файле [`stats.json`](./stats.json):

```json
{
  "updated_at": "2026-06-04T12:00:00+00:00",
  "sources_count": 400,
  "total_fetched": 2000,
  "tcp_passing": 800,
  "tls_passing": 500,
  "xray_passing": 250,
  "final_count": 200,
  "xray_used": true,
  "success_rate": 10.0
}
```

---

## ▶️ Запустить вручную

1. Перейдите во вкладку **[Actions](../../actions)**
2. Выберите **VLESS Parser - Hourly Update**
3. Нажмите **Run workflow**

Параметры при ручном запуске:

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `concurrency_tcp` | 80 | Параллельных TCP-проверок |
| `concurrency_xray` | 10 | Параллельных Xray-проверок |
| `xray_timeout` | 15 | Таймаут Xray-проверки (сек) |
| `max_output` | 200 | Максимум конфигов в выводе |

---

## ➕ Добавить источник

Откройте [`source.txt`](./source.txt) и добавьте URL на новой строке:
- Прямая ссылка на `vless.txt` / `configs.txt`
- Ссылка на GitHub-репозиторий (скрипт сам найдёт файл с конфигами)
- Подписка в формате base64

Строки, начинающиеся с `#`, игнорируются.
