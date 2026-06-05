<div align="center">

# 🛜 ОСТАТЬСЯ НА СВЯЗИ

<img src="://readme-typing-svg.demolab.com?font=Fira+Code&size=22&pause=1000&color=00D4FF&center=true&vCenter=true&width=600&lines=Автоматический+сборщик+VLESS+конфигов;Обновление+каждый+час+%F0%9F%94%84;TCP+%E2%86%92+TLS+%E2%86%92+Xray+проверка;Только+рабочие+конфиги+%E2%9C%85" alt="Typing SVG" />

<br/>

[![Telegram](https://img.shields.io/badge/Telegram-@httpsRemainingconnections-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/httpsRemainingconnections)
[![Update](https://img.shields.io/badge/Обновление-каждый%20час-brightgreen?style=for-the-badge&logo=github-actions&logoColor=white)](../../actions/workflows/vless-parser.yml)
[![Configs](https://img.shields.io/badge/Конфиги-200%20Xray%20%7C%20500%20TLS-blue?style=for-the-badge&logo=v2ray&logoColor=white)](./OSTATSYA_NA_SVYAZI.txt)
[![Sources](https://img.shields.io/badge/Источники-500%2B-orange?style=for-the-badge&logo=rss&logoColor=white)](./source.txt)

</div>

---

<div align="center">

## 📲 Подпишись на канал

### [![Telegram](https://img.shields.io/badge/-@httpsRemainingconnections-2CA5E0?style=flat-square&logo=telegram&logoColor=white&labelColor=229ED9&color=1B7BA3)](https://t.me/httpsRemainingconnections)

**Свежие конфиги, обновления и новости — в Telegram**

</div>

---

## 📡 Подписки

> Добавь ссылку в свой клиент (v2rayNG, Hiddify, Nekoray и др.) и получай обновления автоматически

<table>
<tr>
<td align="center" width="50%">

### ✅ Xray‑verified
**Топ 200 — реально рабочие**

Прошли проверку через ядро Xray:  
скачивает 200 КБ через каждый конфиг,  
измеряет скорость и задержку.  
Сортировка: лучшие — первые.

```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI.txt
```

Base64:
```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_base64.txt
```

</td>
<td align="center" width="50%">

### ⚡ TCP+TLS
**Топ 500 — быстрая проверка**

Прошли TCP‑соединение и TLS‑рукопожатие.  
Больше вариантов, быстрее обновляются.  
Подходит если Xray‑пул маловат.

```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls.txt
```

Base64:
```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls_base64.txt
```

</td>
</tr>
</table>

> 💡 **Имя подписки:** при добавлении введи `ОСТАТЬСЯ НА СВЯЗИ 🛜` в поле «Имя» / «Группа».  
> Каждый конфиг уже автоматически назван `🇩🇪 ОСТАТЬСЯ НА СВЯЗИ 🛜` (с флагом страны сервера).

---

## 📲 Поддерживаемые клиенты

<div align="center">

| Клиент | Платформа | Действие |
|:------:|:---------:|:--------:|
| **v2rayNG** | 🤖 Android | Подписки → `+` → вставить ссылку |
| **Hiddify** | 🤖🍎💻 Android / iOS / Win / Mac | Proxies → Add → Subscription link |
| **Nekoray** | 💻 Windows / Linux | Программа → Подписки → Добавить |
| **Streisand** | 🍎 iOS | Добавить конфигурацию → URL |
| **v2rayN** | 💻 Windows | Подписки → Управление → Добавить |
| **Clash Meta** | 💻🤖 Win / Android | Profiles → New → URL |

</div>

---

## ⚙️ Как работает пайплайн

```
📥 source.txt  (~500 источников)
     │
     ├─ прямая ссылка на .txt        →  скачать напрямую
     └─ ссылка на GitHub репо        →  GitHub Tree API → найти все .txt с конфигами
     │
     ▼
🔍 Парсинг VLESS URI + авто-декод Base64  →  дедупликация по uuid@host:port
     │
     ▼
🔌 Stage 1 — TCP         80 потоков │ 5s timeout  →  убираем мёртвые хосты
     │
     ▼
🔒 Stage 2 — TLS         40 потоков │ 8s timeout  →  проверка TLS / REALITY
     │
     ├──────────────────────────────────────────┐
     ▼                                          ▼
🚀 Stage 3 — Xray                        ⚡ TCP+TLS pool
   12 потоков │ 15s timeout               топ 500
   requests + socks5h                     OSTATSYA_NA_SVYAZI_tcptls.txt
   скачивает 200 КБ с Cloudflare
   измеряет: latency + скорость МБ/с
     │
     ▼
🌍 Геолокация ip-api.com  →  флаг страны 🇩🇪🇳🇱🇺🇸
     │
     ▼
📊 Сортировка: ⭐ whitelisted → быстрее → меньше задержка
     │
     ▼
✅ топ 200 → OSTATSYA_NA_SVYAZI.txt + base64
```

---

## 📁 Файлы репозитория

<div align="center">

| Файл | Назначение |
|:-----|:-----------|
| [`OSTATSYA_NA_SVYAZI.txt`](./OSTATSYA_NA_SVYAZI.txt) | 🏆 Xray‑verified, топ 200, plain text |
| [`OSTATSYA_NA_SVYAZI_base64.txt`](./OSTATSYA_NA_SVYAZI_base64.txt) | 🏆 То же, в Base64 |
| [`OSTATSYA_NA_SVYAZI_tcptls.txt`](./OSTATSYA_NA_SVYAZI_tcptls.txt) | ⚡ TCP+TLS, топ 500, plain text |
| [`OSTATSYA_NA_SVYAZI_tcptls_base64.txt`](./OSTATSYA_NA_SVYAZI_tcptls_base64.txt) | ⚡ То же, в Base64 |
| [`stats.json`](./stats.json) | 📊 Статистика последнего запуска |
| [`source.txt`](./source.txt) | 📋 Список источников |
| [`parser.py`](./parser.py) | 🐍 Парсер v8 (3 стадии) |
| [`.github/workflows/vless-parser.yml`](./.github/workflows/vless-parser.yml) | ⚙️ GitHub Actions workflow |

</div>

---

## 📊 Последняя статистика

> Актуальные данные всегда в [`stats.json`](./stats.json)

```jsonc
{
  "sources_count":    524,      // источников обработано
  "total_fetched":    145345,   // уникальных конфигов найдено
  "tcp_passing":      77877,    // прошли TCP  (Stage 1)
  "tls_confirmed":    36904,    // прошли TLS  (Stage 2)
  "xray_confirmed":   "...",    // прошли Xray (Stage 3) — реально рабочие
  "avg_speed_mbps":   "...",    // средняя скорость подтверждённых конфигов
  "whitelisted_pool": 12419,    // в whitelist (приоритетные)
  "output_xray":      200,      // в подписке Xray
  "output_tcptls":    500       // в подписке TCP+TLS
}
```

---

## ▶️ Запустить вручную

1. Перейди в **[Actions → VLESS Parser - Hourly Update](../../actions/workflows/vless-parser.yml)**
2. Нажми **Run workflow** → настрой параметры → **Run workflow**

<div align="center">

| Параметр | По умолчанию | Описание |
|:--------:|:------------:|:---------|
| `max_xray` | `200` | Макс. конфигов в Xray-выводе |
| `max_tcptls` | `500` | Макс. конфигов в TCP+TLS-выводе |
| `tcp_concurrency` | `80` | Параллельных TCP-проверок |
| `xray_concurrency` | `12` | Параллельных Xray-проверок |
| `xray_timeout` | `15` | Таймаут Xray-проверки (сек) |

</div>

---

## ➕ Добавить источник

Открой [`source.txt`](./source.txt) и добавь URL на новой строке:

```
# Примеры форматов:
https://raw.githubusercontent.com/user/repo/main/vless.txt   ← прямая ссылка
https://github.com/user/repo                                  ← репо (скрипт сам найдёт файлы)
https://yoursite.com/sub/token123                             ← подписка (plain или base64)
```

Строки начинающиеся с `#` — комментарии, игнорируются.

---

<div align="center">

## 🔗 Контакты

[![Telegram Channel](https://img.shields.io/badge/Telegram%20Channel-@httpsRemainingconnections-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/Remainingconnections)

**Подписывайся — там свежие конфиги и обновления!**

<br/>

*Автоматически обновляется каждый час через GitHub Actions*  
*Все конфиги берутся из открытых публичных источников*

</div>
