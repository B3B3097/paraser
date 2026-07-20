

## 🛰️ PARASER — Автоматический сборщик конфигов

Парсер автоматически собирает и проверяет VLESS/VMess/Trojan/SS конфиги из 3600+ источников каждые 2 часа через GitHub Actions. **v4.0 "Siberian Pro"** — с автоматическим обхождением ТСПУ (Сигнал 1 & 2), классификацией провайдеров и SNI-ротацией.

## 📥 Актуальные подписки (реально работающие)

### 1️⃣ Основная подписка (Xray-Verified)
Проверенные конфиги через Xray core (TCP + TLS + загрузка тестового файла).  
*Последнее обновление: 20.07.2026 21:05 MSK*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI.txt`
- **Base64:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_base64.txt`

### 2️⃣ TCP+TLS подписка (500 серверов)
Топ-500 серверов, прошедших TCP-handshake и TLS-проверку.  
*Последнее обновление: 20.07.2026 21:05 MSK*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls.txt`
- **Base64:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls_base64.txt`

### 3️⃣ v2ray_sub.txt (Активно обновляется!)
Основной файл подписки с проверенными конфигами.  
*Последнее обновление: 20.07.2026 21:05 MSK*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/v2ray_sub.txt`

### 4️⃣ Valid Internet Links
Проверенные ссылки на интернет-ресурсы.  
*Последнее обновление: 20.07.2026 21:05 MSK*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/valid_internet_links.txt`

### 5️⃣ Valid Whitelist Links
Проверенные ссылки из whitelist.  
*Последнее обновление: 20.07.2026 21:05 MSK*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/valid_whitelist_links.txt`

## ⚙️ Как работает парсер?

1. **Автоматический сбор** из 3600+ источников (GitHub API + source.txt)
2. **Парсинг протоколов:** VLESS, VMess, Trojan, Shadowsocks
3. **Проверка через Xray:** TCP-handshake → TLS → загрузка тестового файла
4. **Дедупликация:** удаление дубликатов по UUID@host:port
5. **Автообновление:** GitHub Actions каждые 2 часа коммитит новые конфиги

## 📂 Дополнительные файлы

- `source.txt` — список всех источников для парсинга
- `stats.json` — статистика проверок
- `status2.txt` — метаданные последнего обновления (время, кол-во конфигов)
- `whitelist_cidr.txt` — 28,247 CIDR блоков для whitelist
- `whitelist_sni.txt` — 23,836 рабочих российских SNI доменов

## 📢 Сообщество

Подписывайся на Telegram-канал — там больше подписок, апдейты и обсуждения:
**👉 [@REMAININGCONNECTIONS](https://t.me/REMAININGCONNECTIONS)**

---
