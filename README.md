

## 🛰️ PARASER — Автоматический сборщик конфигов

Парсер автоматически собирает и проверяет VLESS/VMess/Trojan/SS конфиги из 3600+ источников каждые 2 часа через GitHub Actions.

## 📥 Актуальные подписки (реально работающие)

### 1️⃣ Основная подписка (Xray-Verified)
Проверенные конфиги через Xray core (TCP + TLS + загрузка тестового файла).  
*Последнее обновление: 6 июня 2026*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI.txt`
- **Base64:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_base64.txt`

### 2️⃣ TCP+TLS подписка (500 серверов)
Топ-500 серверов, прошедших TCP-handshake и TLS-проверку.  
*Последнее обновление: 6 июня 2026*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls.txt`
- **Base64:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls_base64.txt`

### 3️⃣ v2ray_sub.txt (Активно обновляется!)
Основной файл подписки с проверенными конфигами.  
*Последнее обновление: 2 июля 2026 (вчера)*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/v2ray_sub.txt`

### 4️⃣ Valid Internet Links
Проверенные ссылки на интернет-ресурсы.  
*Последнее обновление: 2 июля 2026*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/valid_internet_links.txt`

### 5️⃣ Valid Whitelist Links
Проверенные ссылки из whitelist.  
*Последнее обновление: 2 июля 2026*
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
- `whitelist_cidr.txt` — 28,247 CIDR блоков для whitelist
- `whitelist_sni.txt` — 23,836 рабочих российских SNI доменов

## 🔧 Технологии
- Python 3.12 + Xray core
- GitHub Actions (cron каждые 2 часа)
- Multi-threaded проверка
- Поддержка v2rayNG, Hiddify, Nekoray, Streisand

---

**Важно:** Gaming и Stealth подписки (`OSTATSYA_NA_SVYAZI_gaming.txt` и `OSTATSYA_NA_SVYAZI_stealth.txt`) **не существуют** в репозитории. Они были упомянуты в README, но файлы не создаются.