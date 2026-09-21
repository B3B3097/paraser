# 🛰️ PARASER — Автоматический сборщик и чекер VLESS / Белых Списков (БС)

Автоматический сборщик, валидатор и генератор подписок VLESS / VMess / Trojan / Shadowsocks из 3600+ источников.
Регулярное автоматическое обновление каждые 2–3 часа через GitHub Actions с обходом блокировок ТСПУ, проверкой через Xray Core и валидацией Белых Списков РФ (Whitelist).

---

## 🌟 НОВЫЕ СПЕЦИАЛИЗИРОВАННЫЕ ПОДПИСКИ (Белые Списки и Топ)

> 💡 **Как использовать:** Скопируйте нужную ссылку (Plain для прямого списка или Base64 для клиентов) и вставьте в ваше приложение: **v2rayNG, Happ, Hiddify, NekoBox, v2RayTun, Streisand, Sing-box, Clash, FoXray**.

---

### 🔥 1. Подписка «250 Конфигов (20 БС + 230 Интернет)»
**Идеальный сбалансированный набор на каждый день:**
- **20 гарантированных конфигураций из Белых Списков (БС / Whitelist)** — работают даже при масштабных отключениях внешнего трафика и жёстких ограничениях провайдеров РФ (VK, Yandex, Mail, Госуслуги, X5, банковские сети).
- **230 скоростных серверов зарубежного интернета** — максимальная скорость для YouTube, Instagram, Discord, ChatGPT, Twitter/X.
- **Всего:** ровно 250 отборных серверов с минимальной задержкой.

*Последнее обновление: 21.09.2026 17:02 MSK*
- 📄 **Plain Text (URL):**
  ```
  https://raw.githubusercontent.com/B3B3097/paraser/main/sub_250_20bs.txt
  ```
- 📦 **Base64 (URL):**
  ```
  https://raw.githubusercontent.com/B3B3097/paraser/main/sub_250_20bs_base64.txt
  ```

---

### ⚡ 2. Подписка «BS Top Ping (БС Топ по пингу)»
**Конфигурации Белых Списков с минимальной задержкой (ping):**
- Серверы отсортированы по наименьшему пингу и стабильности отклика.
- Оптимизированы под российских операторов связи (МТС, Мегафон, Билайн, Tele2, Ростелеком).
- Идеально для голосовой связи, игр и мгновенного открытия сайтов во время изоляции сети.

*Последнее обновление: 21.09.2026 17:02 MSK*
- 📄 **Plain Text (URL):**
  ```
  https://raw.githubusercontent.com/B3B3097/paraser/main/sub_bs_top_ping.txt
  ```
- 📦 **Base64 (URL):**
  ```
  https://raw.githubusercontent.com/B3B3097/paraser/main/sub_bs_top_ping_base64.txt
  ```

---

### 🛡️ 3. Подписка «BS Все (Все проверенные Белые Списки)»
**Полный массив всех доступных серверов из Белых Списков:**
- Более 3 000+ валидных конфигураций, прошедших проверку по российским CIDR-диапазонам и валидным SNI.
- Включает все рабочие конфигурации из базы VLESS-For-U, проверенные пулы и источники из `source.txt`.
- Максимальная надёжность и отказоустойчивость при любых сценариях блокировок.

*Последнее обновление: 21.09.2026 17:02 MSK*
- 📄 **Plain Text (URL):**
  ```
  https://raw.githubusercontent.com/B3B3097/paraser/main/sub_bs_all.txt
  ```
- 📦 **Base64 (URL):**
  ```
  https://raw.githubusercontent.com/B3B3097/paraser/main/sub_bs_all_base64.txt
  ```

---

## 📥 Классические и полные пулы подписок

### 4️⃣ Основная подписка (Xray-Verified: OSTATSYA NA SVYAZI)
Проверенные конфиги через Xray core (TCP + TLS + загрузка тестового файла).  
*Последнее обновление: 21.09.2026 17:02 MSK*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI.txt`
- **Base64:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_base64.txt`

### 5️⃣ TCP+TLS подписка (500 серверов)
Топ-500 серверов, прошедших TCP-handshake и TLS-проверку.  
*Последнее обновление: 21.09.2026 17:02 MSK*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls.txt`
- **Base64:** `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls_base64.txt`

### 6️⃣ v2ray_sub.txt (Общий проверенный пул)
*Последнее обновление: 21.09.2026 17:02 MSK*
- **Plain:** `https://raw.githubusercontent.com/B3B3097/paraser/main/v2ray_sub.txt`

### 7️⃣ Дополнительные базы
- **Valid Internet Links:** `https://raw.githubusercontent.com/B3B3097/paraser/main/valid_internet_links.txt`
- **Valid Whitelist Links:** `https://raw.githubusercontent.com/B3B3097/paraser/main/valid_whitelist_links.txt`

---

## 🛠️ Как добавить подписку в клиент

### Android (v2rayNG / Happ / Hiddify / v2RayTun / NekoBox)
1. Скопируйте одну из ссылок подписки выше (рекомендуется **Plain** или **Base64**).
2. Откройте приложение (например, **v2rayNG**).
3. Перейдите в меню слева ➔ **«Группы подписок»** (Subscription groups) ➔ нажмите **«+»**.
4. В поле **«URL подписки»** вставьте скопированную ссылку.
5. Сохраните и в основном меню нажмите **«Обновить подписку»** (Update subscription).

### iOS (Happ / Streisand / FoXray / Shadowrocket / Sing-box)
1. Скопируйте ссылку подписки.
2. В приложении перейдите во вкладку подписок / добавления URL.
3. Вставьте ссылку и выполните импорт / синхронизацию.

### Windows / Linux / macOS (NekoBox / Hiddify / v2rayN / Sing-box)
1. Скопируйте ссылку подписки.
2. Вставьте в раздел подписок и обновите список узлов.

---

## ⚙️ Архитектура и механизм работы

1. **Автоматический сбор:** сканирование 3 600+ открытых источников (GitHub API, raw-ссылки, публичные репозитории, VLESS-For-U базы).
2. **Проверка Белых Списков (БС / Whitelist):**
   - Сопоставление IP адресов с 28 247 CIDR блоками российских сетей (`whitelist_cidr.txt`).
   - Валидация SNI по базе доверенных доменов РФ (`whitelist_sni.txt`).
   - Тестирование доступности портов и рукопожатия TLS.
3. **Обход блокировок ТСПУ:** автоматический подбор и подстановка устойчивых TLS fingerprint (`firefox`, `edge`), эмуляция трафика браузера.
4. **Регулярная автогенерация:** GitHub Actions каждые 2–3 часа запускает цикл проверки, формирует подписки и публикует свежие версии в репозиторий.

---

## 📂 Структура репозитория

- `generate_subscriptions.py` — генератор 3 специализированных подписок (250 c 20 БС, BS Top Ping, BS Все)
- `checker.py` — основной движок тестирования серверов и замера скорости через Xray
- `source.txt` — каталог из 3 630+ проверенных источников
- `whitelist_cidr.txt` — 28 247 доверенных CIDR блоков
- `whitelist_sni.txt` — 23 836 российских SNI доменов
- `status2.txt` & `stats.json` — телеметрия и статистика последнего прогона чекера

---

## 📢 Сообщество и поддержка

Свежие новости, оперативные обновления подписок и резервные каналы:  
**👉 [@REMAININGCONNECTIONS](https://t.me/REMAININGCONNECTIONS)**
