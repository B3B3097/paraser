<div align="center">

# 🛰️ ОСТАТЬСЯ НА СВЯЗИ

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=22&pause=1000&color=00D4FF&center=true&vCenter=true&width=700&lines=Автоматический+сборщик+VLESS+конфигов;Обновление+каждые+2+часа+🔄;TCP+→+TLS+→+Xray+проверка;Multi-fp+|+ASN+|+SNI+ротация;Обход+ТСПУ+v4.0+«Siberian+Pro»;Только+рабочие+конфиги+✅" alt="Typing SVG" />

[![Telegram](https://img.shields.io/badge/Telegram-@Remainingconnections-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/Remainingconnections)
[![Update](https://img.shields.io/badge/Update-every%202h-brightgreen?style=for-the-badge&logo=github-actions&logoColor=white)](../../actions/workflows/check_and_update.yml)
[![Configs](https://img.shields.io/badge/Configs-200%20Xray%20%7C%20500%20TLS-blue?style=for-the-badge&logo=v2ray&logoColor=white)](./OSTATSYA_NA_SVYAZI.txt)

---

**Высокопроизводительный агрегатор VLESS-конфигураций с глубокой валидацией через ядро Xray.**
*Скрипт обходит блокировки ТСПУ, проверяет реальную скорость загрузки и фильтрует «мертвые» узлы.*

</div>

## 📥 Актуальные подписки

Добавьте одну из ссылок в свой клиент (**v2rayNG, Hiddify, Nekoray, Streisand**) для автоматического получения свежих узлов.

### 1. 🏆 Xray-Verified (Рекомендуемая)
Самые стабильные конфиги. Прошли 3 стадии проверки, включая загрузку тестового файла 200 КБ.
- **Plain Text:** 
  `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI.txt`
- **Base64:** 
  `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_base64.txt`

### 2. ⚡ TCP + TLS (Расширенная)
Топ 500 быстрых серверов. Прошли проверку на рукопожатие (handshake). Больше выбора, выше ротация.
- **Plain Text:** 
  `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls.txt`
- **Base64:** 
  `https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_tcptls_base64.txt`

---

## 🛠️ Как это работает

Пайплайн обработки данных включает 80 параллельных потоков и три уровня фильтрации:

1.  **Сбор:** Парсинг более 500 источников из `source.txt` (GitHub, Telegram, публичные подписки).
2.  **Stage 1 (TCP):** Проверка доступности порта (5s timeout).
3.  **Stage 2 (TLS/REALITY):** Валидация сертификатов и параметров шифрования.
4.  **Stage 3 (Xray Speedtest):** Эмуляция реального трафика через ядро Xray. Замер задержки (latency) и скорости (MBps).
5.  **Geo-Tagging:** Определение страны и присвоение флага (напр. 🇩🇪).
6.  **Siberian Pro:** Применение специфичных параметров для обхода ТСПУ (версия 4.0).

---

## 📱 Поддерживаемые клиенты

| Клиент | Платформа | Инструкция |
|:------:|:---------:|:-----------|
| **v2rayNG** | 🤖 Android | Группы подписок → Нажать `+` → Вставить URL |
| **Hiddify** | 💻🍎🤖 All | Новый профиль → Добавить из ссылки |
| **Nekoray** | 💻 Win/Linux | Группы → Добавить → Тип: Subscription |
| **Streisand** | 🍎 iOS | Добавить конфигурацию → URL подписки |
| **v2rayN** | 💻 Windows | Подписки → Настройка подписок → Добавить |

---

## 📈 Текущая статистика
> Обновляется автоматически. Полные данные в [stats.json](./stats.json).

- **Источников:** ~500
- **Найдено уникальных:** ~145,000
- **Прошли проверку (Verified):** 200 (Top-tier)
- **Средняя скорость:** Зависит от вашего провайдера и региона.

---

## ➕ Добавление источников
Вы можете предложить свой источник, добавив его в `source.txt` через Pull Request. 

**Рекомендуемые дополнения для продвинутых пользователей:**
*   **Маршрутизация:** Для раздельного туннелирования (РФ/Мир) используйте [ru-routing-dat](https://github.com/GrimbirdUsers/ru-routing-dat).
*   **Гейминг:** Списки для игровых сервисов [ru-gaming-blocklist](https://github.com/medvedeff-true/ru-gaming-blocklist).

---

<div align="center">

### [📢 Наш Telegram канал](https://t.me/Remainingconnections)
*Свежие новости, апдейты парсера и помощь сообщества.*

</div>
