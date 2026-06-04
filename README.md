# VLESS Ultimate Parser 🛜

Автоматический парсер и валидатор VLESS конфигураций с многоуровневой проверкой.

## 🌟 Возможности

- **Многоуровневая проверка**: TCP, TLS, WebSocket
- **Автоматическое обновление**: каждые 2 часа
- **Дедупликация**: удаление дубликатов конфигов
- **Белый/чёрный список**: фильтрация по SNI и паттернам
- **Base64 кодирование**: подписи для клиентов (Clash, V2Ray и т.д.)
- **Статистика**: отслеживание количества конфигов
- **GitHub Actions**: полная автоматизация

## 📋 Источники

- igareck/vpn-configs-for-russia (приоритет)
- SilentGhostCodes/WhiteListVpn
- zieng2/wl

## 🔗 Получение подписей

### Plain текст (для V2Ray, Xray):
```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI.txt
```

### Base64 (для Clash, другие клиенты):
```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI_base64.txt
```

### WAR формат (sub-store):
```
https://raw.githubusercontent.com/B3B3097/paraser/main/OSTATSYA_NA_SVYAZI.war
```

## 📊 Статистика

Статистика обновлений доступна в:
```
https://raw.githubusercontent.com/B3B3097/paraser/main/stats.json
```

## 🛠️ Локальный запуск

```bash
# Установка зависимостей
pip install requests pysocks

# Запуск парсера
python parser.py

# С автоматической отправкой в GitHub
python parser.py --push
```

## ⚙️ Конфигурация

Параметры в `parser.py`:
- `max_keys`: 400 (максимальное количество конфигов)
- `tcp_timeout`: 3.0 сек
- `tls_timeout`: 5.0 сек
- `http_timeout`: 8.0 сек
- `max_latency`: 1500 мс

## 📝 Дополнительные файлы

Создай для более гибкой настройки:

**`sources.txt`** - дополнительные источники (один URL на строку):
```
https://example.com/vless.txt
https://example2.com/configs.txt
```

**`sni_whitelist.txt`** - дополнительные белые домены (один домен на строку):
```
example.ru
test.com
```

**`blacklist.txt`** - чёрный список паттернов (один паттерн на строку):
```
badactor.com
spam.ru
```

## 🔄 GitHub Actions

Автоматический запуск:
- ⏰ По расписанию: каждые 2 часа
- 🚀 Вручную: через кнопку "Run workflow"

## 📧 Контакты

ТГ: [@Remainingconnections](https://t.me/Remainingconnections)

---

**Последнее обновление**: смотри `stats.json`
