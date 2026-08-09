#!/bin/bash
# Скрипт для отправки статистики в Telegram
# Запускается вручную или автоматически после workflow

set -u

# ── Секреты репозитория (из .env) ──
source .env 2>/dev/null || {
    echo "❌ Не найдено .env файл"
    exit 1
}

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

# Проверка секротов
if [ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]; then
    echo "❌ Не найдены секреты:"
    echo "  TELEGRAM_BOT_TOKEN"
    echo "  TELEGRAM_CHAT_ID"
    exit 1
fi

# ── Читаем конфигурацию из noty-telegram.yaml ──
CONFIG_FILE="${1:-noty-telegram.yaml}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Конфигурация не найдена: $CONFIG_FILE"
    exit 1
fi

# Заменяем переменные в конфиге на реальные значения (если они есть)
sed -i 's/\${TELEGRAM_BOT_TOKEN}/'"$TELEGRAM_BOT_TOKEN"'/g' "$CONFIG_FILE"
sed -i 's/\${TELEGRAM_CHAT_ID}/'"$TELEGRAM_BOT_TOKEN"'/g' "$CONFIG_FILE"

source "$CONFIG_FILE"

# Проверка секротов
if [ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]; then
    echo "❌ Не найдены секреты из конфига:"
    echo "  TELEGRAM_BOT_TOKEN"
    echo "  echo "
    echo "  TELEGRAM_CHAT_ID"
    exit 1
fi

# ── Кол-во конфигов в v2ray_sub.txt ──
CONFIG_COUNT=0
if [ -f v2ray_sub.txt ]; then
    CONFIG_COUNT=$(wc -l < v2ray_sub.txt | tr -d " ")
fi

# ── Данные из status2.txt (написан checker-воркфлоу) ──
INTERNET=0; WHITELIST=0; TOTAL=0; LAST_UPDATE=""
if [ -f status2.txt ]; then
    INTERNET=$(jq -r ".internet_count // 0" status2.txt 2>/dev/null || echo 0)
    WHITELIST=$(jq -r ".whitelist_count // 0" status2.txt 2>/dev/null || echo 0)
    TOTAL=$(jq -r ".total_count // 0" status2.txt 2>/dev/null || echo 0)
    LAST_UPDATE=$(jq -r ".last_update_msk // \"\"" status2.txt 2>/dev/null || echo "")
fi

[ -z "$LAST_UPDATE" ] && LAST_UPDATE=$(TZ="Europe/Moscow" date "+%d.%m.%Y %H:%M MSK")
[ "$CONFIG_COUNT" -eq 0 ] && [ "$TOTAL" -gt 0 ] 2>/dev/null && CONFIG_COUNT=$TOTAL

# ── Было обновлено? (последний коммит от бота за последние 20 мин) ──
UPDATED="❌ нет"
LAST_AUTHOR=$(git log -1 --pretty=format:"%an" 2>/dev/null || echo "")
LAST_TS=$(git log -1 --pretty=format:"%ct" 2>/dev/null || echo 0)
NOW=$(date +%s)
if [ "$LAST_AUTHOR" = "github-actions[bot]" ] && [ "$LAST_TS" -gt 0 ]; then
    AGE=$((NOW - LAST_TS))
    if [ "$AGE" -lt 1200 ]; then
        UPDATED="✅ да"
    fi
fi

# ── Сообщение ──
MSG="📡 OSTATSYA NA SVYAZI — статистика обновления
━━━━━━━━━━━━━━━━━━
📁 Файл: v2ray_sub.txt
🔢 Конфигов: ${CONFIG_COUNT} (I: ${INTERNET} · W: ${WHITELIST})
🔄 Обновлено: ${UPDATED}
🕐 Время: ${LAST_UPDATE}
━━━━━━━━━━━━━━━━━━"

# ── Отправка в Telegram ──
curl -fsSL -X POST \
"https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
--data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
--data-urlencode "text=${MSG}" \
--data-urlencode "disable_web_page_preview=true"

echo "✅ Уведомление отправлено в Telegram"

# ── Получаем сообщение (опционально) ──
if [ -n "$2" ]; then
    MSG="$2"
else

