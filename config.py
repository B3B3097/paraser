import os
from dotenv import load_dotenv

load_dotenv()

raw_internet_subs = os.getenv("INTERNET_SUBS_POOL", "")
INTERNET_SUBS_POOL = [url.strip() for url in raw_internet_subs.split(",") if url.strip()]

DEFAULT_WHITELIST_SUBS = [
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
]

raw_whitelist_subs = os.getenv("WHITELISTED_SUBS_POOL", "")
WHITELISTED_SUBS_POOL = [url.strip() for url in raw_whitelist_subs.split(",") if url.strip()]
if not WHITELISTED_SUBS_POOL:
    WHITELISTED_SUBS_POOL = DEFAULT_WHITELIST_SUBS

INTERNET_CFGS_COUNT = int(os.getenv("INTERNET_CFGS_COUNT", 10))
WHITELISTED_CFGS_COUNT = int(os.getenv("WHITELISTED_CFGS_COUNT", 500))

CONCURRENT_THREADS_CHECK_DEFAULT = int(os.getenv("CONCURRENT_THREADS_CHECK_DEFAULT", 50))
# 0 = без лимита: проверяем ВСЕ ссылки (из source.txt и пулов)
MAX_LINKS_TO_CHECK_INTERNET = int(os.getenv("MAX_LINKS_TO_CHECK_INTERNET", 0))
MAX_LINKS_TO_CHECK_WHITELIST = int(os.getenv("MAX_LINKS_TO_CHECK_WHITELIST", 0))

# Бюджет времени на проверку (сек). По истечении чекер останавливается и публикует
# те рабочие конфиги, что успел найти. 0 = без бюджета (проверять до конца).
CHECK_TIME_BUDGET_SEC = int(os.getenv("CHECK_TIME_BUDGET_SEC", 0))

print(f"Загружено интернет-ссылок: {len(INTERNET_SUBS_POOL)}")
print(f"Загружено whitelist-ссылок: {len(WHITELISTED_SUBS_POOL)}")
