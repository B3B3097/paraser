import os
from dotenv import load_dotenv

load_dotenv()

raw_internet_subs = os.getenv("INTERNET_SUBS_POOL", "")
INTERNET_SUBS_POOL = [url.strip() for url in raw_internet_subs.split(",") if url.strip()]

raw_whitelist_subs = os.getenv("WHITELISTED_SUBS_POOL", "")
WHITELISTED_SUBS_POOL = [url.strip() for url in raw_whitelist_subs.split(",") if url.strip()]

INTERNET_CFGS_COUNT = int(os.getenv("INTERNET_CFGS_COUNT", 10))
WHITELISTED_CFGS_COUNT = int(os.getenv("WHITELISTED_CFGS_COUNT", 500))

CONCURRENT_THREADS_CHECK_DEFAULT = int(os.getenv("CONCURRENT_THREADS_CHECK_DEFAULT", 50))
MAX_LINKS_TO_CHECK_INTERNET = int(os.getenv("MAX_LINKS_TO_CHECK_INTERNET", 1000))
MAX_LINKS_TO_CHECK_WHITELIST = int(os.getenv("MAX_LINKS_TO_CHECK_WHITELIST", 5000))

print(f"Загружено интернет-ссылок: {len(INTERNET_SUBS_POOL)}")
print(f"Загружено whitelist-ссылок: {len(WHITELISTED_SUBS_POOL)}")
