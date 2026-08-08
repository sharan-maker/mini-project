"""
build_dataset.py
-----------------
Builds dataset/dataset.csv (url,label) from completely free sources —
no API keys, no paid signups required:

  - MALICIOUS: OpenPhish free feed (https://openphish.com/feed.txt)
               Public, no registration required.
  - SAFE:      Tranco top sites list (https://tranco-list.eu)
               Free research-grade top-domains ranking, no key needed.

NOTE on "suspicious" label:
  There is no free, ready-made "suspicious" (borderline) URL feed.
  This script produces a SAFE / MALICIOUS dataset by default. True
  "suspicious" examples are best added by hand later (e.g. legitimate
  sites with weak configs, or borderline cases you find during testing) —
  see the manual_suspicious list below, which you can extend yourself
  at zero cost.
"""

import io
import csv
import zipfile
import random
import requests

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
TRANCO_LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"

OUTPUT_PATH = "dataset.csv"

# Optional: hand-picked "suspicious" examples (free — just your own judgment).
# Extend this list yourself with real borderline cases you encounter.
MANUAL_SUSPICIOUS_URLS = [
    # "http://example-newly-registered-lookalike.com",
]

REQUEST_TIMEOUT = 15


def fetch_malicious_urls(limit: int = 500) -> list:
    """Pulls phishing URLs from the free OpenPhish feed (plain text, one URL per line)."""
    print("Fetching malicious URLs from OpenPhish (free feed)...")
    try:
        resp = requests.get(OPENPHISH_FEED_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
        random.shuffle(urls)
        return urls[:limit]
    except Exception as e:
        print(f"[warning] Could not fetch OpenPhish feed: {e}")
        return []


def fetch_safe_urls(limit: int = 500) -> list:
    """Pulls top-ranked domains from the free Tranco list (safe = well-established, high-traffic)."""
    print("Fetching safe domains from Tranco top list (free)...")
    try:
        resp = requests.get(TRANCO_LIST_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            csv_filename = zf.namelist()[0]
            with zf.open(csv_filename) as f:
                lines = f.read().decode("utf-8").splitlines()

        domains = []
        for line in lines[:limit]:
            # Tranco format: rank,domain
            parts = line.split(",")
            if len(parts) == 2:
                domains.append(f"https://{parts[1].strip()}")

        random.shuffle(domains)
        return domains[:limit]
    except Exception as e:
        print(f"[warning] Could not fetch Tranco list: {e}")
        return []


def build_dataset(malicious_limit: int = 500, safe_limit: int = 500):
    malicious_urls = fetch_malicious_urls(malicious_limit)
    safe_urls = fetch_safe_urls(safe_limit)

    rows = []
    rows += [(url, "malicious") for url in malicious_urls]
    rows += [(url, "safe") for url in safe_urls]
    rows += [(url, "suspicious") for url in MANUAL_SUSPICIOUS_URLS]

    random.shuffle(rows)

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)

    print(f"\nDataset written to {OUTPUT_PATH}")
    print(f"  malicious:  {len(malicious_urls)}")
    print(f"  safe:       {len(safe_urls)}")
    print(f"  suspicious: {len(MANUAL_SUSPICIOUS_URLS)}  (add more manually for a real 3-class model)")
    print(f"  TOTAL:      {len(rows)}")


if __name__ == "__main__":
    # Start small while testing — increase limits once you're ready for full training
    build_dataset(malicious_limit=200, safe_limit=200)