"""
tools/baseline_traffic.py

Human-like web crawler for generating realistic baseline traffic while the
IsolationForest ML model trains. Run this in one terminal alongside:

    sudo venv/bin/python -m nids.detectors.ml_train --live --duration 1800 \
        --iface wlan0 --out models/iforest.pkl

What it does (per worker):
  1. Picks a random seed site from SEED_SITES.
  2. Fetches the page with a random User-Agent, realistic headers, and a
     persistent session (cookies + connection reuse, like a real browser).
  3. Parses outbound links, filters them, and queues a handful.
  4. Waits a random "dwell" interval (simulating reading).
  5. Either clicks a same-domain link (intra-site browse) or jumps to a new
     seed (topic switch).
  6. Occasionally takes a longer "idle" break.
  7. Mixes in DNS lookups and small background fetches (favicon, robots.txt,
     static assets) to broaden the feature distribution.

The aim is DISTRIBUTION COVERAGE, not load — single-digit requests per second,
multiple domains, varied ports (80/443), varied payload sizes, varied times of
day. That is what the IsolationForest needs to learn "normal."

Dependencies:
    pip install requests beautifulsoup4

Usage:
    python tools/baseline_traffic.py --workers 3 --duration 1800
    python tools/baseline_traffic.py --duration 0      # run until Ctrl+C
"""

from __future__ import annotations

import argparse
import logging
import random
import signal
import socket
import sys
import threading
import time
from collections import defaultdict
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


logger = logging.getLogger("baseline_traffic")


# -----------------------------------------------------------------------------
# Seeds — deliberately varied: news, wiki, docs, code hosts, search, media.
# Mix of HTTP/HTTPS, different TLDs, different CDNs → richer ML feature space.
# -----------------------------------------------------------------------------
SEED_SITES = [
    "https://en.wikipedia.org/wiki/Special:Random",
    "https://news.ycombinator.com/",
    "https://www.bbc.com/news",
    "https://www.reuters.com/",
    "https://www.theguardian.com/international",
    "https://arstechnica.com/",
    "https://www.nature.com/",
    "https://stackoverflow.com/questions",
    "https://github.com/trending",
    "https://gitlab.com/explore",
    "https://www.reddit.com/r/all/.json",
    "https://duckduckgo.com/html/?q=networking+basics",
    "https://www.python.org/",
    "https://docs.python.org/3/",
    "https://developer.mozilla.org/en-US/",
    "https://www.cloudflare.com/learning/",
    "https://httpbin.org/get",
    "https://httpbin.org/bytes/2048",
    "https://httpbin.org/stream/10",
    "https://www.wikipedia.org/",
    "https://archive.org/",
    "https://www.imdb.com/",
    "https://www.amazon.com/",
    "https://www.ebay.com/",
    "https://www.weather.gov/",
    "https://time.gov/",
    "https://www.nasa.gov/",
    "https://www.kernel.org/",
    "https://www.debian.org/",
    "https://fedoraproject.org/",
]

USER_AGENTS = [
    # Chrome / Firefox / Safari / Edge — recent real-world strings
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
]

ACCEPT_LANGS = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-US,en;q=0.7,hi;q=0.3"]

# Skip binary / gated / auth / infinite-scroll / captcha-heavy destinations.
SKIP_EXT = (
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".exe",
    ".dmg",
    ".iso",
    ".mp4",
    ".mkv",
    ".mov",
    ".mp3",
    ".flac",
    ".wav",
)

SKIP_DOMAINS = {
    "accounts.google.com",
    "login.microsoftonline.com",
    "appleid.apple.com",
    "captcha.cloudflare.com",
    "challenges.cloudflare.com",
}


# -----------------------------------------------------------------------------
# Per-domain rate limiting — don't hammer a single site.
# -----------------------------------------------------------------------------
_last_hit: dict[str, float] = defaultdict(float)
_domain_lock = threading.Lock()
PER_DOMAIN_MIN_GAP_SEC = 3.0


def _wait_domain(url: str) -> None:
    host = urlparse(url).hostname or ""
    with _domain_lock:
        since = time.time() - _last_hit[host]
        if since < PER_DOMAIN_MIN_GAP_SEC:
            wait = PER_DOMAIN_MIN_GAP_SEC - since + random.uniform(0, 1.0)
        else:
            wait = 0.0
        _last_hit[host] = time.time() + wait
    if wait > 0:
        time.sleep(wait)


def _build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(ACCEPT_LANGS),
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive",
        }
    )
    return s


def _extract_links(html: str, base_url: str) -> list[str]:
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []

    links: list[str] = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if any(absolute.lower().endswith(ext) for ext in SKIP_EXT):
            continue
        if parsed.hostname in SKIP_DOMAINS:
            continue
        links.append(absolute)

    random.shuffle(links)
    return links[:40]


def _maybe_fetch_assets(session: requests.Session, base_url: str) -> None:
    """Fire off a couple of typical-browser side requests: favicon, robots."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    assets = [f"{origin}/favicon.ico", f"{origin}/robots.txt"]
    for asset in assets:
        if random.random() < 0.35:
            try:
                _wait_domain(asset)
                session.get(asset, timeout=6, allow_redirects=True)
            except Exception:
                pass


def _dns_noise(host: str) -> None:
    """One extra DNS lookup — broadens UDP/53 feature coverage."""
    try:
        socket.gethostbyname(host)
    except Exception:
        pass


def _fetch(session: requests.Session, url: str, timeout: int = 12) -> tuple[int, str]:
    _wait_domain(url)
    resp = session.get(url, timeout=timeout, allow_redirects=True)
    status = resp.status_code
    ctype = resp.headers.get("Content-Type", "")
    body = resp.text if "text" in ctype or "html" in ctype or "json" in ctype else ""
    return status, body


def _dwell() -> float:
    """
    Human dwell times follow a long tail:
      - 60% quick scan:    3–12 s
      - 30% reading:       12–45 s
      - 8%  deep read:     45–120 s
      - 2%  idle / tab:    120–600 s
    """
    r = random.random()
    if r < 0.60:
        return random.uniform(3, 12)
    if r < 0.90:
        return random.uniform(12, 45)
    if r < 0.98:
        return random.uniform(45, 120)
    return random.uniform(120, 600)


# -----------------------------------------------------------------------------
# Worker
# -----------------------------------------------------------------------------
def worker(worker_id: int, stop_event: threading.Event) -> None:
    session = _build_session()
    current_queue: list[str] = []
    pages = 0
    errors = 0

    while not stop_event.is_set():
        # Refresh session/UA occasionally (new "browser profile")
        if pages and pages % random.randint(15, 30) == 0:
            session.close()
            session = _build_session()
            logger.info(f"[w{worker_id}] session rotated (pages={pages})")

        # Pick next URL: 70% continue current site, 30% jump to a new seed
        if current_queue and random.random() < 0.70:
            url = current_queue.pop(0)
        else:
            url = random.choice(SEED_SITES)
            current_queue.clear()

        host = urlparse(url).hostname or ""
        if host:
            _dns_noise(host)

        try:
            status, body = _fetch(session, url)
            pages += 1
            logger.info(f"[w{worker_id}] {status} {url[:80]}")

            if body and 200 <= status < 300:
                new_links = _extract_links(body, url)
                # Keep queue shallow so we don't drift forever down one site
                current_queue = new_links[:8]
                _maybe_fetch_assets(session, url)
        except requests.RequestException as e:
            errors += 1
            logger.debug(f"[w{worker_id}] err {url[:60]}: {e}")
            current_queue.clear()
        except Exception as e:
            errors += 1
            logger.warning(f"[w{worker_id}] unexpected {type(e).__name__}: {e}")
            current_queue.clear()

        stop_event.wait(_dwell())

    session.close()
    logger.info(f"[w{worker_id}] stopped (pages={pages}, errors={errors})")


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate human-like browsing traffic for ML baseline training."
    )
    parser.add_argument(
        "--workers", type=int, default=3, help="Concurrent 'tabs' (default: 3)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=1800,
        help="Run duration in seconds. 0 = run until Ctrl+C. Default: 1800 (30 min)",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(message)s",
        datefmt="%H:%M:%S",
    )

    stop_event = threading.Event()

    def _shutdown(signum, frame):
        logger.info("Shutdown requested — draining workers …")
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    threads = []
    for i in range(args.workers):
        t = threading.Thread(target=worker, args=(i + 1, stop_event), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(random.uniform(0.5, 2.0))  # stagger startup

    logger.info(
        f"Started {args.workers} workers "
        f"(duration={'∞' if args.duration == 0 else f'{args.duration}s'})"
    )

    try:
        if args.duration > 0:
            stop_event.wait(args.duration)
            stop_event.set()
        else:
            while not stop_event.is_set():
                stop_event.wait(1.0)
    except KeyboardInterrupt:
        stop_event.set()

    for t in threads:
        t.join(timeout=10)

    logger.info("All workers stopped. Baseline traffic generation finished.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
