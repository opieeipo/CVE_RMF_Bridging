"""Source -> data/raw/. The only networked step.

Pulls NVD bulk yearly feeds, the CISA KEV catalog, CISA ICS advisories and the
NVD CPE dictionary. Cached files are never fetched twice (check-and-skip).
"""

import argparse
import datetime as dt
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from src.config import data_path, load_config

MAX_WORKERS = 5  # I/O-bound, so threads are fine

NVD_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# CISA publishes ICS advisories as CSAF 2.0 JSON; each carries a
# "Critical infrastructure sectors" note, which is the sector label.
CSAF_RAW = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"
CPE_DICT = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"

session = requests.Session()
session.headers["User-Agent"] = "cve-sector-context-spike (research)"


def fetch(url: str, dest: Path, force: bool = False) -> Path:
    """Download url to dest unless it is already cached. Writes atomically."""
    if dest.exists() and dest.stat().st_size > 0 and not force:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with session.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
    tmp.rename(dest)
    return dest


def pull_nvd_year(year: int, raw_dir: Path) -> Path:
    return fetch(NVD_FEED.format(year=year), raw_dir / "nvd" / f"nvdcve-2.0-{year}.json.gz")


def pull_kev(raw_dir: Path) -> Path:
    return fetch(KEV_URL, raw_dir / "kev" / "known_exploited_vulnerabilities.json")


def ics_advisory_years(years: list[int]) -> list[int]:
    # Advisories can trail or precede NVD publication, so pad the window by a year.
    return list(range(years[0] - 1, min(years[-1] + 1, dt.date.today().year) + 1))


def pull_ics_advisories(raw_dir: Path, years: list[int], limit: int | None) -> list[Path]:
    ics_dir = raw_dir / "ics"
    index = fetch(CSAF_RAW + "index.txt", ics_dir / "index.txt", force=True)
    wanted = {str(y) for y in ics_advisory_years(years)}
    paths = [p for p in index.read_text().split() if p.split("/")[0] in wanted]
    paths.sort(reverse=True)
    if limit:
        paths = paths[:limit]
    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        return list(pool.map(lambda p: fetch(CSAF_RAW + p, ics_dir / p), paths))


def pull_cpe_dictionary(raw_dir: Path) -> Path:
    return fetch(CPE_DICT, raw_dir / "cpe" / "nvdcpe-2.0.tar.gz")


def parse_window(window: str) -> list[int]:
    start, end = (int(y) for y in window.split("-"))
    return list(range(start, end + 1))


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--window", default="-".join(str(y) for y in cfg["window"]))
    parser.add_argument("--limit", type=int, default=None, help="cap ICS advisories for a smoke test")
    args = parser.parse_args()

    raw_dir = data_path(cfg, "raw")
    years = parse_window(args.window)
    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        # CVE-ID year != publication year, so include the prior year's feed too.
        feeds = list(pool.map(lambda y: pull_nvd_year(y, raw_dir), [years[0] - 1, *years]))
        kev = pool.submit(pull_kev, raw_dir)
        cpe = pool.submit(pull_cpe_dictionary, raw_dir)
        ics = pull_ics_advisories(raw_dir, years, args.limit)
        kev, cpe = kev.result(), cpe.result()
    print(f"nvd feeds: {len(feeds)}  kev: {kev.name}  ics advisories: {len(ics)}  cpe: {cpe.name}")


if __name__ == "__main__":
    main()
