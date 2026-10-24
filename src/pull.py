"""Source -> data/raw/. The only networked step.

Pulls NVD bulk yearly feeds, the CISA KEV catalog, CISA ICS advisories and the
NVD CPE dictionary. Cached files are never fetched twice (check-and-skip).
"""

import argparse

from src.config import data_path, load_config

MAX_WORKERS = 5  # I/O-bound, so threads are fine


def pull_nvd_year(year: int, raw_dir) -> None:
    raise NotImplementedError("NVD JSON 2.0 bulk yearly gzip feed")


def pull_kev(raw_dir) -> None:
    raise NotImplementedError("CISA KEV catalog JSON")


def pull_ics_advisories(raw_dir, limit: int | None) -> None:
    raise NotImplementedError("CISA ICS advisories (sector tags)")


def pull_cpe_dictionary(raw_dir) -> None:
    raise NotImplementedError("NVD CPE dictionary")


def parse_window(window: str) -> list[int]:
    start, end = (int(y) for y in window.split("-"))
    return list(range(start, end + 1))


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--window", default="-".join(str(y) for y in cfg["window"]))
    parser.add_argument("--limit", type=int, default=None, help="cap rows for a smoke test")
    args = parser.parse_args()

    raw_dir = data_path(cfg, "raw")
    years = parse_window(args.window)
    # TODO: pull years concurrently with ThreadPoolExecutor(MAX_WORKERS)
    for year in years:
        pull_nvd_year(year, raw_dir)
    pull_kev(raw_dir)
    pull_ics_advisories(raw_dir, args.limit)
    pull_cpe_dictionary(raw_dir)


if __name__ == "__main__":
    main()
