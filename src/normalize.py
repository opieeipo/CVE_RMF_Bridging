"""data/raw/ -> data/interim/. Stream-parse, flatten, join on CVE id, write Parquet."""

import argparse

from src.config import data_path, load_config


def normalize_nvd(raw_dir, interim_dir, limit: int | None) -> None:
    raise NotImplementedError("stream-parse NVD feeds with ijson; one row per CVE")


def normalize_kev(raw_dir, interim_dir) -> None:
    raise NotImplementedError


def normalize_ics(raw_dir, interim_dir) -> None:
    raise NotImplementedError


def join_on_cve(interim_dir) -> None:
    raise NotImplementedError("merge NVD, KEV and ICS frames on CVE id")


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    raw_dir, interim_dir = data_path(cfg, "raw"), data_path(cfg, "interim")
    normalize_nvd(raw_dir, interim_dir, args.limit)
    normalize_kev(raw_dir, interim_dir)
    normalize_ics(raw_dir, interim_dir)
    join_on_cve(interim_dir)


if __name__ == "__main__":
    main()
