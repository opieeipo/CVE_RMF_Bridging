"""Assign targets on the joined interim table: sector and time-to-KEV."""

import argparse

from src.config import data_path, load_config


def sector_labels(interim_dir) -> None:
    raise NotImplementedError("sector tags from ICS advisories, plus CPE product -> sector lookup")


def time_to_kev_labels(interim_dir) -> None:
    raise NotImplementedError("days from CVE publication to KEV dateAdded")


TARGETS = {"sector": sector_labels, "time_to_kev": time_to_kev_labels}


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", default=",".join(cfg["targets"]))
    args = parser.parse_args()

    interim_dir = data_path(cfg, "interim")
    for target in args.targets.split(","):
        TARGETS[target](interim_dir)


if __name__ == "__main__":
    main()
