"""Assign targets on the joined interim table: sector and time-to-KEV."""

import argparse
import re
from pathlib import Path

import pandas as pd

from src.config import data_path, load_config

# The 16 CISA critical-infrastructure sectors, keyed by the patterns that
# identify them in advisory free text ("Water and Wastewater", "Healthcare and
# Public Health", "Nuclear Reactors, Materials, and Waste", ...).
SECTOR_PATTERNS = {
    "Chemical": r"\bchemical",
    "Commercial Facilities": r"\bcommercial facilit",
    "Communications": r"\bcommunications?\b",
    "Critical Manufacturing": r"\bman\w*acturing|\bmanufacturer",  # incl. advisory typos
    "Dams": r"\bdams?\b",
    "Defense Industrial Base": r"\bdefen[cs]e",
    "Emergency Services": r"\bemergency",
    "Energy": r"\benergy\b",
    "Financial Services": r"\bfinancial",
    "Food and Agriculture": r"\bfood|\bagricultur",
    "Government Facilities": r"\bgovernment",
    "Healthcare and Public Health": r"\bhealth",
    "Information Technology": r"\binformation technology",
    "Nuclear Reactors, Materials, and Waste": r"\bnuclear",
    "Transportation Systems": r"\btransportation",
    "Water and Wastewater Systems": r"\bwater|\bwastewater",
}
_COMPILED = {s: re.compile(p, re.I) for s, p in SECTOR_PATTERNS.items()}
_CORP_SUFFIXES = {"inc", "ag", "co", "ltd", "llc", "gmbh", "corp", "corporation", "sa", "se", "plc", "company", "kg", "limited"}


def canonical_sectors(raw: str) -> list[str]:
    return [s for s, rx in _COMPILED.items() if rx.search(raw)]


def vendor_key(name: str) -> str:
    """Collapse "Schneider Electric", "schneider-electric", "Schneider Electric SE" to one key."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", name.lower()) if t and t not in _CORP_SUFFIXES]
    return "_".join(tokens)


def primary_vendor(row: pd.Series) -> str:
    for col in ("ics_vendors", "cpe_vendors", "affected_vendors"):
        vals = row.get(col)
        if vals is not None and len(vals):
            return vendor_key(vals[0])
    if isinstance(row.get("kev_vendor"), str):
        return vendor_key(row["kev_vendor"])
    return "unknown"


def sector_labels(interim_dir: Path, cfg: dict) -> pd.DataFrame:
    joined = pd.read_parquet(interim_dir / "joined.parquet")
    ics = joined[joined["in_ics"]].copy()
    ics["sectors"] = ics["sectors_raw"].map(
        lambda raws: sorted({s for r in raws for s in canonical_sectors(r)})
    )
    ics["n_sectors"] = ics["sectors"].map(len)
    ics["sector"] = ics["sectors"].map(lambda s: s[0] if len(s) == 1 else None)
    ics["vendor"] = ics.apply(primary_vendor, axis=1)
    out = ics[["cve_id", "sectors_raw", "sectors", "n_sectors", "sector", "vendor"]]
    out.to_parquet(interim_dir / "labels_sector.parquet", index=False)

    unmatched = sorted({r for raws, s in zip(ics["sectors_raw"], ics["sectors"]) if not s for r in raws})
    print(f"sector: {len(ics)} ICS-listed CVEs, {out['sector'].notna().sum()} single-sector, "
          f"{(out['n_sectors'] == 0).sum()} with no parsable sector")
    if unmatched:
        print("  unmatched sector strings:", unmatched[:10])
    vendor_sector_lookup(joined, out, interim_dir)
    return out


def vendor_sector_lookup(joined: pd.DataFrame, labels: pd.DataFrame, interim_dir: Path) -> pd.DataFrame:
    """Transparent product -> sector lookup: CPE vendor -> its sector distribution in ICS labels.

    Also measures how far this lookup could extend sector labels to NVD CVEs that
    no advisory covers (weak labels, reported in coverage, never used as ground truth).
    """
    labeled = labels.dropna(subset=["sector"]).merge(joined[["cve_id", "cpe_vendors"]], on="cve_id")
    pairs = labeled.explode("cpe_vendors").dropna(subset=["cpe_vendors"])
    lookup = (
        pairs.groupby(["cpe_vendors", "sector"]).size().rename("n").reset_index()
        .rename(columns={"cpe_vendors": "cpe_vendor"})
    )
    lookup["share"] = lookup["n"] / lookup.groupby("cpe_vendor")["n"].transform("sum")
    lookup.to_parquet(interim_dir / "vendor_sector_lookup.parquet", index=False)

    known = set(lookup["cpe_vendor"])
    unlabeled = joined[~joined["in_ics"]]
    reachable = unlabeled["cpe_vendors"].map(lambda vs: any(v in known for v in vs))
    print(f"  vendor lookup: {len(known)} CPE vendors; would weak-label {reachable.sum()} "
          f"of {len(unlabeled)} non-ICS CVEs")
    return lookup


def time_to_kev_labels(interim_dir: Path, cfg: dict) -> pd.DataFrame:
    joined = pd.read_parquet(interim_dir / "joined.parquet")
    kev = joined[joined["in_kev"]].copy()
    published = kev["published"].dt.tz_localize(None).dt.normalize()
    kev["days_to_kev"] = (kev["kev_date_added"] - published).dt.days
    lo, hi = cfg["labels"]["time_to_kev_buckets"]
    kev["time_to_kev"] = pd.cut(
        kev["days_to_kev"], [-float("inf"), lo, hi, float("inf")],
        labels=[f"<={lo}d", f"{lo + 1}-{hi}d", f">{hi}d"],
    ).astype(str)
    kev["vendor"] = kev.apply(primary_vendor, axis=1)
    out = kev[["cve_id", "published", "kev_date_added", "days_to_kev", "time_to_kev", "vendor"]]
    out.to_parquet(interim_dir / "labels_time_to_kev.parquet", index=False)
    print(f"time_to_kev: {len(out)} KEV CVEs in window")
    return out


TARGETS = {"sector": sector_labels, "time_to_kev": time_to_kev_labels}


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", default=",".join(cfg["targets"]))
    args = parser.parse_args()

    interim_dir = data_path(cfg, "interim")
    for target in args.targets.split(","):
        TARGETS[target](interim_dir, cfg)


if __name__ == "__main__":
    main()
