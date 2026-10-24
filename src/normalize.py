"""data/raw/ -> data/interim/. Stream-parse, flatten, join on CVE id, write Parquet."""

import argparse
import gzip
import json
import tarfile
from pathlib import Path

import ijson
import pandas as pd

from src.config import data_path, load_config

# CVSS preference: the v3 family is the most complete across the window; v4 and
# v2 fill gaps. Within a version, NVD's own "Primary" score wins.
CVSS_PREFERENCE = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]


def _pick_cvss(metrics: dict) -> tuple[str | None, str | None, float | None]:
    for key in CVSS_PREFERENCE:
        entries = metrics.get(key) or []
        if entries:
            entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = entry["cvssData"]
            return data.get("version"), data.get("vectorString"), float(data["baseScore"])
    return None, None, None


def _cpe_vendor_products(cve: dict) -> tuple[set[str], set[str]]:
    vendors, products = set(), set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match["criteria"].split(":")
                if len(parts) > 4 and match.get("vulnerable", True):
                    vendors.add(parts[3])
                    products.add(parts[4])
    return vendors, products


def parse_nvd_record(cve: dict) -> dict:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    cwes = sorted({
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d["value"].startswith("CWE-")
    })
    version, vector, score = _pick_cvss(cve.get("metrics", {}))
    cpe_vendors, cpe_products = _cpe_vendor_products(cve)
    aff_vendors, aff_products = set(), set()
    for a in cve.get("affected", []):
        for d in a.get("affectedData", []):
            if d.get("vendor"):
                aff_vendors.add(d["vendor"])
            if d.get("product"):
                aff_products.add(d["product"])
    return {
        "cve_id": cve["id"],
        "published": cve["published"],
        "vuln_status": cve.get("vulnStatus"),
        "source": cve.get("sourceIdentifier"),
        "description": desc,
        "cwes": cwes,
        "cvss_version": version,
        "cvss_vector": vector,
        "cvss_score": score,
        "cpe_vendors": sorted(cpe_vendors),
        "cpe_products": sorted(cpe_products),
        "affected_vendors": sorted(aff_vendors),
        "affected_products": sorted(aff_products),
    }


def normalize_nvd(raw_dir: Path, interim_dir: Path, years: list[int], limit: int | None) -> pd.DataFrame:
    rows = []
    for year in [years[0] - 1, *years]:
        path = raw_dir / "nvd" / f"nvdcve-2.0-{year}.json.gz"
        n = 0
        with gzip.open(path) as f:
            for item in ijson.items(f, "vulnerabilities.item"):
                cve = item["cve"]
                if cve.get("vulnStatus") == "Rejected":
                    continue
                rows.append(parse_nvd_record(cve))
                n += 1
                if limit and n >= limit:
                    break
    df = pd.DataFrame(rows)
    df["published"] = pd.to_datetime(df["published"])
    df["year"] = df["published"].dt.year
    # Yearly feeds are keyed by CVE-ID year; keep only CVEs *published* in the window.
    df = df[df["year"].between(years[0], years[-1])].drop_duplicates("cve_id")
    df.to_parquet(interim_dir / "nvd.parquet", index=False)
    return df


def normalize_kev(raw_dir: Path, interim_dir: Path) -> pd.DataFrame:
    with open(raw_dir / "kev" / "known_exploited_vulnerabilities.json") as f:
        kev = json.load(f)["vulnerabilities"]
    df = pd.DataFrame({
        "cve_id": [v["cveID"] for v in kev],
        "kev_date_added": pd.to_datetime([v["dateAdded"] for v in kev]),
        "kev_vendor": [v["vendorProject"] for v in kev],
        "kev_product": [v["product"] for v in kev],
        "kev_ransomware": [v.get("knownRansomwareCampaignUse") for v in kev],
    })
    df.to_parquet(interim_dir / "kev.parquet", index=False)
    return df


def _walk_branches(branches: list[dict], vendors: set[str], products: set[str]) -> None:
    for b in branches:
        if b.get("category") == "vendor":
            vendors.add(b["name"])
        elif b.get("category") == "product_name":
            products.add(b["name"])
        _walk_branches(b.get("branches", []), vendors, products)


def parse_csaf(doc: dict) -> dict:
    notes = {n.get("title"): n.get("text", "") for n in doc["document"].get("notes", [])}
    vendors, products = set(), set()
    _walk_branches(doc.get("product_tree", {}).get("branches", []), vendors, products)
    return {
        "advisory_id": doc["document"]["tracking"]["id"],
        "release_date": doc["document"]["tracking"].get("initial_release_date"),
        "sectors_raw": notes.get("Critical infrastructure sectors"),
        "ics_vendors": sorted(vendors),
        "ics_products": sorted(products),
        "cves": sorted({v["cve"] for v in doc.get("vulnerabilities", []) if v.get("cve")}),
    }


def normalize_ics(raw_dir: Path, interim_dir: Path) -> pd.DataFrame:
    rows = []
    for path in sorted((raw_dir / "ics").glob("*/*.json")):
        with open(path) as f:
            rows.append(parse_csaf(json.load(f)) | {"file": path.name})
    df = pd.DataFrame(rows)
    df["release_date"] = pd.to_datetime(df["release_date"], utc=True, format="ISO8601")
    df.to_parquet(interim_dir / "ics_advisories.parquet", index=False)
    return df


def normalize_cpe_titles(raw_dir: Path, interim_dir: Path, vendors: set[str]) -> pd.DataFrame | None:
    """vendor:product -> English title from the CPE dictionary, for vendors we actually see."""
    path = raw_dir / "cpe" / "nvdcpe-2.0.tar.gz"
    if not path.exists():
        print("cpe dictionary not pulled yet; skipping titles")
        return None
    seen, rows = set(), []
    with tarfile.open(path) as tar:
        for member in tar:
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            for item in ijson.items(tar.extractfile(member), "products.item"):
                cpe = item["cpe"]
                parts = cpe["cpeName"].split(":")
                key = (parts[3], parts[4])
                if parts[3] not in vendors or key in seen:
                    continue
                seen.add(key)
                title = next((t["title"] for t in cpe.get("titles", []) if t["lang"] == "en"), None)
                rows.append({"vendor": parts[3], "product": parts[4], "title": title})
    df = pd.DataFrame(rows)
    df.to_parquet(interim_dir / "cpe_titles.parquet", index=False)
    return df


def join_on_cve(nvd: pd.DataFrame, kev: pd.DataFrame, ics: pd.DataFrame, interim_dir: Path) -> pd.DataFrame:
    per_cve = (
        ics.explode("cves")
        .dropna(subset=["cves"])
        .rename(columns={"cves": "cve_id"})
        .groupby("cve_id")
        .agg(
            ics_advisories=("advisory_id", lambda s: sorted(set(s))),
            ics_first_release=("release_date", "min"),
            sectors_raw=("sectors_raw", lambda s: sorted({x for x in s if isinstance(x, str)})),
            ics_vendors=("ics_vendors", lambda s: sorted({v for vs in s for v in vs})),
            ics_products=("ics_products", lambda s: sorted({p for ps in s for p in ps})),
        )
        .reset_index()
    )
    joined = nvd.merge(kev, on="cve_id", how="left").merge(per_cve, on="cve_id", how="left")
    joined["in_kev"] = joined["kev_date_added"].notna()
    joined["in_ics"] = joined["ics_advisories"].notna()
    joined.to_parquet(interim_dir / "joined.parquet", index=False)
    return joined


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="cap NVD rows per year")
    args = parser.parse_args()

    raw_dir, interim_dir = data_path(cfg, "raw"), data_path(cfg, "interim")
    interim_dir.mkdir(parents=True, exist_ok=True)
    years = list(range(cfg["window"][0], cfg["window"][1] + 1))
    nvd = normalize_nvd(raw_dir, interim_dir, years, args.limit)
    kev = normalize_kev(raw_dir, interim_dir)
    ics = normalize_ics(raw_dir, interim_dir)
    joined = join_on_cve(nvd, kev, ics, interim_dir)
    vendors = {v for vs in joined["cpe_vendors"] for v in vs}
    normalize_cpe_titles(raw_dir, interim_dir, vendors)
    print(
        f"nvd: {len(nvd)}  kev: {len(kev)}  ics advisories: {len(ics)}  "
        f"joined: {len(joined)}  in_kev: {joined['in_kev'].sum()}  in_ics: {joined['in_ics'].sum()}"
    )


if __name__ == "__main__":
    main()
