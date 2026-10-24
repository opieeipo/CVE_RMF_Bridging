"""Label-noise and leakage diagnostics that qualify the gate results. Reads cached files only."""

import json
import re

import numpy as np
import pandas as pd
import scipy.sparse as sp

from src.config import data_path, load_config
from src.experiment import cross_validate, folds, load_target
from src.sector_v2 import canon

# Language NVD descriptions gain when exploitation is known; for time-to-KEV it
# may be post-hoc (added after KEV listing) rather than disclosure-time.
EXPLOIT_RX = re.compile(r"exploited in the wild|actively exploited|aware of (?:a )?reports?|has been exploited|known to be exploited", re.I)


def third_party_share(joined: pd.DataFrame, labels: pd.DataFrame) -> dict:
    """Single-sector CVEs whose advisory vendor is absent from the CVE's own CPE/affected vendors."""
    rows = labels.dropna(subset=["sector"]).merge(joined, on="cve_id")
    def mismatch(r):
        own = {canon(v) for v in [*r["cpe_vendors"], *r["affected_vendors"]]} - {"", "na"}
        ics = {canon(v) for v in r["ics_vendors"]}
        if not own:
            return np.nan
        return not any(a in b or b in a for a in ics for b in own)
    m = rows.apply(mismatch, axis=1)
    return {"checked": int(m.notna().sum()), "third_party": int(m.sum()), "share": float(m.mean())}


def duplicate_share(rows: pd.DataFrame) -> float:
    return float(rows["text_masked"].duplicated(keep=False).mean())


def exploit_language(rows: pd.DataFrame) -> dict:
    hit = rows["description"].str.contains(EXPLOIT_RX)
    return {k: round(float(v), 3) for k, v in hit.groupby(rows["label"]).mean().items()}


def exploit_ablated_f1(processed_dir, cfg: dict) -> dict:
    """time-to-KEV masked text with exploitation phrases removed, refit from scratch."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    rows, _ = load_target(processed_dir, "time_to_kev", cfg)
    text = rows["text_masked"].str.replace(EXPLOIT_RX, " ", regex=True)
    X = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2,
                        token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_]+\b").fit_transform(text)
    out = {}
    for grouped in (False, True):
        r = cross_validate(sp.csr_matrix(X), rows, "logreg", folds(rows, grouped, cfg), cfg)
        out["grouped" if grouped else "stratified"] = round(r["macro_f1_mean"], 3)
    return out


def main() -> None:
    cfg = load_config()
    interim, processed = data_path(cfg, "interim"), data_path(cfg, "processed")
    if not (processed / "results_time_to_kev.json").exists():
        print("diagnostics: no full results yet; skipping")
        return
    joined = pd.read_parquet(interim / "joined.parquet")
    sector_labels = pd.read_parquet(interim / "labels_sector.parquet")
    sector_rows = pd.read_parquet(processed / "rows_sector.parquet")
    ttk_rows = pd.read_parquet(processed / "rows_time_to_kev.parquet")
    single = sector_rows["vendor"].value_counts()
    out = {
        "sector_third_party_components": third_party_share(joined, sector_labels),
        "sector_top_vendor_share": {"vendor": single.index[0], "share": round(float(single.iloc[0] / single.sum()), 3)},
        "sector_duplicate_masked_text_share": round(duplicate_share(sector_rows), 3),
        "ttk_duplicate_masked_text_share": round(duplicate_share(ttk_rows), 3),
        "ttk_exploit_language_rate_by_class": exploit_language(ttk_rows),
        "ttk_masked_f1_without_exploit_language": exploit_ablated_f1(processed, cfg),
        "ttk_negative_days": int((pd.read_parquet(interim / "labels_time_to_kev.parquet")["days_to_kev"] < 0).sum()),
    }
    (processed / "diagnostics.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
