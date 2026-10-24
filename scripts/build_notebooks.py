"""Write the three spike notebooks. Logic lives in src/; notebooks only call and display.

Usage: python scripts/build_notebooks.py && jupyter nbconvert --execute --inplace notebooks/*.ipynb
"""

from pathlib import Path

import nbformat as nbf

NB_DIR = Path(__file__).resolve().parent.parent / "notebooks"

SETUP = """\
import pandas as pd
from src.config import load_config, data_path

pd.set_option("display.width", 140)
cfg = load_config()
interim, processed = data_path(cfg, "interim"), data_path(cfg, "processed")"""

NOTEBOOKS = {
    "00_coverage.ipynb": [
        ("md", """\
# 00 - Coverage (Q1, run first)

Do sector labels exist in volume? Label counts and sector balance.

**Pass (pre-registered in `config.yaml` → `gates.q1`):** >= 2,000 single-sector CVEs,
>= 5 sectors with >= 50 CVEs each, no sector above 60% of labeled CVEs. Otherwise pivot to time-to-KEV."""),
        ("code", SETUP),
        ("code", """\
joined = pd.read_parquet(interim / "joined.parquet")
labels = pd.read_parquet(interim / "labels_sector.parquet")
funnel = pd.Series({
    "NVD CVEs published in window": len(joined),
    "listed in a CISA ICS advisory": int(joined["in_ics"].sum()),
    ">= 1 canonical sector": int((labels["n_sectors"] >= 1).sum()),
    "exactly 1 sector (primary task)": int(labels["sector"].notna().sum()),
    "2+ sectors (multi-label only)": int((labels["n_sectors"] >= 2).sum()),
    "'Multiple Sectors' / unparsable": int((labels["n_sectors"] == 0).sum()),
    "in KEV (time-to-KEV fallback)": int(joined["in_kev"].sum()),
})
funnel.to_frame("CVEs")"""),
        ("md", "## Primary task: single-sector CVEs"),
        ("code", """\
single = labels.dropna(subset=["sector"])
dist = single["sector"].value_counts().to_frame("CVEs")
dist["share"] = (dist["CVEs"] / dist["CVEs"].sum()).round(3)
dist["vendors"] = single.groupby("sector")["vendor"].nunique()
dist"""),
        ("md", "## Multi-label prevalence (any CVE with >= 1 sector)"),
        ("code", """\
multi = labels[labels["n_sectors"] >= 1]
prev = multi.explode("sectors")["sectors"].value_counts().to_frame("CVEs")
prev["prevalence"] = (prev["CVEs"] / len(multi)).round(3)
prev"""),
        ("md", """\
## Vendor concentration

A sector classifier trained on a handful of vendors learns vendors, not sectors.
This is why Q2 is also scored on a vendor-grouped split."""),
        ("code", """\
top = single["vendor"].value_counts().head(10).to_frame("CVEs")
top["share"] = (top["CVEs"] / len(single)).round(3)
top["top sector"] = single.groupby("vendor")["sector"].agg(lambda s: s.value_counts().index[0])
print(f"{single['vendor'].nunique()} vendors across {len(single)} single-sector CVEs")
top"""),
        ("md", "## Fallback target: time-to-KEV"),
        ("code", """\
ttk = pd.read_parquet(interim / "labels_time_to_kev.parquet")
print(ttk["days_to_kev"].describe().round(1).to_dict())
ttk["time_to_kev"].value_counts().to_frame("CVEs")"""),
        ("md", "## Q1 decision"),
        ("code", """\
from src.gates import q1_coverage

q1 = q1_coverage(labels, cfg)
q1"""),
    ],
    "01_signal.ipynb": [
        ("md", """\
# 01 - Signal (Q2)

Text -> target with product/vendor tokens masked, against a majority-class baseline.

**Pass (pre-registered `gates.q2`):** masked macro-F1 >= majority + 0.15 (stratified 5-fold).
If the vendor-grouped split keeps < +0.05 over majority, the signal is vendor-specific."""),
        ("code", SETUP),
        ("code", """\
import json

results = {t: json.loads((processed / f"results_{t}.json").read_text()) for t in cfg["targets"]}
rows = []
for target, r in results.items():
    for name, run in r["signal"].items():
        rows.append({"target": target, "run": name, "macro_f1": run["macro_f1_mean"],
                     "sd": run["macro_f1_sd"], "accuracy": run["accuracy_mean"], "n": run["n"]})
pd.DataFrame(rows).round(3)"""),
        ("md", "## Masking example"),
        ("code", """\
feats = pd.read_parquet(processed / "rows_sector.parquet")
for _, r in feats.sample(3, random_state=1).iterrows():
    print(r["cve_id"], r["label"]); print("  raw:   ", r["description"][:300]); print("  masked:", r["text_masked"][:300]); print()"""),
        ("md", "## Per-class (masked text, stratified)"),
        ("code", """\
for target, r in results.items():
    print(target)
    display(pd.DataFrame(r["signal"]["masked"]["per_class"]).T.round(3))"""),
        ("md", "## Q2 decision"),
        ("code", "{t: r['q2'] for t, r in results.items()}"),
    ],
    "02_ablation.ipynb": [
        ("md", """\
# 02 - Ablation (Q3)

Same model, shrinking feature sets from `config.yaml`. Plot the degradation curve.

**Pass (pre-registered `gates.q3`):** the text-free `[cwe, cvss]` set retains >= 50% of the
full model's macro-F1 gain over majority (25-50% = degrades, < 25% = cliff)."""),
        ("code", SETUP),
        ("code", """\
import json
import matplotlib.pyplot as plt

results = {t: json.loads((processed / f"results_{t}.json").read_text()) for t in cfg["targets"]}
fig, axes = plt.subplots(1, len(results), figsize=(6 * len(results), 4), squeeze=False)
for ax, (target, r) in zip(axes[0], results.items()):
    abl = pd.DataFrame(r["ablation"])
    ax.errorbar(abl["feature_set"], abl["macro_f1_mean"], yerr=abl["macro_f1_sd"], marker="o", capsize=3)
    ax.axhline(r["signal"]["majority"]["macro_f1_mean"], ls="--", c="grey", label="majority")
    ax.set_title(f"{target} (masked text, stratified 5-fold)")
    ax.set_ylabel("macro-F1"); ax.set_ylim(0, 1); ax.legend(); ax.tick_params(axis="x", rotation=20)
fig.tight_layout()
for target, r in results.items():
    print(target); display(pd.DataFrame(r["ablation"])[["feature_set", "macro_f1_mean", "macro_f1_sd", "accuracy_mean"]].round(3))"""),
        ("md", "## Q3 decision"),
        ("code", "{t: r['q3'] for t, r in results.items()}"),
    ],
}


def main() -> None:
    for name, cells in NOTEBOOKS.items():
        nb = nbf.v4.new_notebook()
        nb.cells = [nbf.v4.new_markdown_cell(s) if kind == "md" else nbf.v4.new_code_cell(s) for kind, s in cells]
        nb.metadata["kernelspec"] = {"name": "python3", "display_name": "Python 3", "language": "python"}
        nbf.write(nb, NB_DIR / name)
        print("wrote", name)


if __name__ == "__main__":
    main()
