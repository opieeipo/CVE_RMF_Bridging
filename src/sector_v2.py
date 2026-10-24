"""Sector v2: CVE -> sector exposure as an RMF input. Reads the v1 cache only.

Multi-label sector sets with third-party-link hygiene, a transparent
product -> vendor -> prior lookup scored on a temporal split, and a text + CWE +
CVSS model scored on unseen vendors. Gates: config.yaml -> sector_v2.

Lookup keys come from the NVD side of the record only (CPE and CVE 5 "affected"),
never from the advisory, so the lookup applies to any CVE, ICS-listed or not.
"""

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score
from sklearn.model_selection import GroupKFold
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer, normalize

from src.config import data_path, load_config
from src.features import _cvss_tokens
from src.labels import canonical_sectors, vendor_key

CM = "Critical Manufacturing"


# ---------- labels

ALIASES = {"ni": "nationalinstruments"}


def canon(name: str) -> str:
    """Separator-free vendor key: "Mitsubishi Electric", "mitsubishi_electric", "mitsubishielectric" -> one key."""
    k = re.sub(r"[^a-z0-9]", "", vendor_key(name))
    return ALIASES.get(k, k)


def _own_vendors(row) -> set[str]:
    return {canon(v) for v in [*row["cpe_vendors"], *row["affected_vendors"]]} - {"", "na"}


def _vendor_match(ics: set[str], own: set[str]) -> bool:
    return any(a in b or b in a for a in ics for b in own)


def build_labels(interim: Path) -> tuple[pd.DataFrame, dict]:
    joined = pd.read_parquet(interim / "joined.parquet")
    ics = pd.read_parquet(interim / "ics_advisories.parquet")
    links = (
        ics.explode("cves").dropna(subset=["cves"]).rename(columns={"cves": "cve_id"})
        [["advisory_id", "cve_id", "sectors_raw", "ics_vendors"]]
        .merge(joined, on="cve_id", suffixes=("_adv", ""))
    )
    links["adv_sectors"] = links["sectors_raw_adv"].map(lambda r: canonical_sectors(r) if isinstance(r, str) else [])
    own = links.apply(_own_vendors, axis=1)
    adv_vendors = links["ics_vendors_adv"].map(lambda vs: {canon(v) for v in vs})
    # Unverifiable links (no NVD-side vendor) are kept; mismatched ones are third-party.
    links["third_party"] = [bool(o) and not _vendor_match(a, o) for a, o in zip(adv_vendors, own)]
    kept = links[~links["third_party"]]

    per_cve = kept.groupby("cve_id")["adv_sectors"].agg(lambda s: sorted({x for xs in s for x in xs}))
    labels = joined.set_index("cve_id").loc[per_cve.index].reset_index()
    labels["sectors"] = per_cve.to_numpy()
    labels = labels[labels["sectors"].map(len) > 0].reset_index(drop=True)
    labels["vendor_keys"] = [_own_vendors(r) | {canon(v) for v in r["ics_vendors"]} for _, r in labels.iterrows()]
    labels["vendor"] = [canon(r["ics_vendors"][0]) if len(r["ics_vendors"]) else min(r["vendor_keys"], default=r["cve_id"])
                        for _, r in labels.iterrows()]
    labels["vendor_component"] = vendor_components(labels)
    hygiene = {
        "links": int(len(links)),
        "third_party_links_dropped": int(links["third_party"].sum()),
        "unverifiable_links_kept": int((own.map(len) == 0).sum()),
    }
    return labels, hygiene


def vendor_components(labels: pd.DataFrame) -> pd.Series:
    """Fold groups: connected components over each CVE's vendor keys, so no vendor spans two folds."""
    parent: dict[str, str] = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    keysets = [_own_vendors(r) | {canon(v) for v in r["ics_vendors"]} or {f"cve:{r['cve_id']}"}
               for _, r in labels.iterrows()]
    for ks in keysets:
        ks = list(ks)
        for k in ks[1:]:
            parent[find(k)] = find(ks[0])
    return pd.Series([find(next(iter(ks))) for ks in keysets], index=labels.index)


# ---------- lookup

PLACEHOLDERS = {"", "na", "n_a", "unknown"}


def _keys(row, only_vendors: set[str] | None = None) -> tuple[set[str], set[str]]:
    """(product keys, vendor keys). only_vendors restricts to those vendors (used when fitting)."""
    def ok(v: str) -> bool:
        return v not in PLACEHOLDERS and (only_vendors is None or _vendor_match(only_vendors, {v}))
    products = {f"cpe::{canon(v)}::{vendor_key(p)}" for v in row["cpe_vendors"] for p in row["cpe_products"]
                if ok(canon(v)) and vendor_key(p) not in PLACEHOLDERS}
    products |= {f"aff::{canon(v)}::{vendor_key(p)}" for v in row["affected_vendors"] for p in row["affected_products"]
                 if ok(canon(v)) and vendor_key(p) not in PLACEHOLDERS}
    return products, {v for v in _own_vendors(row) if ok(v)}


class SectorLookup:
    """product -> vendor -> prior. Scores are the share of training CVEs under a key carrying each sector."""

    def fit(self, rows: pd.DataFrame, Y: np.ndarray):
        # Sector tags belong to the advisory vendor's product, so only its keys get credit
        # (a Siemens advisory relisting a Linux CVE says nothing about Linux).
        self.prior = Y.mean(axis=0)
        self.tables = {}
        for level in (0, 1):
            sums, counts = {}, {}
            for keys, y in zip(rows["fit_keys"], Y):
                for k in keys[level]:
                    sums[k] = sums.get(k, 0) + y
                    counts[k] = counts.get(k, 0) + 1
            self.tables[level] = {k: sums[k] / counts[k] for k in sums}
        return self

    def predict(self, rows: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        scores, level_used = [], []
        for keys in rows["keys"]:
            for level in (0, 1):
                hits = [self.tables[level][k] for k in keys[level] if k in self.tables[level]]
                if hits:
                    scores.append(np.mean(hits, axis=0)); level_used.append(level)
                    break
            else:
                scores.append(self.prior); level_used.append(2)
        return np.vstack(scores), np.array(level_used)


# ---------- metrics

def macro_ap(Y: np.ndarray, S: np.ndarray, classes: list[str], exclude: tuple = ()) -> dict:
    per = {}
    for j, c in enumerate(classes):
        if c in exclude or Y[:, j].sum() == 0:
            continue
        per[c] = {"ap": float(average_precision_score(Y[:, j], S[:, j])), "prevalence": float(Y[:, j].mean())}
    ap = float(np.mean([v["ap"] for v in per.values()]))
    prev = float(np.mean([v["prevalence"] for v in per.values()]))
    return {"macro_ap": ap, "mean_prevalence": prev, "gain": ap - prev, "per_sector": per}


def macro_f1(Y: np.ndarray, S: np.ndarray) -> float:
    return float(f1_score(Y, (S >= 0.5).astype(int), average="macro", zero_division=0))


# ---------- features for the unseen-vendor model

def model_features(rows: pd.DataFrame) -> sp.csr_matrix:
    text = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2, max_features=50000,
                           token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_]+\b").fit_transform(rows["description"])
    cwe = MultiLabelBinarizer(sparse_output=True).fit_transform(rows["cwes"].map(lambda c: list(c) or ["cwe:none"]))
    cvss = MultiLabelBinarizer(sparse_output=True).fit_transform(
        [_cvss_tokens(v if isinstance(v, str) else None, s if isinstance(s, str) else None)
         for v, s in zip(rows["cvss_version"], rows["cvss_vector"])])
    return sp.hstack([normalize(text), normalize(cwe), normalize(cvss)]).tocsr()


def grouped_eval(rows, Y, classes, X, kind: str, folds: int, seed: int, group_col: str = "vendor") -> dict:
    """Unseen-vendor CV: group by advisory vendor, then purge any training CVE sharing a vendor key with the test fold."""
    S = np.zeros(Y.shape)
    purged = 0
    for train, test in GroupKFold(folds).split(rows, groups=rows[group_col]):
        test_keys = set().union(*rows["vendor_keys"].iloc[test])
        clean = np.array([not (ks & test_keys) for ks in rows["vendor_keys"].iloc[train]])
        purged += int((~clean).sum())
        train = train[clean]
        if kind == "lookup":
            S[test] = SectorLookup().fit(rows.iloc[train], Y[train]).predict(rows.iloc[test])[0]
        else:
            clf = OneVsRestClassifier(LogisticRegression(max_iter=5000, class_weight="balanced", random_state=seed))
            S[test] = clf.fit(X[train], Y[train]).predict_proba(X[test])
    return {"all": macro_ap(Y, S, classes), "excl_cm": macro_ap(Y, S, classes, exclude=(CM,)),
            "macro_f1": macro_f1(Y, S), "purged_train_rows": purged}


# ---------- run

def main() -> None:
    cfg = load_config()
    v2 = cfg["sector_v2"]
    interim, processed = data_path(cfg, "interim"), data_path(cfg, "processed")
    labels, hygiene = build_labels(interim)

    counts = labels.explode("sectors")["sectors"].value_counts()
    classes = sorted(counts[counts >= v2["min_positives"]].index)
    mlb = MultiLabelBinarizer(classes=classes)
    Y = mlb.fit_transform(labels["sectors"].map(lambda s: [x for x in s if x in classes]))
    labels["keys"] = labels.apply(_keys, axis=1)
    labels["fit_keys"] = [_keys(r, {canon(v) for v in r["ics_vendors"]}) for _, r in labels.iterrows()]

    g1 = v2["gates"]["v1"]
    v1_res = {"labeled": int(len(labels)), "sectors_at_min_positives": len(classes),
              "positives": counts.to_dict(), **hygiene}
    groups, comps = labels["vendor"].value_counts(), labels["vendor_component"].value_counts()
    v1_res["vendor_groups"] = {"n": int(len(groups)), "largest_share": float(groups.iloc[0] / len(labels)),
                               "components": int(len(comps)), "largest_component_share": float(comps.iloc[0] / len(labels))}
    v1_res["pass"] = v1_res["labeled"] >= g1["min_labeled"] and len(classes) >= g1["min_sectors"]

    # V2: lookup on the temporal split
    train = labels["year"].isin(v2["split"]["temporal_train_years"]).to_numpy()
    test = labels["year"].isin(v2["split"]["temporal_test_years"]).to_numpy()
    lookup = SectorLookup().fit(labels[train], Y[train])
    S, level = lookup.predict(labels[test])
    g2 = v2["gates"]["v2"]
    v2_res = {
        "n_train": int(train.sum()), "n_test": int(test.sum()),
        "coverage": float((level < 2).mean()),
        "coverage_by_level": {"product": float((level == 0).mean()), "vendor": float((level == 1).mean()),
                              "prior": float((level == 2).mean())},
        "all": macro_ap(Y[test], S, classes),
        "excl_cm": macro_ap(Y[test], S, classes, exclude=(CM,)),
        "covered_only": macro_ap(Y[test][level < 2], S[level < 2], classes),
        "macro_f1": macro_f1(Y[test], S),
    }
    # Sensitivity (no gate): the dominant vendor's advisories may use boilerplate sector lists.
    top = labels["vendor"].value_counts().index[0]
    test_rows = labels[test]
    not_top = (test_rows["vendor"] != top).to_numpy()
    sets = labels.loc[labels["vendor"] == top, "sectors"].map(tuple).value_counts()
    v2_res["top_vendor"] = {
        "vendor": top, "test_share": float(1 - not_top.mean()),
        "distinct_sector_sets": int(len(sets)), "most_common_set_share": float(sets.iloc[0] / sets.sum()),
        "most_common_set": list(sets.index[0]),
        "excl_top_vendor": macro_ap(Y[test][not_top], S[not_top], classes),
    }
    v2_res["pass"] = v2_res["all"]["gain"] >= g2["min_ap_gain"] and v2_res["coverage"] >= g2["min_coverage"]

    # V3: unseen vendors (vendor-grouped), text + CWE + CVSS vs. the lookup
    X = model_features(labels)
    folds, seed = cfg["model"]["folds"], cfg["model"]["seed"]
    v3_res = {
        "model": grouped_eval(labels, Y, classes, X, "model", folds, seed),
        "lookup": grouped_eval(labels, Y, classes, X, "lookup", folds, seed),
        "model_by_component": grouped_eval(labels, Y, classes, X, "model", folds, seed, "vendor_component"),
    }
    v3_res["pass"] = v3_res["model"]["all"]["gain"] >= v2["gates"]["v3"]["min_ap_gain"]

    # Reach: non-ICS CVEs the full lookup would score
    joined = pd.read_parquet(interim / "joined.parquet")
    others = joined[~joined["cve_id"].isin(labels["cve_id"])].copy()
    others["keys"] = others.apply(_keys, axis=1)
    _, lvl = SectorLookup().fit(labels, Y).predict(others)
    reach = {"non_labeled_cves": int(len(others)), "by_product": int((lvl == 0).sum()), "by_vendor": int((lvl == 1).sum())}

    result = {"classes": classes, "v1": v1_res, "v2": v2_res, "v3": v3_res, "reach": reach}
    (processed / "results_sector_v2.json").write_text(json.dumps(result, indent=1))
    summarize(result)


def summarize(r: dict) -> None:
    v1, v2, v3 = r["v1"], r["v2"], r["v3"]
    print(f"V1 labels: {v1['labeled']} CVEs, {v1['sectors_at_min_positives']} sectors >= min positives, "
          f"dropped {v1['third_party_links_dropped']}/{v1['links']} third-party links -> {'PASS' if v1['pass'] else 'FAIL'}")
    print(f"V2 lookup (temporal, n_test={v2['n_test']}): macro-AP {v2['all']['macro_ap']:.3f} vs prevalence "
          f"{v2['all']['mean_prevalence']:.3f} (gain {v2['all']['gain']:+.3f}); coverage {v2['coverage']:.2f} "
          f"{ {k: round(x, 2) for k, x in v2['coverage_by_level'].items()} } -> {'PASS' if v2['pass'] else 'FAIL'}")
    print(f"   excl CM gain {v2['excl_cm']['gain']:+.3f}; covered-only gain {v2['covered_only']['gain']:+.3f}; macro-F1@0.5 {v2['macro_f1']:.3f}")
    t = v2["top_vendor"]
    print(f"   top vendor {t['vendor']}: {t['test_share']:.0%} of test, {t['distinct_sector_sets']} distinct sector sets, "
          f"most common {t['most_common_set_share']:.0%}; excl top vendor gain {t['excl_top_vendor']['gain']:+.3f}")
    for k in ("model", "lookup", "model_by_component"):
        a = v3[k]
        print(f"V3 grouped {k:<18}: macro-AP {a['all']['macro_ap']:.3f} vs {a['all']['mean_prevalence']:.3f} "
              f"(gain {a['all']['gain']:+.3f}; excl CM {a['excl_cm']['gain']:+.3f}; macro-F1 {a['macro_f1']:.3f}; purged {a['purged_train_rows']})")
    print(f"   -> {'PASS' if v3['pass'] else 'FAIL'}")
    print("Reach:", r["reach"])


if __name__ == "__main__":
    main()
