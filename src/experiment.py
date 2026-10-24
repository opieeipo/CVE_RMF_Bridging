"""data/processed/ -> metrics. Train, evaluate and ablate linear baselines.

Reports macro-F1 and per-class scores against a majority-class baseline;
accuracy alone will lie on imbalanced sectors. Every score is a 5-fold mean on
two splits: stratified (the pre-registered gate) and vendor-grouped (no vendor
in both train and test), which shows how much of the signal is vendor-specific.
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.preprocessing import normalize

from src.config import data_path, load_config
from src.gates import q2_signal, q3_ablation

BLOCKS = {"text": "X_text_{text}.npz", "cwe": "X_cwe.npz", "cvss": "X_cvss.npz"}


def load_target(processed_dir: Path, target: str, cfg: dict) -> tuple[pd.DataFrame, np.ndarray]:
    rows = pd.read_parquet(processed_dir / f"rows_{target}.parquet")
    counts = rows["label"].value_counts()
    keep = rows["label"].isin(counts[counts >= cfg["labels"]["min_class_size"]].index).to_numpy()
    return rows[keep].reset_index(drop=True), keep


def features(processed_dir: Path, target: str, feature_set: list[str], keep: np.ndarray, text: str = "masked"):
    # Each block is L2-normalized per row (as TF-IDF already is) so one-hot metadata
    # cannot swamp the text under a shared regularization strength.
    mats = [normalize(sp.load_npz(processed_dir / target / BLOCKS[b].format(text=text))) for b in feature_set]
    return sp.hstack(mats).tocsr()[keep]


def folds(rows: pd.DataFrame, grouped: bool, cfg: dict):
    k, seed = cfg["model"]["folds"], cfg["model"]["seed"]
    y = rows["label"].to_numpy()
    if grouped:
        return list(StratifiedGroupKFold(k, shuffle=True, random_state=seed).split(rows, y, rows["vendor"]))
    return list(StratifiedKFold(k, shuffle=True, random_state=seed).split(rows, y))


def make_model(kind: str, cfg: dict):
    if kind == "majority":
        return DummyClassifier(strategy="most_frequent")
    return LogisticRegression(max_iter=5000, class_weight="balanced", random_state=cfg["model"]["seed"])


def majority_baseline(y):
    return DummyClassifier(strategy="most_frequent").fit(np.zeros((len(y), 1)), y)


def vendor_lookup_predict(train: pd.DataFrame, test: pd.DataFrame) -> np.ndarray:
    """The transparent baseline: each vendor's most common training label."""
    fallback = train["label"].value_counts().index[0]
    by_vendor = train.groupby("vendor")["label"].agg(lambda s: s.value_counts().index[0])
    return test["vendor"].map(by_vendor).fillna(fallback).to_numpy()


def cross_validate(X, rows: pd.DataFrame, kind: str, splits, cfg: dict) -> dict:
    y = rows["label"].to_numpy()
    pred = np.empty(len(y), dtype=object)
    f1s, accs = [], []
    for train, test in splits:
        if kind == "vendor_lookup":
            p = vendor_lookup_predict(rows.iloc[train], rows.iloc[test])
        else:
            p = make_model(kind, cfg).fit(X[train], y[train]).predict(X[test])
        pred[test] = p
        f1s.append(f1_score(y[test], p, average="macro", labels=np.unique(y), zero_division=0))
        accs.append(accuracy_score(y[test], p))
    report = classification_report(y, pred.astype(str), output_dict=True, zero_division=0)
    return {
        "macro_f1_mean": float(np.mean(f1s)), "macro_f1_sd": float(np.std(f1s)),
        "accuracy_mean": float(np.mean(accs)), "n": int(len(y)),
        "per_class": {c: report[c] for c in np.unique(y)},
    }


def train_eval(processed_dir: Path, target: str, feature_set: list[str], cfg: dict,
               grouped: bool = False, text: str = "masked") -> dict:
    rows, keep = load_target(processed_dir, target, cfg)
    X = features(processed_dir, target, feature_set, keep, text)
    res = cross_validate(X, rows, "logreg", folds(rows, grouped, cfg), cfg)
    return {"feature_set": "+".join(feature_set), "grouped": grouped, **res}


def signal(processed_dir: Path, target: str, cfg: dict) -> dict:
    rows, keep = load_target(processed_dir, target, cfg)
    X_dummy = sp.csr_matrix((len(rows), 1))
    out = {}
    for grouped, suffix in ((False, ""), (True, "_grouped")):
        splits = folds(rows, grouped, cfg)
        out["majority" + suffix] = cross_validate(X_dummy, rows, "majority", splits, cfg)
        out["vendor_lookup" + suffix] = cross_validate(X_dummy, rows, "vendor_lookup", splits, cfg)
        for text in ("masked", "unmasked"):
            X = features(processed_dir, target, ["text"], keep, text)
            out[text + suffix] = cross_validate(X, rows, "logreg", splits, cfg)
    return out


def ablate(processed_dir: Path, target: str, cfg: dict) -> list[dict]:
    return [
        train_eval(processed_dir, target, fs, cfg, grouped=g)
        for g in (False, True) for fs in cfg["ablation"]["feature_sets"]
    ]


def run(processed_dir: Path, target: str, cfg: dict) -> dict:
    sig = signal(processed_dir, target, cfg)
    abl = ablate(processed_dir, target, cfg)
    f1 = {k: v["macro_f1_mean"] for k, v in sig.items()}
    strat = {a["feature_set"]: a["macro_f1_mean"] for a in abl if not a["grouped"]}
    grp = {a["feature_set"]: a["macro_f1_mean"] for a in abl if a["grouped"]}
    result = {
        "target": target,
        "classes": sorted(load_target(processed_dir, target, cfg)[0]["label"].unique()),
        "signal": sig,
        "ablation": [a for a in abl if not a["grouped"]],
        "ablation_grouped": [a for a in abl if a["grouped"]],
        "q2": q2_signal(f1, cfg),
        "q3": q3_ablation(f1["majority"], strat["text+cwe+cvss"], strat["cwe+cvss"], cfg),
        "q3_grouped": q3_ablation(f1["majority_grouped"], grp["text+cwe+cvss"], grp["cwe+cvss"], cfg),
    }
    (processed_dir / f"results_{target}.json").write_text(json.dumps(result, indent=1, default=str))
    return result


def summarize(result: dict) -> None:
    print(f"== {result['target']}  classes={len(result['classes'])}  n={result['signal']['majority']['n']}")
    for name, r in result["signal"].items():
        print(f"  {name:<24} macro-F1 {r['macro_f1_mean']:.3f} ± {r['macro_f1_sd']:.3f}   acc {r['accuracy_mean']:.3f}")
    for a in result["ablation"] + result["ablation_grouped"]:
        tag = "grouped" if a["grouped"] else "strat"
        print(f"  ablation[{tag}] {a['feature_set']:<16} macro-F1 {a['macro_f1_mean']:.3f} ± {a['macro_f1_sd']:.3f}")
    print("  Q2:", {k: round(v, 3) if isinstance(v, float) else v for k, v in result["q2"].items()})
    print("  Q3:", result["q3"], " grouped:", result["q3_grouped"])


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=None, choices=cfg["targets"], help="default: all targets")
    parser.add_argument("--ablate", action="store_true", help="only print the ablation for --target")
    args = parser.parse_args()

    processed_dir = data_path(cfg, "processed")
    if args.ablate:
        for a in ablate(processed_dir, args.target or cfg["targets"][0], cfg):
            print(a["feature_set"], "grouped" if a["grouped"] else "strat", round(a["macro_f1_mean"], 3))
        return
    for target in [args.target] if args.target else cfg["targets"]:
        rows, _ = load_target(processed_dir, target, cfg)
        if rows["label"].nunique() < 2 or rows["label"].value_counts().min() < cfg["model"]["folds"]:
            print(f"== {target}: too few labels to model ({len(rows)} rows); sample run, skipping")
            continue
        summarize(run(processed_dir, target, cfg))


if __name__ == "__main__":
    main()
