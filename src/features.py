"""data/interim/ -> data/processed/. Text and metadata feature matrices.

Product/vendor tokens (from CPE) are masked out of the text before vectorizing,
so Q2 measures real signal rather than product leakage. The fitted vectorizer
and sparse matrix are cached so models never re-vectorize.

Masking, per target:
  1. every vendor name seen in that target's labeled CVEs (CPE, CVE 5 "affected",
     ICS advisory, KEV) is masked as a phrase in every text, plus each vendor's
     distinctive leading token ("rockwell", "schneider");
  2. each CVE's own product names are masked as phrases, and their tokens are
     masked if rarer than `text.mask_max_doc_freq` across all NVD descriptions,
     so generic words ("server", "controller", "pump") survive.
"""

import argparse
import re
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, CountVectorizer, TfidfVectorizer
from sklearn.preprocessing import MultiLabelBinarizer

from src.config import data_path, load_config

VENDOR_MASK, PRODUCT_MASK = " xxvendor ", " xxproduct "
NAME_COLS = {
    "vendor": ["cpe_vendors", "affected_vendors", "ics_vendors", "kev_vendor"],
    "product": ["cpe_products", "affected_products", "ics_products", "kev_product"],
}
LABEL_FILES = {"sector": "labels_sector.parquet", "time_to_kev": "labels_time_to_kev.parquet"}


def _tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", name.lower()) if t]


def _phrase_pattern(names: set[str]) -> re.Pattern | None:
    """One alternation matching each name with flexible separators ("schneider[-_ ]electric")."""
    alts = {r"[\W_]*".join(map(re.escape, toks)) for n in names if (toks := _tokens(n)) and len("".join(toks)) >= 3}
    if not alts:
        return None
    # Longest first so "siemens energy" wins over "siemens".
    return re.compile(r"\b(?:" + "|".join(sorted(alts, key=len, reverse=True)) + r")\b", re.I)


def _names(row: pd.Series, kind: str) -> set[str]:
    out = set()
    for col in NAME_COLS[kind]:
        v = row.get(col)
        if isinstance(v, str):
            out.add(v)
        elif v is not None and not (isinstance(v, float) and np.isnan(v)):
            out.update(x for x in v if isinstance(x, str))
    return out


def document_frequency(texts: pd.Series) -> dict[str, float]:
    cv = CountVectorizer(binary=True, token_pattern=r"(?u)\b[a-z0-9]+\b", lowercase=True)
    X = cv.fit_transform(texts)
    df = np.asarray(X.sum(axis=0)).ravel() / X.shape[0]
    return dict(zip(cv.get_feature_names_out(), df))


def mask_product_tokens(rows: pd.DataFrame, doc_freq: dict[str, float], max_df: float, titles: dict) -> pd.Series:
    vendors = set().union(*(_names(r, "vendor") for _, r in rows.iterrows()))
    leading = {
        toks[0] for v in vendors
        if len(toks := _tokens(v)) > 1 and len(toks[0]) >= 3
        and toks[0] not in ENGLISH_STOP_WORDS and doc_freq.get(toks[0], 0) < 0.02
    }
    vendor_rx = _phrase_pattern(vendors | leading)

    masked = []
    for _, row in rows.iterrows():
        text = row["description"]
        products = _names(row, "product")
        products |= {titles[(v, p)] for v in row["cpe_vendors"] for p in row["cpe_products"] if (v, p) in titles}
        product_rx = _phrase_pattern(products)
        if product_rx:
            text = product_rx.sub(PRODUCT_MASK, text)
        if vendor_rx:
            text = vendor_rx.sub(VENDOR_MASK, text)
        rare = {t for p in products for t in _tokens(p) if doc_freq.get(t, 0) < max_df and len(t) >= 2 and not t.isdigit()}
        rare -= ENGLISH_STOP_WORDS
        if rare:
            text = re.sub(r"\b(?:" + "|".join(map(re.escape, sorted(rare))) + r")\b", PRODUCT_MASK, text, flags=re.I)
        masked.append(re.sub(r"\s+", " ", text).strip())
    return pd.Series(masked, index=rows.index)


def target_rows(interim_dir: Path, target: str, limit: int | None) -> pd.DataFrame:
    joined = pd.read_parquet(interim_dir / "joined.parquet")
    labels = pd.read_parquet(interim_dir / LABEL_FILES[target])
    if target == "sector":
        labels = labels.dropna(subset=["sector"]).rename(columns={"sector": "label"})
    else:
        labels = labels.rename(columns={"time_to_kev": "label"})
    rows = labels[["cve_id", "label", "vendor"]].merge(joined, on="cve_id")
    if limit:
        rows = rows.sample(min(limit, len(rows)), random_state=0)
    return rows.reset_index(drop=True)


def build_text_features(rows: pd.DataFrame, out: Path, cfg: dict) -> None:
    for variant, col in (("masked", "text_masked"), ("unmasked", "description")):
        vec = TfidfVectorizer(
            ngram_range=(1, 2), sublinear_tf=True, min_df=2,
            max_features=cfg["text"]["max_features"], token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_]+\b",
        )
        X = vec.fit_transform(rows[col])
        sp.save_npz(out / f"X_text_{variant}.npz", X.tocsr())
        joblib.dump(vec, out / f"tfidf_{variant}.joblib")


def _cvss_tokens(version: str | None, vector: str | None) -> list[str]:
    if not vector:
        return ["cvss:none"]
    fam = "v3" if version and version.startswith("3") else f"v{(version or '?')[0]}"
    parts = [p for p in vector.split("/") if ":" in p and not p.startswith("CVSS")]
    return [f"cvss:{fam}"] + [f"{fam}:{p}" for p in parts]


def build_metadata_features(rows: pd.DataFrame, out: Path) -> None:
    cwe = MultiLabelBinarizer(sparse_output=True)
    X_cwe = cwe.fit_transform(rows["cwes"].map(lambda c: list(c) if len(c) else ["cwe:none"]))
    cvss = MultiLabelBinarizer(sparse_output=True)
    X_vec = cvss.fit_transform([_cvss_tokens(v, s) for v, s in zip(rows["cvss_version"], rows["cvss_vector"])])
    score = sp.csr_matrix(rows["cvss_score"].fillna(0).to_numpy()[:, None] / 10.0)
    sp.save_npz(out / "X_cwe.npz", X_cwe.tocsr())
    sp.save_npz(out / "X_cvss.npz", sp.hstack([X_vec, score]).tocsr())
    joblib.dump({"cwe": cwe.classes_, "cvss": cvss.classes_}, out / "metadata_vocab.joblib")


def build_target(interim_dir: Path, processed_dir: Path, target: str, cfg: dict, limit: int | None,
                 doc_freq: dict[str, float], titles: dict) -> None:
    out = processed_dir / target
    out.mkdir(parents=True, exist_ok=True)
    rows = target_rows(interim_dir, target, limit)
    rows["text_masked"] = mask_product_tokens(rows, doc_freq, cfg["text"]["mask_max_doc_freq"], titles)
    rows[["cve_id", "label", "vendor", "description", "text_masked"]].to_parquet(
        processed_dir / f"rows_{target}.parquet", index=False)
    build_text_features(rows, out, cfg)
    build_metadata_features(rows, out)
    changed = (rows["text_masked"] != rows["description"]).mean()
    print(f"{target}: {len(rows)} rows, {rows['label'].nunique()} classes, {changed:.0%} of texts masked")


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--targets", default=",".join(cfg["targets"]))
    args = parser.parse_args()

    interim_dir, processed_dir = data_path(cfg, "interim"), data_path(cfg, "processed")
    processed_dir.mkdir(parents=True, exist_ok=True)
    nvd = pd.read_parquet(interim_dir / "nvd.parquet", columns=["description"])
    doc_freq = document_frequency(nvd["description"])
    titles_path = interim_dir / "cpe_titles.parquet"
    titles = {}
    if titles_path.exists():
        t = pd.read_parquet(titles_path).dropna(subset=["title"])
        titles = dict(zip(zip(t["vendor"], t["product"]), t["title"]))
    for target in args.targets.split(","):
        build_target(interim_dir, processed_dir, target, cfg, args.limit, doc_freq, titles)


if __name__ == "__main__":
    main()
