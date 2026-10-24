"""data/interim/ -> data/processed/. Text and metadata feature matrices.

Product/vendor tokens (from CPE) are masked out of the text before vectorizing,
so Q2 measures real signal rather than product leakage. The fitted vectorizer
and sparse matrix are cached so models never re-vectorize.
"""

import argparse

from src.config import data_path, load_config


def mask_product_tokens(texts, cpe_terms):
    raise NotImplementedError


def build_text_features(interim_dir, processed_dir, cfg: dict) -> None:
    raise NotImplementedError("TfidfVectorizer -> scipy.sparse + joblib cache")


def build_metadata_features(interim_dir, processed_dir) -> None:
    raise NotImplementedError("CWE and CVSS features")


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None)
    parser.parse_args()

    interim_dir, processed_dir = data_path(cfg, "interim"), data_path(cfg, "processed")
    build_text_features(interim_dir, processed_dir, cfg)
    build_metadata_features(interim_dir, processed_dir)


if __name__ == "__main__":
    main()
