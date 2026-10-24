"""data/processed/ -> metrics. Train, evaluate and ablate linear baselines.

Reports macro-F1 and per-class scores against a majority-class baseline;
accuracy alone will lie on imbalanced sectors.
"""

import argparse

from src.config import data_path, load_config


def majority_baseline(y):
    raise NotImplementedError


def train_eval(processed_dir, target: str, feature_set: list[str], cfg: dict) -> dict:
    raise NotImplementedError("stratified split, LogisticRegression / LinearSVC, macro-F1")


def ablate(processed_dir, target: str, cfg: dict) -> list[dict]:
    return [train_eval(processed_dir, target, fs, cfg) for fs in cfg["ablation"]["feature_sets"]]


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=cfg["targets"][0], choices=cfg["targets"])
    parser.add_argument("--ablate", action="store_true")
    args = parser.parse_args()

    processed_dir = data_path(cfg, "processed")
    if args.ablate:
        ablate(processed_dir, args.target, cfg)
    else:
        train_eval(processed_dir, args.target, cfg["ablation"]["feature_sets"][0], cfg)


if __name__ == "__main__":
    main()
