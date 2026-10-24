"""Pre-registered go/no-go gates (config.yaml `gates`), evaluated mechanically."""

import pandas as pd


def q1_coverage(labels: pd.DataFrame, cfg: dict) -> dict:
    g = cfg["gates"]["q1"]
    single = labels["sector"].dropna()
    counts = single.value_counts()
    result = {
        "labeled": int(len(single)),
        "sectors_at_min_size": int((counts >= g["min_sector_size"]).sum()),
        "max_share": float(counts.iloc[0] / counts.sum()) if len(counts) else 1.0,
        "max_sector": counts.index[0] if len(counts) else None,
    }
    result["checks"] = {
        "min_labeled": result["labeled"] >= g["min_labeled"],
        "min_sectors": result["sectors_at_min_size"] >= g["min_sectors"],
        "max_share": result["max_share"] <= g["max_share"],
    }
    result["pass"] = all(result["checks"].values())
    return result


def q2_signal(scores: dict, cfg: dict) -> dict:
    """scores: macro-F1 means keyed by majority, masked, unmasked, masked_grouped, majority_grouped."""
    g = cfg["gates"]["q2"]
    gain = scores["masked"] - scores["majority"]
    gain_grouped = scores["masked_grouped"] - scores["majority_grouped"]
    return {
        "gain_masked": gain,
        "gain_unmasked": scores["unmasked"] - scores["majority"],
        "gain_masked_grouped": gain_grouped,
        "pass": gain >= g["min_gain_over_majority"],
        "vendor_specific": gain_grouped < g["min_gain_grouped"],
    }


def q3_ablation(f1_majority: float, f1_full: float, f1_minimal: float, cfg: dict) -> dict:
    g = cfg["gates"]["q3"]
    denom = f1_full - f1_majority
    retention = (f1_minimal - f1_majority) / denom if denom > 0 else float("nan")
    if retention >= g["pass_retention"]:
        verdict = "pass"
    elif retention >= g["weak_retention"]:
        verdict = "degrades"
    else:
        verdict = "cliff"
    return {"retention": retention, "verdict": verdict}
