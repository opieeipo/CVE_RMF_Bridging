#!/usr/bin/env bash
# End-to-end spike on a sample. Usage: scripts/run_spike.sh [limit]
set -euo pipefail
cd "$(dirname "$0")/.."

LIMIT="${1:-2000}"

python -m src.pull --limit "$LIMIT"
python -m src.normalize --limit "$LIMIT"
python -m src.labels --targets sector,time_to_kev
# Q1 gate: review notebooks/00_coverage.ipynb before trusting anything below.
python -m src.features --limit "$LIMIT"
python -m src.experiment --target sector
python -m src.experiment --target sector --ablate
