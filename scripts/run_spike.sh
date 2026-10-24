#!/usr/bin/env bash
# End-to-end spike. Usage: scripts/run_spike.sh [limit|full]   (default: 2000-row sample)
# The sample run proves the wiring only; gate numbers come from `full`.
set -euo pipefail
cd "$(dirname "$0")/.."

PY="python"
[ -x .venv/bin/python ] && PY=".venv/bin/python"

LIMIT="${1:-2000}"
if [ "$LIMIT" = "full" ]; then LIM=(); else LIM=(--limit "$LIMIT"); fi

$PY -m src.pull ${LIM[@]+"${LIM[@]}"}
$PY -m src.normalize ${LIM[@]+"${LIM[@]}"}
$PY -m src.labels --targets sector,time_to_kev
# Q1 gate: review notebooks/00_coverage.ipynb before trusting anything below.
$PY -m src.features ${LIM[@]+"${LIM[@]}"}
$PY -m src.experiment
$PY -m src.diagnostics
[ "$LIMIT" = "full" ] && $PY -m src.sector_v2

if [ "$LIMIT" = "full" ]; then
  $PY scripts/build_notebooks.py
  .venv/bin/jupyter nbconvert --to notebook --execute --inplace notebooks/0*.ipynb
fi
