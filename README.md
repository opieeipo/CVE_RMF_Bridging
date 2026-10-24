# CVE Sector-Context Spike

> **Status:** feasibility spike. No results yet. Numbers produced here are go/no-go signals, not paper results.

Feasibility probe for an ML paper: can a CVE's **industry sector / impact
context** be predicted from its public text and metadata, using externally
sourced labels, well enough to justify a full paper? Built to answer go/no-go
fast, not to produce final results.

This is a **spike**. Its numbers are signals, not paper results. The code is
written to be reusable toward the real submission, but nothing here is the
model.

## Project Progress

**Overall: 50%** (14 of 28 tasks) -- see [TODO](#todo) for details

```
Phase 0 - Setup                      ████████████████░░░░   80% (4/5)
Phase 1 - Pull & normalize           █████████████████░░░   83% (5/6)
Phase 2 - Labels & Q1 coverage gate  ████████████████████  100% (5/5)
Phase 3 - Q2 text signal             ░░░░░░░░░░░░░░░░░░░░    0% (0/5)
Phase 4 - Q3 ablation                ░░░░░░░░░░░░░░░░░░░░    0% (0/4)
Phase 5 - Go/no-go                   ░░░░░░░░░░░░░░░░░░░░    0% (0/3)
```

*Last updated: 2026-10-24*

---

## The three questions this spike must answer

Answer them in order. If an early one fails, stop and pivot before building
further.

1. **Do labels exist in volume?** Enough public, externally-sourced
   sector-tagged CVEs to train on, spread across more than one or two sectors.
   This is the gatekeeper. (Primary source: CISA ICS advisories + KEV. Fallback
   label for the alternate framing: time-to-KEV, below.)
2. **Is there signal in the text?** Can CVE description text predict sector
   above a majority-class baseline, *without* leaking the product name that
   makes it trivial? (Run with product/vendor tokens masked.)
3. **Does the ablation degrade gracefully?** As features are stripped toward a
   minimal "embeddable" set, does accuracy fall on a usable curve or off a
   cliff?

If (1) fails for sectors, switch to the **fallback framing**: predict
**time-to-KEV** (days from CVE publication to KEV listing) from disclosure-time
features. Cleaner labels, no sector dependency. The pipeline below supports both
targets from the same cached data, so you test both in one pass.

---

## Design principle: cache once, iterate forever

The slow part is the network pull. The experiments are cheap. So the pipeline is
split hard at that boundary: **pull and normalize once to disk, then every
experiment reads local Parquet.** You should be able to re-run a model in
seconds without touching the network.

```
  [ raw pull ]  -->  [ normalize + join ]  -->  [ feature cache ]  -->  [ experiments ]
   slow, once         slow, once                fast, cached           instant, many
   data/raw/          data/interim/             data/processed/        notebooks / scripts
```

Rules that keep iteration fast:
- **Never re-pull in an experiment.** Pulls write to `data/raw/` and stop.
- **Everything downstream of the pull is a pure function of cached files.** Delete
  `data/processed/` and rebuild in under a minute, never re-download.
- **Parquet, not JSON/CSV,** for anything read more than once. Columnar + typed +
  compressed; 10-50x faster to load than re-parsing JSON.
- **Sample first, scale later.** Every stage takes a `--limit`. Prove the wiring
  on 2,000 rows before pulling the full window.

---

## Data sources (all public, no auth)

| Source | Gives you | Access | Notes |
|---|---|---|---|
| NVD CVE (JSON 2.0 feeds) | CVE id, description, CWE, CVSS vector/scores, CPE | Bulk yearly gzip feeds, or API | **Use the bulk feeds, not the API.** API is rate-limited (even with a key); the gzipped yearly feeds are one download each and far faster. |
| CISA KEV catalog | known-exploited label, date added, vendor/product | Single JSON file | Tiny. Label source for time-to-KEV. |
| CISA ICS advisories | sector tags (critical-infra sectors), affected products | Advisory pages / feed | Primary sector-label source. Coverage is the open question (Q1). |
| NVD CPE dictionary | product -> category mapping | Bulk | For the transparent product->sector lookup and for masking product tokens. |

Get an NVD API key only if you end up using the API at all
(https://nvd.nist.gov/developers/request-an-api-key). The bulk-feed path doesn't
need one.

---

## Layout

```
.
+-- README.md
+-- pyproject.toml            # or requirements.txt
+-- config.yaml               # window, paths, target, feature sets
+-- data/
|   +-- raw/                  # downloaded feeds, untouched. gitignored.
|   +-- interim/              # normalized, joined on CVE id
|   +-- processed/            # feature matrices, Parquet, ready to model
+-- src/
|   +-- pull.py               # source -> data/raw/   (the only networked step)
|   +-- normalize.py          # raw -> interim        (parse, flatten, join)
|   +-- labels.py             # sector + time-to-KEV label assignment
|   +-- features.py           # interim -> processed  (text + metadata vectors)
|   +-- experiment.py         # processed -> metrics  (train/eval/ablate)
+-- notebooks/
|   +-- 00_coverage.ipynb     # Q1: label counts, sector balance. RUN FIRST.
|   +-- 01_signal.ipynb       # Q2: text -> target, product-masked baseline
|   +-- 02_ablation.ipynb     # Q3: feature-set degradation curve
+-- scripts/
    +-- run_spike.sh          # end-to-end on a sample, one command
```

---

## Run order

```bash
# 0. setup
pip install -e .                      # or: pip install -r requirements.txt

# 1. pull once (slow). --limit to smoke-test the wiring first.
python -m src.pull --window 2023-2025 --limit 2000
python -m src.pull --window 2023-2025          # then the full window

# 2. normalize + join + label (cached to Parquet)
python -m src.normalize
python -m src.labels --targets sector,time_to_kev

# 3. Q1 FIRST — is there anything to model?
jupyter lab notebooks/00_coverage.ipynb

# 4. only if Q1 passes:
python -m src.features
jupyter lab notebooks/01_signal.ipynb
jupyter lab notebooks/02_ablation.ipynb
```

`00_coverage.ipynb` is the stop/go gate. Don't build features until it passes.

---

## Performance plan (optimization as a forethought)

Sized so you get answers in **minutes on a laptop**, with clear escape hatches
if a stage gets heavy. Match the tool to the actual bottleneck:

**Pull (I/O-bound).**
- Bulk gzip feeds over the API, always. One request per year vs. thousands.
- Pull years concurrently (`concurrent.futures`, ~5 workers). It's network wait,
  so threads are fine.
- Cache raw bytes to disk and never fetch the same file twice (check-and-skip).

**Normalize/join (CPU, single pass).**
- Stream-parse the JSON feeds; don't load a whole year into memory at once
  (`ijson` or chunked reads).
- Write Parquet with a defined schema. Join on CVE id as a dataframe merge.
- Expect this to be the quiet time-sink; it runs once, so let it.

**Features.**
- Start with the cheapest thing that answers Q2: `TfidfVectorizer` +
  `LogisticRegression` / `LinearSVC`. CPU, seconds, no GPU. Do **not** reach for
  transformers for a go/no-go.
- Cache the fitted vectorizer and the sparse matrix (`scipy.sparse` /
  `joblib`). Re-running a model should never re-vectorize.
- Product-token masking happens here: strip vendor/product strings (from CPE) out
  of the text before vectorizing, so Q2 measures real signal, not product leakage.

**Experiments.**
- Stratified split by sector. Report macro-F1 and per-class, not just accuracy
  (sectors will be imbalanced; accuracy will lie).
- Ablation = same model, shrinking feature sets. Cheap to loop.

**When to scale up (only if a stage actually stalls):**
- **Colab:** free GPU/TPU if you move to a transformer text model *after* the
  linear baseline earns it. For a go/no-go you probably won't need it. Mount the
  cached Parquet from Drive so you don't re-pull in the cloud.
- **Ray:** only worth it if you're running a large hyperparameter sweep or
  ablation grid. `ray.tune` for the sweep, or `ray` to parallelize the ablation
  across cores. Overkill for the gate; keep it in reserve.
- Rule of thumb: don't add a distributed tool until a single-machine run is the
  measured bottleneck. The cache-first design means most stages won't be.

---

## config.yaml (starting point)

```yaml
window: [2023, 2025]        # CVE publication years to include
targets: [sector, time_to_kev]
paths:
  raw: data/raw
  interim: data/interim
  processed: data/processed
text:
  mask_product_tokens: true # strip CPE vendor/product from text for Q2
  vectorizer: tfidf
  max_features: 50000
model:
  baseline: logreg          # linear first; transformers only post-gate
  split: stratified
  metric: macro_f1
ablation:
  feature_sets:
    - [text]
    - [text, cwe]
    - [text, cwe, cvss]
    - [cwe, cvss]           # no text — the "minimal/embeddable" probe
```

---

## Go / no-go thresholds (decide before you look)

Set these now so you don't rationalize a weak result later:

- **Q1 pass:** sector labels for at least a few thousand CVEs, across at least
  4-5 sectors, no single sector above ~60%. Below that, pivot to time-to-KEV.
- **Q2 pass:** product-masked macro-F1 meaningfully above the majority-class
  baseline. If masking collapses it to baseline, the "signal" was just the
  product name — that's a real (negative) finding, report it and reconsider.
- **Q3 pass:** the text-free "minimal" feature set keeps usable accuracy. If it
  cliffs, the embeddable-model story dies but the sector classifier can still
  stand.

Any pivot is cheap because the fallback target (time-to-KEV) reads from the same
cached data.

---

## What this spike is NOT

- Not the final model. Linear baselines are for go/no-go only.
- Not paper results. These numbers decide whether to write, not what to claim.
- Not a full pull until the sample run proves the wiring.

---

## TODO

### Phase 0 - Setup

- [x] Scaffold `src/`, `notebooks/`, `scripts/`, `data/` and ignore rules
- [x] MIT license
- [x] `pyproject.toml` with pinned dependencies
- [x] `config.yaml` starting point
- [ ] `scripts/run_spike.sh` end-to-end sample run

### Phase 1 - Pull & normalize

- [x] NVD bulk yearly feed pull, concurrent with check-and-skip cache
- [x] CISA KEV catalog pull
- [x] CISA ICS advisories pull
- [ ] NVD CPE dictionary pull
- [x] Streaming normalize + join on CVE id to Parquet
- [x] Smoke-test wiring on `--limit 2000`, then pull the full 2023-2025 window

### Phase 2 - Labels & Q1 coverage gate

- [x] Sector labels from ICS advisories
- [x] Time-to-KEV labels (days from publication to KEV listing)
- [x] Transparent product -> sector lookup from CPE
- [x] `00_coverage.ipynb`: label counts and sector balance
- [x] Q1 decision: proceed on sector, or pivot to time-to-KEV
  - **Result: FAIL -> pivot to time-to-KEV.** 2,037 single-sector CVEs (pass), 5 sectors >= 50 (pass), but Critical Manufacturing is 62.0% (> 60% cap). Sector still run through Q2/Q3 as a diagnostic.

### Phase 3 - Q2 text signal

- [ ] Product/vendor token masking from CPE
- [ ] TF-IDF vectorizer with cached fit and sparse matrix
- [ ] Majority-class baseline
- [ ] Linear model on stratified split, macro-F1 and per-class report
- [ ] Q2 decision: masked vs. unmasked signal above baseline

### Phase 4 - Q3 ablation

- [ ] CWE and CVSS metadata features
- [ ] Ablation loop over configured feature sets
- [ ] `02_ablation.ipynb`: degradation curve
- [ ] Q3 decision: does the text-free minimal set hold up

### Phase 5 - Go/no-go

- [ ] Write up spike findings against the pre-registered thresholds
- [ ] Final call on paper framing (sector vs. time-to-KEV)
- [ ] Scope a transformer follow-up only if the linear baseline earns it

## License

Code is released under the MIT License (see `LICENSE`). Upstream data (NVD, CISA KEV, CISA ICS advisories) is subject to its publishers' own terms.
