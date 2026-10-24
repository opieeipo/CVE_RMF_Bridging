# CVE Sector-Context Spike

> **Status:** v1 spike complete (2026-10-24). The pre-registered rule pivoted to time-to-KEV, but on review that is kept as descriptive evidence of the exposure window, not as a target. Sector continues as **[Sector v2](#sector-v2-follow-up-spike)**, re-scoped as an RMF input. See [docs/spike_findings.md](docs/spike_findings.md). Numbers here are go/no-go signals, not paper results.

Feasibility probe for an ML paper: can a CVE's **industry sector / impact
context** be predicted from its public text and metadata, using externally
sourced labels, well enough to justify a full paper? Built to answer go/no-go
fast, not to produce final results.

This is a **spike**. Its numbers are signals, not paper results. The code is
written to be reusable toward the real submission, but nothing here is the
model.

## Project Progress

**Overall: 78%** (29 of 37 tasks) -- see [TODO](#todo) for details

```
Phase 0 - Setup                      ████████████████████  100% (5/5)
Phase 1 - Pull & normalize           ████████████████████  100% (6/6)
Phase 2 - Labels & Q1 coverage gate  ████████████████████  100% (5/5)
Phase 3 - Q2 text signal             ████████████████████  100% (5/5)
Phase 4 - Q3 ablation                ████████████████████  100% (4/4)
Phase 5 - Go/no-go                   ████████████████████  100% (3/3)
Phase 6 - Sector v2                  ██░░░░░░░░░░░░░░░░░░   11% (1/9)
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
|   +-- gates.py              # pre-registered go/no-go checks
|   +-- diagnostics.py        # label-noise and leakage checks
+-- notebooks/
|   +-- 00_coverage.ipynb     # Q1: label counts, sector balance. RUN FIRST.
|   +-- 01_signal.ipynb       # Q2: text -> target, product-masked baseline
|   +-- 02_ablation.ipynb     # Q3: feature-set degradation curve
+-- docs/
|   +-- spike_findings.md     # Phase 5 go/no-go write-up
+-- scripts/
    +-- run_spike.sh          # end-to-end: sample (default) or `full`
    +-- build_notebooks.py    # regenerate the three notebooks
    +-- update_progress.py    # recompute this README's progress bars
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

## Sector v2 (follow-up spike)

*Pre-registered 2026-10-24, after the v1 results. Gates are in `config.yaml` ->
`sector_v2`.*

**Why.** v1 asked whether CVE *description text* predicts sector with product names
removed. It mostly doesn't: the signal is vendor identity, and a plain vendor ->
sector lookup (macro-F1 0.773) beat every text model. For an RMF input that was the
wrong test, because the affected product is known when you assess a CVE against your
system. v2 asks:
- how accurate a transparent **CVE -> sector exposure** mapping is;
- how far it reaches;
- what can be done for vendors it has never seen.

**Disclosure.** v2 was designed after seeing v1, and some v1 counts are already known
(multi-label sector counts pass V1 before hygiene). The gates are set on quantities
v1 never measured: post-hygiene volume, lookup accuracy and coverage on a temporal
split, and performance on unseen vendors.

| | v1 | v2 |
|---|---|---|
| Label | single-sector CVEs only (2,037) | multi-label sector sets (4,125 before hygiene) |
| Label hygiene | none | drop CVE-advisory links where the advisory vendor isn't one of the CVE's own vendors (third-party components, 14% of v1 labels) |
| Primary method | text classifier, products masked | product -> vendor -> prior lookup |
| Text | masked | unmasked, evaluated only on unseen vendors |
| Primary split | stratified random | temporal: train on CVEs published 2023-2024, test on 2025 |
| Metric | macro-F1 | macro average precision over sectors, plus coverage |
| Critical Manufacturing | counted | reported with and without (sensitivity, not a gate) |

**Questions and gates**
- **V1, labels:** >= 3,000 CVEs with >= 1 sector after hygiene, and >= 6 sectors with
  >= 100 positives. Before hygiene v1 already shows 4,125 CVEs and 12 such sectors,
  so this only checks that hygiene doesn't break volume.
- **V2, lookup (temporal split):** macro-AP >= mean sector prevalence + 0.20, *and* the
  lookup covers >= 50% of 2025 test CVEs (product or vendor seen in training).
- **V3, unseen vendors (vendor-grouped split):** unmasked text + CWE + CVSS macro-AP
  >= mean prevalence + 0.10.
- **Reach (descriptive, no gate):** how many non-ICS CVEs in the window the lookup
  reaches. v1 found 24,581 of 108,489 at vendor level.

**Decision rules**
- V2 pass: the lookup is the RMF deliverable, and v1 stands as "text alone doesn't
  do it".
- V3 pass: a text model extends exposure mapping to new vendors. V3 fail: the
  deliverable is lookup-only, and its coverage bound is the stated limitation.
- V2 fail: sector as an RMF input isn't supportable from public ICS advisory labels.
  That calls for a different label source. Open question: no IT-sector label source
  is in hand; ICS advisories cover 4.4% of CVEs and only 34 single-sector IT CVEs.

Everything reads from the v1 cache. No new pull is needed.

---

## TODO

### Phase 0 - Setup

- [x] Scaffold `src/`, `notebooks/`, `scripts/`, `data/` and ignore rules
- [x] MIT license
- [x] `pyproject.toml` with pinned dependencies
- [x] `config.yaml` starting point
- [x] `scripts/run_spike.sh` end-to-end sample run

### Phase 1 - Pull & normalize

- [x] NVD bulk yearly feed pull, concurrent with check-and-skip cache
- [x] CISA KEV catalog pull
- [x] CISA ICS advisories pull
- [x] NVD CPE dictionary pull
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

- [x] Product/vendor token masking from CPE
- [x] TF-IDF vectorizer with cached fit and sparse matrix
- [x] Majority-class baseline
- [x] Linear model on stratified split, macro-F1 and per-class report
- [x] Q2 decision: masked vs. unmasked signal above baseline
  - **Result: PASS for both targets.** Time-to-KEV masked macro-F1 0.52 vs 0.22 majority (0.39 vendor-grouped). Sector 0.57 vs 0.13, but a vendor lookup scores 0.77 and the vendor-grouped score collapses to 0.22, so sector signal is mostly vendor identity.

### Phase 4 - Q3 ablation

- [x] CWE and CVSS metadata features
- [x] Ablation loop over configured feature sets
- [x] `02_ablation.ipynb`: degradation curve
- [x] Q3 decision: does the text-free minimal set hold up
  - **Result: time-to-KEV PASS** (CWE+CVSS keeps 75% of the gain; on held-out vendors it beats text). Sector degrades (41%).

### Phase 5 - Go/no-go

- [x] Write up spike findings against the pre-registered thresholds
- [x] Final call on paper framing (sector vs. time-to-KEV)
  - **GO on time-to-KEV**, conditional on disclosure-time features and a wider window. Sector is reported as a negative result. See [docs/spike_findings.md](docs/spike_findings.md).
  - *Post-spike review:* time-to-KEV is retained as evidence of the exposure window, not as a paper target (its label measures CISA's process; EPSS covers the prediction niche). Sector moves to Phase 6.
- [x] Scope a transformer follow-up only if the linear baseline earns it
  - Not yet earned (text-only < CWE+CVSS on held-out vendors, n=522). A frozen-embedding probe is scoped behind an explicit trigger in the findings doc.

### Phase 6 - Sector v2

- [x] Pre-register Sector v2 gates in `config.yaml` (`sector_v2`)
- [ ] Multi-label sector sets with third-party-component hygiene
- [ ] V1: label volume after hygiene
- [ ] Product -> vendor -> prior sector lookup
- [ ] Temporal (2023-2024 -> 2025) and vendor-grouped splits
- [ ] V2: lookup macro-AP and coverage on the temporal split
- [ ] V3: unmasked text + CWE + CVSS on unseen vendors
- [ ] Reach: non-ICS CVEs covered by the lookup
- [ ] Sector v2 write-up and decision

## License

Code is released under the MIT License (see `LICENSE`). Upstream data (NVD, CISA KEV, CISA ICS advisories) is subject to its publishers' own terms.
