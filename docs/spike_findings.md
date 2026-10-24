# Spike findings: go/no-go

*Run 2026-10-24 on CVEs published 2023-2025 (NVD 2.0 feeds pulled 2026-10-24).
Reproduce with `scripts/run_spike.sh full` (~90 s from cache). Raw numbers:
`data/processed/results_*.json`, `data/processed/diagnostics.json`, notebooks `00`-`02`.*

These are go/no-go signals from linear baselines, not paper results.

## Verdict

**GO on the time-to-KEV framing, with two conditions to clear before any claim
(below). Sector prediction does not pass Q1 and is reported as a negative result.**

> **Post-spike review:** the GO above is the pre-registered fallback rule firing,
> not a judgment that time-to-KEV is a valuable prediction target. On review it
> isn't one: its label measures CISA's listing process as much as exploitation, and
> EPSS already covers the predictive niche. Time-to-KEV is kept as **descriptive
> evidence of the exposure window**. Sector continues as a re-scoped follow-up
> (README, "Sector v2"). See [Post-spike review](#post-spike-review).

| Gate | Sector | Time-to-KEV |
|---|---|---|
| Q1 labels in volume | **FAIL** (balance: 62.0% > 60%) | n = 522 (no volume gate was pre-registered for it) |
| Q2 masked text > majority + 0.15 | pass (+0.44), but vendor lookup beats it | **pass** (+0.30) |
| Q2 vendor-grouped > majority + 0.05 | borderline (+0.097) | pass (+0.17) |
| Q3 text-free retention >= 50% | degrades (41%) | **pass** (75%) |

## Pre-registration

The README's prose thresholds were turned into numbers in `config.yaml` (`gates`,
`labels`) before any label count or score was viewed. They were first committed
together with the Q1 result (commit `025b04e`), so the git timestamp alone does not
prove they came first. Two changes were made after seeing results, and both are
reported here: advisory typo handling in sector parsing, and per-block L2
normalization of features. Neither changed a verdict (see Sensitivity).

## Q1: do sector labels exist in volume?

CISA ICS advisories (CSAF 2.0, 2,148 advisories from 2022-2026) cover **4,986** of
113,475 NVD CVEs published 2023-2025 (4.4%).

| | CVEs |
|---|---|
| >= 1 canonical CISA sector | 4,125 |
| exactly one sector (primary task) | **2,037** (2,023 without typo handling) |
| 2+ sectors | 2,088 |
| "Multiple Sectors" / unparsable | 861 |

Single-sector distribution: Critical Manufacturing 1,262 (**62.0%**), Energy 408,
Healthcare 110, Communications 93, Commercial Facilities 83, IT 34, then <30 each.

- Volume (>= 2,000): pass, by a margin of 37.
- Sectors with >= 50 CVEs (>= 5): pass, exactly 5.
- Largest share (<= 60%): **fail** at 62.0%.

**Q1 fails, so the pre-registered rule pivots to time-to-KEV.** The miss is narrow,
but the other two checks also pass only at their minimums, and the label space is
structurally thin: in multi-label terms Critical Manufacturing appears on 76% of
CVEs, and advisories tag sectors where a product is *deployed*, not what a CVE is
*about*. Sector was still run through Q2/Q3 as a diagnostic.

## Q2: is there signal in the text? (product/vendor tokens masked)

Logistic regression on TF-IDF (1-2 grams), class-balanced, 5-fold macro-F1.
"Grouped" = StratifiedGroupKFold by vendor, so no vendor is in both train and test.

| | Sector stratified | Sector grouped | TTK stratified | TTK grouped |
|---|---|---|---|---|
| majority class | 0.129 | 0.125 | 0.222 | 0.221 |
| vendor -> label lookup | **0.773** | 0.125 | 0.443 | 0.221 |
| text, unmasked | 0.735 | 0.263 | 0.560 | 0.383 |
| **text, masked** | **0.569** | **0.222** | **0.521** | **0.391** |

**Sector:** passes the pre-registered gate (+0.44), but the result doesn't survive
inspection:
- A lookup of the vendor's most common sector (0.773) beats every text model.
- Masking costs 0.17, and holding vendors out collapses masked text to 0.222.
  Per-class grouped F1 is 0.00 for IT and 0.05 for Commercial Facilities.
- Siemens alone is 37% of labeled CVEs. 14% of sector labels are third-party
  component CVEs (Fortinet, VMware, etc.) relisted in an ICS vendor's advisory
  that inherit its sector.

The sector "signal" is mostly vendor identity. That is the negative finding the
README anticipated: a real result worth reporting, not a model.

**Time-to-KEV:** passes on both splits. Masking costs only 0.04 and the
vendor-grouped split keeps +0.17, so the signal is not vendor identity. Per-class
masked F1: <=7d 0.68, 8-90d 0.44, >90d 0.44. Exploitation language in descriptions
("actively exploited", ...) is present in 16% of <=7d CVEs. Removing it leaves F1 at
0.521 stratified and 0.378 grouped, so post-hoc wording is not driving the result.

## Q3: does the ablation degrade gracefully?

Masked text, blocks L2-normalized, 5-fold macro-F1.

| feature set | Sector strat | Sector grouped | TTK strat | TTK grouped |
|---|---|---|---|---|
| text | 0.569 | 0.222 | 0.521 | 0.391 |
| text + cwe | 0.509 | 0.205 | 0.501 | 0.421 |
| text + cwe + cvss | 0.503 | 0.236 | 0.503 | 0.433 |
| **cwe + cvss (minimal)** | 0.284 | 0.201 | **0.434** | **0.448** |
| retention (gate) | **41% (degrades)** | 68% | **75% (pass)** | 107% |

- **Sector:** the text-free set degrades but doesn't cliff. Metadata adds nothing to
  text, so the embeddable-model story is weak for sector.
- **Time-to-KEV:** the minimal CWE + CVSS set keeps 75% of the gain. On held-out
  vendors it *matches or beats* text. This is the strongest result in the spike: a
  small, text-free, embeddable feature set carries most of the time-to-KEV signal.

## Conditions before writing (time-to-KEV)

1. **Disclosure-time features.** The NVD feeds are a 2026 snapshot. CVSS and CWE
   can be added or rescored *after* KEV listing, and NVD prioritizes KEV CVEs for
   enrichment. Whether NVD scored a CVE itself varies by class (64% for <=7d, 78%
   for 8-90d, 68% for >90d), so some enrichment leakage is plausible, and it would
   inflate exactly the Q3 minimal-set result. Rebuild features from the CVE record
   as first published (cvelistV5 git history) and rerun Q2/Q3. **If the minimal set
   falls below the 50% retention gate on disclosure-time features, the embeddable
   claim dies.**
2. **Sample size.** n = 522 gives fold SDs up to 0.07. Widen the window (KEV dates
   back to 2021 listings of much older CVEs; a 2018-2025 publication window should
   roughly double n) and confirm the gates still pass.

Framing caveats to carry into the paper: time-to-KEV is conditional on eventual KEV
listing (it doesn't predict *whether* a CVE is exploited). Later-published CVEs are
right-censored for the >90d class. 26 CVEs were KEV-listed before NVD publication
and fall in the <=7d bucket.

## Final call on framing

*Superseded by the [Post-spike review](#post-spike-review); kept as originally written.*

**Time-to-KEV is the paper framing.** It has clean, externally sourced labels with
no sector dependency, signal that survives product masking and vendor hold-out, and
a text-free minimal model that holds up, which is the embeddable story.

**Sector is a negative result**, used as motivation or a secondary section: public
CVE text predicts ICS deployment sector mainly through vendor identity, and labels
are dominated by one sector and one vendor.

## Transformer follow-up: not yet earned

The trigger was "only if the linear baseline earns it". It hasn't, for text:
- On held-out vendors, text alone (0.391) is *below* CWE + CVSS (0.448).
- n = 522 is too small to fine-tune.

Scoped plan, only after conditions 1-2 are met:
- **Trigger:** on the widened, disclosure-time dataset, masked text-only grouped
  macro-F1 is >= the CWE + CVSS grouped macro-F1 + 0.05.
- **Then:** a frozen sentence-embedding probe (small open encoder, embeddings + the
  same logistic regression, CPU or free Colab), not fine-tuning. Fine-tune only if
  the probe beats TF-IDF by >= 0.05 grouped macro-F1.
- **Otherwise:** the paper's model is the linear CWE + CVSS (+ text) baseline. The
  contribution is the label construction, the leakage controls (masking, vendor
  grouping, disclosure-time features) and the ablation curve.

## Sensitivity

- Without the per-block L2 normalization (the original run), every verdict is the
  same. Sector Q3 retention is 47% instead of 41%; TTK is 82% instead of 75%.
- Without the advisory typo handling, the single-sector count is 2,023 instead of
  2,037. Q1 still fails, on the same check.
- With CPE dictionary titles added to masking: masked sector F1 0.567 -> 0.569.

## Post-spike review

*Added 2026-10-24, after the verdict above. Nothing above was re-scored; this changes
how the results are used, not what they are.*

**Time-to-KEV is a weak prediction target.**
- *The label measures CISA as much as attackers.* KEV `dateAdded` is when CISA
  confirmed and listed a CVE, not when exploitation began. A model predicting it
  partly learns CISA's intake priorities and latency, so it evaluates the KEV process
  more than it forecasts exploitation.
- *The niche is taken.* EPSS already scores exploitation likelihood daily from
  disclosure. A three-bucket "how fast will this be listed", defined only on CVEs
  that eventually are, adds little beside it.
- *It's conditional.* It says nothing about the CVEs that never reach KEV, which
  are the large majority.

**What it is useful for: measuring the exposure window.** The same property that
makes it a poor target makes it the right measurement of how long the central
apparatus takes to issue an authoritative "this is exploited" signal. Among the 522
KEV CVEs published 2023-2025:
- **half were listed within 7.5 days**, and a quarter took more than 90;
- the mean was 91 days and the longest 1,268;
- 26 were listed before NVD publication.

These figures are conditional on eventual listing and right-censored for late-2025
CVEs. They are retained as descriptive evidence for the companion IDS-integration
argument, not as a model.

**The Q3 result is still the useful finding.** A small, text-free CWE + CVSS set
carries most of the time-to-KEV signal and holds up on unseen vendors. That is
evidence (pending the disclosure-time condition) that vulnerability metadata alone
can drive an embeddable model. Its value has to be shown against EPSS over all CVEs,
not on KEV-listed CVEs only.

**Sector is re-scoped, not dropped.** v1 tested whether description *text* predicts
sector with product names removed, and found it mostly doesn't. For an RMF input,
the affected product is known when a CVE is assessed against a system, so the
transparent vendor -> sector lookup (macro-F1 0.773, the best score in the spike)
is the relevant artifact. Sector v2 (README) tests that framing with:
- multi-label sectors and third-party label hygiene;
- a temporal split;
- separate evaluation on unseen vendors;
- pre-registered gates in `config.yaml` -> `sector_v2`.
