# Sector v2 findings: CVE -> sector exposure as an RMF input

*Run 2026-10-24 from the v1 cache. Reproduce with `scripts/run_spike.sh full` (or
`python -m src.sector_v2`). Raw numbers: `data/processed/results_sector_v2.json`.
Pre-registered design and gates: README "Sector v2", `config.yaml` -> `sector_v2`.*

## Verdict

| Gate | Result | Threshold | |
|---|---|---|---|
| V1 labels after hygiene | 3,193 CVEs, 12 sectors >= 100 positives | >= 3,000, >= 6 | **pass** |
| V2 lookup, temporal split (train 2023-24, test 2025) | macro-AP 0.428 vs prevalence 0.215, **gain +0.212**; coverage 81% | gain >= 0.20, coverage >= 50% | **pass (narrow, fragile)** |
| V3 unseen vendors, text + CWE + CVSS | macro-AP 0.227 vs 0.217, **gain +0.010** | gain >= 0.10 | **fail** |

**Decision, by the pre-registered rules:**
- V2 passes, so the transparent product -> vendor -> sector lookup is the RMF
  deliverable.
- V3 fails, so the deliverable is lookup-only, and its coverage bound is the stated
  limitation.
- Public vulnerability data cannot infer sector for a product it hasn't seen. The
  text, CWE and CVSS of an unseen vendor's CVEs carry essentially no sector signal.

**What this means for the telemetry premise.** Without an asset inventory, the
chain is telemetry -> product/vendor -> sector.
- v2 tests only the second hop. It works for known ICS products, on a narrow
  margin, and fails for unknown ones.
- The first hop (fingerprinting a product from traffic) was out of scope here.
- So sector context has to come either from mapping telemetry to a *known* product,
  or from the organization itself. It does not come from the vulnerability record.

## V1: labels

- 6,435 CVE-advisory links, of which **1,568 were dropped as third-party** (the
  advisory vendor isn't among the CVE's own NVD vendors). The largest block: 496
  Linux kernel CVEs relisted in Siemens advisories. Others: Fortinet, Microsoft,
  Palo Alto Networks, CODESYS, Node.js, OpenSSL.
- Links with no NVD-side vendor to check against were kept.
- 3,193 CVEs keep >= 1 sector, and 12 sectors have >= 100 positives. Chemical, Food
  and Agriculture, and IT are modeled but thin.
- Before hygiene, v1's numbers already passed this gate, so V1 only shows that
  hygiene didn't break label volume.

## V2: the lookup (temporal split)

Scores for a 2025 CVE come from training CVEs with the same product, else the same
vendor, else the prior. Keys come from the NVD side only (CPE, CVE 5 "affected"), so
the lookup applies to any CVE.

- Coverage of 2025 CVEs: 52% by product, 29% by vendor, 19% prior-only.
- Gain: +0.212 overall; +0.216 excluding Critical Manufacturing; +0.209 on covered
  CVEs only. Macro-F1 at a 0.5 threshold: 0.486.
- Per-sector AP (prevalence in brackets):
  - strong: Critical Manufacturing 0.88 (0.70), Energy 0.72 (0.50);
  - moderate: Healthcare, Transportation, Government;
  - weak: Chemical, Food and Agriculture, IT, Communications.

**It's fragile.**
- Siemens is 53% of the 2025 test set, and 46% of Siemens CVEs carry one identical
  six-sector list (Critical Manufacturing, Energy, Financial Services, Government,
  Healthcare, Transportation). That looks like advisory boilerplate, not
  per-product deployment.
- Excluding Siemens, the gain is **+0.182, below the 0.20 gate**.
- The pass rests on the largest vendor's template being predictable.

## V3: unseen vendors

Folds are grouped by advisory vendor. Any training CVE sharing a vendor key with the
test fold is purged, so test vendors are genuinely unseen.

- The text + CWE + CVSS one-vs-rest logistic model gets macro-AP gain **+0.010**
  (+0.003 excluding Critical Manufacturing).
- Sensitivity: grouping by connected vendor components instead gives +0.012 to +0.013 (varies slightly between runs with set ordering).
- The lookup on the same split sits at the prior (+0.007), which confirms that no
  vendor leaks across folds.

Unmasked text doesn't help either. Category words in descriptions ("PLC",
"inverter", "infusion pump") don't transfer across vendors well enough to register.

## Reach (descriptive, no gate)

The lookup reaches **7,889 of 110,282** non-ICS CVEs in the window: 2,912 by product
and 4,977 by vendor.
- 43% of the reach is Microsoft, because 4 ICS advisories name Microsoft as the
  vendor. That spreads those advisories' sectors over thousands of unrelated
  Microsoft CVEs. D-Link, Samsung and QNAP follow.
- **Vendor-level reach is not meaningful.** A vendor present in a handful of
  advisories isn't a sector signal for its whole catalogue.
- Product-level reach (2,912) is more plausible but unvalidated.
- A usable lookup needs a minimum-support or sector-purity rule per key.

## Vendor data quality

Vendor fields in NVD and CVE 5 are noisy enough to shape every result above:

| issue | measure (CVEs published 2023-2025) |
|---|---|
| No CPE configuration (NVD enrichment backlog) | 22% overall: 0% for 2023, 20% for 2024, **37% for 2025** |
| CVE 5 "affected" vendor is a placeholder ("n/a") | 17% |
| No usable vendor from either source | 1.4% |
| More than one vendor on a CVE | 24% |
| Spelling variants of one vendor | Siemens 4, Schneider Electric 5 (incl. "Schneider ELectric", trailing spaces, NBSP) |

The vendor *name* problem is solvable with normalization (done here). The
*semantic* problem isn't, at least not from these fields:
- multi-vendor CVEs and third-party relisting blur whose product a sector tag
  belongs to;
- advisory-level sector lists are coarse and sometimes boilerplate;
- one ICS advisory for a general-IT vendor contaminates that vendor's whole
  catalogue.

## Implementation changes made after seeing results

All were bug fixes against the pre-registered intent. Each is reported with its
effect:

1. **Separator-free vendor matching** ("mitsubishi_electric" = "mitsubishielectric")
   and an `ni` -> National Instruments alias. Hygiene now drops 1,568 links instead
   of 1,621, and the v1 third-party diagnostic moves from 14% to 13%.
2. **Fold grouping on unseen vendors.** The first run leaked: the lookup scored
   +0.147 on "unseen" vendors because one vendor appeared under several spellings.
   It's now grouped by canonical advisory vendor with purging; the lookup sits at
   the prior.
3. **Lookup attribution.** Only the advisory vendor's own keys get sector credit,
   and "n/a" placeholders are ignored. Before this, the lookup credited Siemens's
   sectors to Linux, and "n/a" made up 35% of reach.
   - V2 gain before the fix: +0.238 (+0.167 excluding Siemens).
   - After: +0.212 (+0.182 excluding Siemens). The V2 verdict is unchanged.
   - The pre-fix run is kept in `data/processed/results_sector_v2_unattributed.json`.
