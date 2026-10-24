# Literature review: fingerprint -> CPE matching

*2026-10-24. This review informs the go/no-go on the "CVE exposure mapping without an
asset inventory" proposal (README, "Next steps"). Citation keys refer to
[`literature.bib`](literature.bib).*

**Method and limits.** Targeted web search (general web, arXiv, Crossref, publisher
pages, USPTO and Google Patents), not a systematic database review. For most papers
only the abstract or summary was read. Patent *claims* were not read, so their scope
is unknown. Search terms covered banner -> CPE, CVE-text -> CPE, passive ICS/IoT
device identification, ICS datasets and network-owner classification.
**A systematic search (IEEE Xplore, ACM DL, Scopus) is still needed before any
submission.**

## Bottom line

1. **Mapping banners to CPEs with ML is not novel, and it is patented.**
   - It has been done academically since 2017 [na2017study; na2018service; feng2018are;
     ohare2019scout; ponce2024sbseg]. ARE's accuracy did not reproduce in an independent
     re-implementation [javed2020banner].
   - Commercial scan engines ship it as rule and heuristic fingerprints with confidence
     scores [censys_software_docs; recog].
   - **CrowdStrike holds a granted US patent on LLM-based banner -> CPE prediction**
     (US 12,625,973 B1, granted 2026-05-12). An ML-modeling sibling application has a
     notice of allowance, and there are two more banner-similarity / synthetic-CPE
     filings whose assignees were not verified [drew2026llmcpe; uspto12549590;
     uspto12705364; uspto12339972].
   - The recommended direction, as worded, fails its own kill criterion: the problem is
     substantially addressed.
2. **Passive traffic -> vendor identification is mature, but the product and version
   level isn't.**
   - Vendor identification is now very accurate at scale: 98.7% top-1 across 2,015 IoT
     vendors with an instruction-tuned LLM [mahmood2025llmiot], building on passive-DNS
     identification [perdisci2020iotfinder].
   - ICS work identifies device type, vendor and sometimes model on small testbeds
     [niedermaier2019mac; yang2024icsasset; icsscada_hybrid; mavrakis2015passive].
   - None of the work found maps passive traffic all the way to CPE and scores the
     result by CVE-applicability accuracy.
   - Firmware version, which decides whether a CVE applies, is the attribute
     practitioners say passive methods often can't capture [dragos2025active;
     wilson2026s71200].
3. **No public benchmark measures fingerprint -> CPE -> CVE accuracy.**
   - The closest dataset, ICSLibrary, has vendor/type/model labels for 2,205 ICS
     endpoints, but no CPEs or versions, and the provenance of its ground truth is
     undocumented [icslibrary].
   - A 2026 survey names the lack of standardized ICS benchmarks as a persistent gap
     [alqahtani2026roadmap].
4. **The CVE side is the weaker link, and the field knows it.**
   - CVE text -> CPE labeling is well studied: F-measure 0.86, then F1 about 0.96
     [wareus2020cpe; hu2024cpeidentifier].
   - Vendor naming in CPE data is inconsistent: over 50% of vendor names
     [jiang2025vulcpe; anwar2022cleaning].
   - Asset discovery and detection precision are named open problems for
     enumeration-based vulnerability identification [sadlek2022challenges].
   - NVD has stopped enriching every CVE [csa2026nvd]. This spike measured 37% of 2025
     CVEs with no CPE.
   - A perfect fingerprint -> CPE match still misses every CVE that has no CPE.
5. **The scan-data sector-prior idea is undercut.**
   - ASdb can classify network owners into industries at 93% accuracy across 17
     categories [ziv2021asdb].
   - But Censys finds exposed ICS concentrated on carrier and ISP networks: over 50% of
     low-level automation hosts, and over 80% of exposed HMIs on wireless networks
     [censys2024ics].
   - So for ICS, the network owner usually isn't the operator, and owner industry is a
     poor proxy for deployment sector.

## What remains open (candidate contributions)

These are narrower than the original proposal. Each would need its own feasibility
check.

| Gap | Why it's open | Nature of contribution | Main risk |
|---|---|---|---|
| **A. End-to-end benchmark:** passive observation -> CPE -> CVE applicability, scored by CVE precision/recall | Prior work stops at vendor/model, or scores CPEs, not CVE applicability; no public benchmark exists | Dataset + evaluation methodology (measurement/datasets venue), ML baselines included | Ground truth needs devices with known firmware: testbed access or a partner |
| **B. Version-uncertain CVE applicability:** calibrated probability that a CVE applies when version is unobserved or partial | Passive methods often can't see firmware; CPE matching is binary and assumes a known version [tovarnak2021graphcpe] | ML: probabilistic version inference + calibrated scoring | May reduce to priors over version distributions; needs version ground truth |
| **C. Joint CVE-side and device-side resolution:** matching when the CVE has no CPE, using CVE text (`affected`, description) directly against device evidence | Device-side and CVE-side CPE work are separate literatures; the NVD backlog breaks the CPE bridge | ML: entity resolution between two noisy text sources, skipping CPE | Overlap with VulCPE-style work [jiang2025vulcpe]; needs a careful novelty check |

**Patent caution.** A/B/C are research contributions. Productizing anything that
predicts CPEs from banners with ML or LLMs would need a freedom-to-operate review
against the CrowdStrike family.

## How this relates to the spike's findings

- The spike's core finding (a CVE describes the flaw, not where it is deployed) is
  consistent with this literature and not contradicted by it.
- The spike's vendor-data audit (spelling variants, "n/a" placeholders, multi-vendor
  CVEs, the 2025 CPE gap) is already documented in general terms [anwar2022cleaning;
  jiang2025vulcpe; csa2026nvd]. The ICS-specific measurements (third-party relisting
  in advisories, boilerplate sector lists) were not found in prior work.

## Verdict: no-go

**There is no viable ML research direction here as the project was conceived.**
Every thread ended in a negative result or prior art:

| Thread | Outcome |
|---|---|
| Sector from CVE data (v1, Sector v2) | Failed. v2 passed its gate by +0.012, only because Siemens reuses one sector list; without Siemens it fails. Chance level on unseen vendors |
| Time-to-KEV | Real signal, but the label partly measures CISA's listing process, and EPSS already covers the prediction across all CVEs |
| Fingerprint -> CPE | Academic prior art since 2017, shipped in commercial scan engines, and a granted CrowdStrike patent on the ML/LLM variant |
| Sector priors from scan data | Exposed ICS sits mostly on ISP networks, so network-owner industry doesn't reflect sector |

**The open gaps above are not an ML proposal.**
- Gap A (an end-to-end benchmark) needs devices with known firmware versions. That is
  the same data-access problem as fingerprinting, just moved.
- Practitioners say passive methods often can't see firmware at all, and public
  testbeds offer a few dozen devices.
- The likely outcome is documenting that passive methods can't establish CVE
  applicability. That is a measurement paper, not an ML contribution.
- Gaps B and C depend on the same version ground truth, or overlap existing work.

**What is real, but modest (workshop-level measurement or position piece):**
- ICS advisory label quality: third-party relisting (1,568 of 6,435 links),
  boilerplate sector lists, and ICS advisories covering 4.4% of CVEs.
- The KEV-lag distribution: median 7.5 days, a quarter over 90 days.
- The argument that public vulnerability data can't substitute for asset context, so
  asset-inventory gaps are the binding constraint.

**Correction to earlier advice.** Before this review, the README's next-steps advice
called passive fingerprinting "the untested route", and the conversation recommended
it as a viable proposal. That recommendation was premature; this review overturns it.
