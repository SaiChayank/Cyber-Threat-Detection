# DGA classifier development — 29 September 2026

The broader lexical classifier is implemented, fitted, exported and integrated
behind a quality gate. **It is not active in the dashboard.** The final candidate
fails the predeclared comparison-recall and benign-DNS false-positive gates, so the
existing conservative guard remains active. DGA detection is not deployment-ready.

## Data and provenance

The official [UMUDGA v1 release](https://data.mendeley.com/datasets/y8ph45msv8/1)
by Mattia Zago, Manuel Gil Perez and Gregorio Martinez Perez is MIT-licensed,
DOI `10.17632/y8ph45msv8.1`. This phase downloads 51 complete raw-text files:
10,000-domain lists for 50 DGA variants and a 100,000-domain legitimate reference.
Total transfer: **11,451,100 bytes**. Every file matches publisher size and SHA256.
No malware program or DGA generator source is downloaded or executed.

Files live in `data/raw/umudga-expanded/`, separately from the original seven lists.
`data/umudga_expanded_manifest.json` retains source URLs, file IDs and hashes.
Raw files are excluded from Git. The existing two CIC benign-reference PCAPs also
have their catalog hashes checked. Query names from the first capture supply
22,336 distinct first-label hard negatives; the second supplies a separate check.

Publisher labels describe reference lists and captures, not independently verified
current threat intelligence. Domains are strings; no network packet timings,
source behavior or attack sessions are invented from them.

## Splits and leakage controls

Related variants such as `fobber_v1/v2`, `gozi_*` and `suppobox_*` share a family
group. Groups use a stable SHA256 split defined before fitting. The previously
inspected banjori, corebot, dircrypt, matsnu, necurs and ramnit groups are training
only. The original 1,000 legitimate references also remain in training.

First labels are the actual feature vectors' identifiers. Identical first labels
cannot cross train/validation/test splits even when their suffixes differ.
Twenty conflicting benign/attack labels are excluded. Cross-split positive-label
collisions are excluded too; none occur in this selected data. Training positives
are capped at 2,000 per variant with deterministic sampling; held-out lists are
used completely after normalization/deduplication.

| Split | Benign first labels | DGA first labels | Variant lists |
| --- | ---: | ---: | ---: |
| Training | 67,715 | 69,993 | 35 |
| Validation | 15,236 | 80,000 | 8 |
| Comparison test | 14,910 | 60,577 | 7 |

Validation groups: cryptolocker, fobber, locky, murofet and proslikefan.
Comparison groups: bedep, ccleaner, chinad, kraken, sisron and symmi.
Test-family results were inspected after the initial baseline; later feature/model
iterations reuse these splits. They are **development comparisons**, not an untouched
final test. No previously unseen word-based group appears in this comparison split.
The same historical publisher is used throughout; independent contemporary data
is still needed for generalization claims.

## Model and inference

`datasets/train_dga_v2.py` fits character bigrams/trigrams with TF-IDF and logistic
encoding, plus ten first-label statistics: length, entropy, digits, vowels, hyphens,
unique characters, consonant/digit runs, digit transitions and adjacent repeats.
One hundred depth-three boosted trees combine the encoding with those statistics.
Vocabulary, IDF, scaling, coefficients and trees are fitted on training rows only.
Family IDs, TLDs, addresses, timestamps and source file names are not predictors.

The threshold is selected on validation from a fixed grid. Eligibility requires
recall >=80%, precision >=95% and FPR <=2%. Those conditions must also hold on the
comparison split; unseen first labels from the second benign DNS reference must
have FPR <=2%. The gate was not relaxed after observing failures.

`ml/dga_v2.json` contains only numbers, feature contracts and provenance, protected
by `ml/dga_v2.sha256`. Runtime `ml/dga.py` uses the Python standard library:
no sklearn import, pickle, networking, source query or decryption. Names are bounded
and normalized; unsupported wire-name representations abstain. The per-model score
cache has a 4,096-label limit. Each tree has bounded inference depth. Float32 tree
inputs match sklearn's comparisons; saved reference vectors verify exported scores.

The pipeline ignores synthetic DGA hits and the old length rule when an approved
lexical model is active. A negative model decision cannot be overridden by them.
Model alerts include the observed DNS name, scored label, threshold, feature
version and an explicitly **uncalibrated** score kind. Disabled/missing models
retain the conservative guard; modified artifacts fail integrity checking.
`/api/telemetry` reports `dga_detector` and `dga_candidate_enabled`.

## Measured development comparisons

All three models use the same split definition. Thresholds use validation only.

| Candidate | Comparison recall | Comparison FPR | Second DNS-reference FPR |
| --- | ---: | ---: | ---: |
| Character TF-IDF/logistic | 56.84% | 0.93% | 1.50% |
| Add lexical statistics | 74.02% | 1.80% | 2.65% |
| Add bounded boosted trees | **76.77%** | **1.68%** | **2.34%** |

The final threshold is **0.9**. Validation recall is 91.97%, FPR 1.76% and precision
99.64%. Comparison counts are TP 46,503, FN 14,074, FP 251, TN 14,659; precision is
99.46%. The conservative length-20 guard detects **zero** positives on this same
short-label comparison. Its earlier 7.97% recall was on different, smaller inputs
and must not be presented as a directly comparable test result.

The second DNS-reference check excludes training labels and first-capture labels:
275 of 11,731 unseen labels trigger the candidate. These are unique-label decisions
against a benign reference, not flow-level false-positive rates. Actual traffic
prevalence is different from these positive-heavy domain tests; the reported
precision is not production precision. Scores are not probabilities of compromise.

The final candidate is disabled because 76.77% recall is below 80% and 2.34% DNS
reference FPR exceeds 2%. Weak families include ccleaner (58.67%), symmi (57.25%)
and kraken_v1 (66.43%). Lowering the gate or selecting a threshold on test data
would conceal those limitations. The reports retain earlier failed baselines.

## Reproduce and verify

```powershell
.venv/Scripts/python.exe -m pip install '.[dga-training]'
.venv/Scripts/python.exe -m datasets.download_domains --expanded
.venv/Scripts/python.exe -m datasets.train_dga_v2
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m datasets.validate_streaming
npm run build
```

Training also requires the original legitimate list and the two prepared benign
DNS captures described in [Dataset integration](DATASETS.md). It uses sklearn
1.9.1 and NumPy 2.5.3 in this run. These are optional training dependencies.
The included artifact runs with the normal application dependencies.

**81 tests pass**; the production website/TypeScript build passes. The Monitor
loads its preserved history, live connection and refreshed benchmark without
browser console errors. The active guard pipeline sustains **2,514 metadata
events/sec** with SQLite, processing/persistence p95 **1.28 ms**, on the saved
20,000-event synthetic workload. This does not benchmark an activated candidate,
capture parsing, HTTP, SSE or rendering.

Next work should expand hard-negative variety and improve short/pronounceable
family discrimination using validation-only experiments. Reserve new data before
the next evaluation. Consider causal DNS behavior only when genuine labelled
observations exist; a list wrapper cannot validate timing or behavioral accuracy.
