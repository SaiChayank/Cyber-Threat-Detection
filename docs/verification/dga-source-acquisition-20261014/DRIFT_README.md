---
license: cc-by-nc-sa-3.0
language:
  - en
pretty_name: "DRIFT: Longitudinal Benign and DGA Domain Name Dataset (2017-2025)"
size_categories:
  - 100M<n<1B
task_categories:
  - text-classification
tags:
  - security
  - dga
  - domain-generation-algorithm
  - malware
  - concept-drift
  - cybersecurity
  - network-security
annotations_creators:
  - machine-generated
source_datasets:
  - original
configs:
  - config_name: T17_eSLD
    default: true
    data_files:
      - split: train
        path:
          - DRIFT_input_eSLD/T17_benign_train.parquet
          - DRIFT_input_eSLD/T17_dga_train.parquet
      - split: validation
        path:
          - DRIFT_input_eSLD/T17_benign_val.parquet
          - DRIFT_input_eSLD/T17_dga_val.parquet
      - split: test
        path:
          - DRIFT_input_eSLD/T17_benign_test.parquet
          - DRIFT_input_eSLD/T17_dga_test.parquet
  - config_name: T18_eSLD
    data_files:
      - split: train
        path:
          - DRIFT_input_eSLD/T18_benign_train.parquet
          - DRIFT_input_eSLD/T18_dga_train.parquet
      - split: validation
        path:
          - DRIFT_input_eSLD/T18_benign_val.parquet
          - DRIFT_input_eSLD/T18_dga_val.parquet
      - split: test
        path:
          - DRIFT_input_eSLD/T18_benign_test.parquet
          - DRIFT_input_eSLD/T18_dga_test.parquet
  - config_name: T19_eSLD
    data_files:
      - split: train
        path:
          - DRIFT_input_eSLD/T19_benign_train.parquet
          - DRIFT_input_eSLD/T19_dga_train.parquet
      - split: validation
        path:
          - DRIFT_input_eSLD/T19_benign_val.parquet
          - DRIFT_input_eSLD/T19_dga_val.parquet
      - split: test
        path:
          - DRIFT_input_eSLD/T19_benign_test.parquet
          - DRIFT_input_eSLD/T19_dga_test.parquet
  - config_name: T20_eSLD
    data_files:
      - split: train
        path:
          - DRIFT_input_eSLD/T20_benign_train.parquet
          - DRIFT_input_eSLD/T20_dga_train.parquet
      - split: validation
        path:
          - DRIFT_input_eSLD/T20_benign_val.parquet
          - DRIFT_input_eSLD/T20_dga_val.parquet
      - split: test
        path:
          - DRIFT_input_eSLD/T20_benign_test.parquet
          - DRIFT_input_eSLD/T20_dga_test.parquet
  - config_name: T21_eSLD
    data_files:
      - split: train
        path:
          - DRIFT_input_eSLD/T21_benign_train.parquet
          - DRIFT_input_eSLD/T21_dga_train.parquet
      - split: validation
        path:
          - DRIFT_input_eSLD/T21_benign_val.parquet
          - DRIFT_input_eSLD/T21_dga_val.parquet
      - split: test
        path:
          - DRIFT_input_eSLD/T21_benign_test.parquet
          - DRIFT_input_eSLD/T21_dga_test.parquet
  - config_name: T22_eSLD
    data_files:
      - split: train
        path:
          - DRIFT_input_eSLD/T22_benign_train.parquet
          - DRIFT_input_eSLD/T22_dga_train.parquet
      - split: validation
        path:
          - DRIFT_input_eSLD/T22_benign_val.parquet
          - DRIFT_input_eSLD/T22_dga_val.parquet
      - split: test
        path:
          - DRIFT_input_eSLD/T22_benign_test.parquet
          - DRIFT_input_eSLD/T22_dga_test.parquet
  - config_name: T23_eSLD
    data_files:
      - split: train
        path:
          - DRIFT_input_eSLD/T23_benign_train.parquet
          - DRIFT_input_eSLD/T23_dga_train.parquet
      - split: validation
        path:
          - DRIFT_input_eSLD/T23_benign_val.parquet
          - DRIFT_input_eSLD/T23_dga_val.parquet
      - split: test
        path:
          - DRIFT_input_eSLD/T23_benign_test.parquet
          - DRIFT_input_eSLD/T23_dga_test.parquet
  - config_name: T24_eSLD
    data_files:
      - split: train
        path:
          - DRIFT_input_eSLD/T24_benign_train.parquet
          - DRIFT_input_eSLD/T24_dga_train.parquet
      - split: validation
        path:
          - DRIFT_input_eSLD/T24_benign_val.parquet
          - DRIFT_input_eSLD/T24_dga_val.parquet
      - split: test
        path:
          - DRIFT_input_eSLD/T24_benign_test.parquet
          - DRIFT_input_eSLD/T24_dga_test.parquet
  - config_name: T25_eSLD
    data_files:
      - split: train
        path:
          - DRIFT_input_eSLD/T25_benign_train.parquet
          - DRIFT_input_eSLD/T25_dga_train.parquet
      - split: validation
        path:
          - DRIFT_input_eSLD/T25_benign_val.parquet
          - DRIFT_input_eSLD/T25_dga_val.parquet
      - split: test
        path:
          - DRIFT_input_eSLD/T25_benign_test.parquet
          - DRIFT_input_eSLD/T25_dga_test.parquet
  - config_name: T17_raw
    data_files:
      - split: benign
        path: raw_including_TLD/T17_benign.parquet
      - split: dga
        path: raw_including_TLD/T17_dga.parquet
  - config_name: T18_raw
    data_files:
      - split: benign
        path: raw_including_TLD/T18_benign.parquet
      - split: dga
        path: raw_including_TLD/T18_dga.parquet
  - config_name: T19_raw
    data_files:
      - split: benign
        path: raw_including_TLD/T19_benign.parquet
      - split: dga
        path: raw_including_TLD/T19_dga.parquet
  - config_name: T20_raw
    data_files:
      - split: benign
        path: raw_including_TLD/T20_benign.parquet
      - split: dga
        path: raw_including_TLD/T20_dga.parquet
  - config_name: T21_raw
    data_files:
      - split: benign
        path: raw_including_TLD/T21_benign.parquet
      - split: dga
        path: raw_including_TLD/T21_dga.parquet
  - config_name: T22_raw
    data_files:
      - split: benign
        path: raw_including_TLD/T22_benign.parquet
      - split: dga
        path: raw_including_TLD/T22_dga.parquet
  - config_name: T23_raw
    data_files:
      - split: benign
        path: raw_including_TLD/T23_benign.parquet
      - split: dga
        path: raw_including_TLD/T23_dga.parquet
  - config_name: T24_raw
    data_files:
      - split: benign
        path: raw_including_TLD/T24_benign.parquet
      - split: dga
        path: raw_including_TLD/T24_dga.parquet
  - config_name: T25_raw
    data_files:
      - split: benign
        path: raw_including_TLD/T25_benign.parquet
      - split: dga
        path: raw_including_TLD/T25_dga.parquet
---
# DRIFT Dataset

**Longitudinal Benign and DGA Domain Name Dataset (2017–2025)**

- **Authors:** Chaeyoung Lee*, Chaeri Jung*, Seonghoon Jeong (* Equal contribution)
- **Affiliation:** Division of Artificial Intelligence Engineering, Sookmyung Women's University
- **Venue & Paper:** [IEEE/IFIP International Conference on Dependable Systems and Networks (**DSN 2026**)](https://doi.org/10.1109/DSN69566.2026.00077)
- **arXiv:** [arxiv.org/abs/2605.10436](https://arxiv.org/abs/2605.10436)
- **GitHub:** [snsec-net/2026-DSN-DRIFT](https://github.com/snsec-net/2026-DSN-DRIFT)
- **Hugging Face:** [Paper](https://huggingface.co/papers/2605.10436) · [Dataset](https://huggingface.co/datasets/snsec-net/dga-detection-drift26dsn) · [Model](https://huggingface.co/snsec-net/dga-detector-drift26dsn)
- **IEEE DataPort:** [10.21227/za2s-9e09](https://dx.doi.org/10.21227/za2s-9e09)

---

## Description

This dataset was curated and used in the paper "DRIFT: Drift-Resilient Invariant-Feature Transformer for DGA Detection", accepted at IEEE/IFIP DSN 2026.

This dataset provides a nine-year longitudinal collection (2017–2025) of benign and DGA (Domain Generation Algorithm) domain names, designed to support evaluation of DGA detectors under real-world concept drift. Most existing DGA datasets are constructed from a single time period, which masks how quickly detection models degrade when exposed to evolving domain distributions. This dataset addresses that gap by providing temporally aligned benign and malicious domains, enabling forward-chaining experiments that simulate realistic deployment conditions.

|                 | Count                    | Source                                                    |
| --------------- | ------------------------ | --------------------------------------------------------- |
| Benign domains  | ~49.4M unique            | Alexa Top 1M + Tranco Top 1M                              |
| DGA domains     | ~149.4M unique           | DGArchive · 148 families (133 char-based, 15 word-based) |
| **Total** | **~198.8M unique** |                                                           |

### Cumulative Dataset Statistics (from Table I of the paper)

| Period     | Benign (Total) | Benign (Unique) | DGA (Total) | DGA (Unique) | Unique DGA Families |
| ---------- | -------------- | --------------- | ----------- | ------------ | ------------------- |
| 2017       | 1,913,418      | 1,913,418       | 14,888,780  | 14,888,780   | 58                  |
| 2017–2018 | 18,729,906     | 17,129,997      | 30,004,459  | 29,305,992   | 62                  |
| 2017–2019 | 40,508,820     | 29,359,365      | 46,423,032  | 44,940,295   | 65                  |
| 2017–2020 | 58,149,929     | 36,796,092      | 65,116,780  | 62,272,656   | 71                  |
| 2017–2021 | 72,679,722     | 41,856,865      | 84,661,350  | 79,752,910   | 77                  |
| 2017–2022 | 88,262,644     | 47,358,571      | 104,424,484 | 97,107,537   | 80                  |
| 2017–2023 | 92,962,312     | 48,190,058      | 124,186,047 | 114,189,860  | 81                  |
| 2017–2024 | 94,833,375     | 48,805,692      | 144,981,221 | 132,177,150  | 148                 |
| 2017–2025 | 96,849,575     | 49,433,110      | 165,824,441 | 149,405,584  | 148                 |

> Note: counts above are **cumulative** across years (as reported in the paper). The per-year parquet files in this repository are the per-period snapshots used as model input.

---

## Data Collection

**Benign domains** are sourced from Alexa Top 1M and Tranco Top 1M. Historical Alexa snapshots were retrieved via the Internet Archive Wayback Machine, and historical Tranco lists were obtained through the Tranco API. Yearly snapshots were collected from 2017 to 2025. Domains appearing in both the benign and DGA sets were removed to prevent cross-contamination.

**DGA domains** are sourced from **DGArchive**, maintained by Fraunhofer FKIE. DGArchive provides deterministic domain outputs derived directly from reverse-engineered malware algorithms and seeds, along with per-domain timestamps. 148 out of 151 available families were selected based on suitability for longitudinal analysis, covering both character-based (133 families) and word-based (15 families) generation schemes.

**Preprocessing:**

- All domain names are lowercased
- Effective second-level domains (eSLDs) are extracted by stripping TLD and ccTLD suffixes
- Deduplication is performed on effective eSLDs
- Characters are restricted to alphanumerics, hyphens (`-`), and dots (`.`) per IETF RFC 1035

---

## Repository Layout

```
dga-detection-drift26dsn/
├── DRIFT_input_eSLD/         # eSLD, 72 files: T{YY}_{benign,dga}[_{train,val,test}].parquet
│   ├── T17_benign.parquet                    # Full 2017 benign (eSLD)
│   ├── T17_benign_train.parquet              # 1,500,000 samples
│   ├── T17_benign_val.parquet                # 150,000 samples
│   ├── T17_benign_test.parquet               # Remaining samples
│   ├── T17_dga.parquet                       # Full 2017 DGA (eSLD)
│   ├── T17_dga_train.parquet
│   ├── T17_dga_val.parquet
│   ├── T17_dga_test.parquet
│   ├── T18_benign.parquet
│   ├── ... (same pattern for T18–T25)
│   └── T25_dga_val.parquet
└── raw_including_TLD/        # raw + family, 18 files: T{YY}_{benign,dga}.parquet
    ├── T17_benign.parquet                    # Full 2017 benign (with TLD)
    ├── T17_dga.parquet                       # Full 2017 DGA (with TLD + family)
    ├── T18_benign.parquet
    ├── ... (same pattern for T18–T25)
    └── T25_dga.parquet
```

**File naming convention:** `T{YY}_{class}[_{split}].parquet`

- `YY`: two-digit year (`17` = 2017 … `25` = 2025)
- `class`: `benign` or `dga`
- `split` (optional): `train`, `val`, or `test` — omitted for the full yearly file

**Split sizes (`DRIFT_input_eSLD` only):**

- `train`: 1,500,000 samples per class per year
- `val`: 150,000 samples per class per year (10% of train)
- `test`: remaining samples (varies by year and class)

The train size was determined by the smallest yearly class file across all years, ensuring no class/year combination runs out of samples. The full `T{YY}_{class}.parquet` files are the union of train + val + test for that year and class.

`raw_including_TLD/` provides only full yearly files (no pre-split), as it is intended for reference and custom preprocessing rather than direct model input.

---

## Format

### `*_eSLD` configs (DRIFT_input_eSLD/)

All files are *.parquet with the following columns:

| Column     | Type   | Description                                                                   |
| ---------- | ------ | ----------------------------------------------------------------------------- |
| `domain` | string | Effective second-level domain (eSLD), TLD and ccTLD stripped (e.g.`google`) |
| `label`  | int    | `0` = benign, `1` = DGA                                                   |

**Example rows:**

```
domain,label
google,0
vutotoid,1
runtime-incorrect,1
```

### `*_raw` configs (raw_including_TLD/)

All files are *.parquet with the following columns:

| Column     | Type   | Description                                                                   |
| ---------- | ------ | ----------------------------------------------------------------------------- |
| `domain` | string | Raw domain name including TLD (e.g.`google.com`)                            |
| `label`  | int    | `0` = benign, `1` = DGA                                                   |
| `family` | string | DGA family name (e.g.`virut`, `qsnatch`); `"benign"` for benign domains |

**Example rows:**

```
domain,label,family
google.com,0,benign
sbhya.com,1,virut
w0gv.gl,1,qsnatch
```

---

## Quick Start

### Usage

This repository exposes **two representations**, each split into **per-year configs** (`T17`–`T25`):

- **`T{YY}_eSLD`** — effective second-level domain only (TLD/ccTLD stripped). Benign + DGA are merged into ready-to-train `train` / `validation` / `test` splits; the `label` column distinguishes the class. This is the direct DRIFT model input.
- **`T{YY}_raw`** — raw domain (including TLD) plus the DGA `family` label. Provided as `benign` / `dga` splits for reference and custom preprocessing.

```python
from datasets import load_dataset

# eSLD model input — load one within-year partition of 2020 (benign + DGA, with label).
# NOTE: `split` here selects a packaged file partition, NOT a forward-chaining role —
# see the Recommended Evaluation Protocol below for how to assemble train/test by year.
drift_input = load_dataset("snsec-net/dga-detection-drift26dsn", "T20_eSLD", split="test")

# raw, with TLD + DGA family — e.g. 2017 DGA domains
raw = load_dataset("snsec-net/dga-detection-drift26dsn", "T17_raw", split="dga")
```

### Recommended Evaluation Protocol (Forward-Chaining)

DRIFT measures **temporal robustness**, so the train/test distinction is defined **by time, not by the split names.**

> **Important — what the `split` names mean.** Each yearly config ships `train` / `validation` / `test` splits, but these are just **within-year partitions of that one year's data** (an artifact of how the files were packaged); they are **not** conventional ML train/test roles. The forward-chaining role of any data is decided by **which year it belongs to** relative to your cutoff — so a *training* year's `test` partition is still training data, and a *test* year's `train` partition is still test data.

The protocol, stated temporally:

1. **Stand at a point in time** (in the paper, the end of 2019).
2. **Train** on **all data strictly before** that point (2017–2019), holding out a small slice per year for validation / early stopping.
3. **Freeze** the model, then **evaluate it year by year** on each later year (2020, 2021, …, 2025) — each year tested independently, so accuracy degradation reveals drift over time.

Mapping that onto the packaged splits (`full year = train + validation + test`):

| Forward-chaining role                                                                  | Years              | What to load                                                                |
| -------------------------------------------------------------------------------------- | ------------------ | --------------------------------------------------------------------------- |
| **Training data**                                                                | 2017–2019         | full year**minus** the val holdout → `train` + `test` partitions |
| **Validation** (early stopping / model selection — the one *real* ML val set) | 2017–2019         | the `validation` partition (150k benign + 150k DGA per year)              |
| **Test** (frozen model, scored per year)                                         | each of 2020–2025 | the**whole** year → `train` + `validation` + `test` partitions |

So **do not** read `split="train"` as "the training set" or `split="test"` as "the test set": for a training year you want `train`+`test` (the full year minus the val holdout), and for a later year you want the *entire* year. Using `split="train"`/`split="test"` literally would mix the temporal roles and silently drop most of the data — e.g. `split="train"` is capped at 1.5M/class, discarding the `test` partition that holds the bulk of each year (for 2017 DGA, **13.2M of 14.9M** domains live in `test`).

```python
from datasets import load_dataset, concatenate_datasets

REPO = "snsec-net/dga-detection-drift26dsn"
TRAIN_YEARS = ["17", "18", "19"]

# Training set: FULL 2017–2019 data minus the 150k/class held-out validation.
# full = train + validation + test  =>  full - validation = train + test
train = concatenate_datasets([
    load_dataset(REPO, f"T{y}_eSLD", split="train+test") for y in TRAIN_YEARS
])

# Held-out validation: 150k benign + 150k DGA per training year
val = concatenate_datasets([
    load_dataset(REPO, f"T{y}_eSLD", split="validation") for y in TRAIN_YEARS
])

# Test on a strictly-newer year — the FULL year (2020–2025 are never used for training)
test_2020 = load_dataset(REPO, "T20_eSLD", split="train+validation+test")
```

**Not running forward-chaining?** If you are not running a longitudinal (forward-chaining) evaluation — e.g. you are training and testing within a single year, or pooling several years together as one ordinary dataset — you can use the `train` / `validation` / `test` partitions at face value. The temporal caveat above applies only when a year's role is decided by its position relative to a cutoff.

---

## Citation

If you use this dataset, please cite:

**Dataset:**

```
C. Lee, C. Jung, and S. Jeong, "Longitudinal Benign and DGA Domain Name Dataset,"
IEEE DataPort, 2026. doi: 10.21227/za2s-9e09.
Available: https://dx.doi.org/10.21227/za2s-9e09
```

```bibtex
@misc{lee2026driftdata,
  author       = {Lee, Chaeyoung and Jung, Chaeri and Jeong, Seonghoon},
  title        = {Longitudinal Benign and {DGA} Domain Name Dataset},
  howpublished = {IEEE Dataport},
  year         = {2026},
  doi          = {10.21227/za2s-9e09},
  url          = {https://dx.doi.org/10.21227/za2s-9e09}
}
```

**Paper:**

```
C. Lee, C. Jung, and S. Jeong, "DRIFT: Drift-Resilient Invariant-Feature Transformer
for DGA Detection," in Proc. IEEE/IFIP DSN, 2026. [to be updated with DOI upon publication]
```

```bibtex
@inproceedings{lee2026drift,
  title     = {{DRIFT}: Drift-Resilient Invariant-Feature Transformer for {DGA} Detection},
  author    = {Lee, Chaeyoung and Jung, Chaeri and Jeong, Seonghoon},
  booktitle = {Proc. IEEE/IFIP International Conference on Dependable Systems and Networks (DSN)},
  year      = {2026}
}
```

---

## Intended Use & Ethical Considerations

This dataset is released **for cybersecurity research** — building and benchmarking DGA detectors, studying concept drift, and improving network defenses. It must **not** be used to operate, register, or distribute malicious domains. Use is restricted to **non-commercial research and personal use** per the license below.

---

## License

DGArchive is governed by the CC BY-NC-SA 3.0 license. Therefore, this dataset may not be used for commercial purposes, but is available for research or personal use. If this license does not meet your needs, we are open to individual licensing agreements.

https://creativecommons.org/licenses/by-nc-sa/3.0/

---

## References

[1] D. Plohmann, K. Yakdan, M. Klatt, J. Bader, and E. Gerhards-Padilla, "A comprehensive measurement study of domain generating malware," in *Proc. USENIX Security*, 2016.

[2] V. Le Pochat, T. Van Goethem, S. Tajalizadehkhoob, M. Korczynski, and W. Joosen, "Tranco: A research-oriented top sites ranking hardened against manipulation," in *Proc. NDSS*, 2019.
