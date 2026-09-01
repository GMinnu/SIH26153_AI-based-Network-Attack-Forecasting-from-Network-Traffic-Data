# ThreatCast — AI-based Network Attack Forecasting

> Forecasting network attacks **before they fully unfold**, instead of only detecting them after they start.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![PyTorch](https://img.shields.io/badge/PyTorch-LSTM-red)
![Explainability](https://img.shields.io/badge/Explainability-SHAP-green)
![Runs](https://img.shields.io/badge/Runs-fully%20offline-lightgrey)
![SIH](https://img.shields.io/badge/Smart%20India%20Hackathon-2026-orange)

**Smart India Hackathon 2026 · Problem Statement `SIH26153`**
**Team:** Foresight · **Theme:** Blockchain & Cybersecurity · **Category:** Software

---

## 1. The problem

Most network security tools only **detect** an attack once it is already in progress — by then the damage has often begun. But attacks unfold in **stages** (reconnaissance → initial access → lateral movement → command-and-control → exfiltration). NTRO's problem statement asks for a system that **predicts** an attack a little before it fully happens, so defenders on Critical Information Infrastructure (power, telecom, banking, railways, government) get time to act.

## 2. What ThreatCast does

ThreatCast reads network traffic, groups it into short **time-windows**, and a temporal model (**LSTM**) reads the recent sequence to forecast:

- the **probability of an attack** in the next few windows,
- the likely **MITRE ATT&CK stage** it is heading toward, and
- a **SHAP explanation** — which flags/ports/flows drove each alert (no black box).

Everything runs **fully offline** (no cloud), on free public datasets, and is measured **honestly** against a simple logistic-regression baseline.

## 3. Results (real, leakage-free)

Measured on **CIC-IDS-2018 (Infiltration day, `02-28-2018.csv`)** with a leakage-free chronological split.

| Metric | Baseline (LogReg) | ThreatCast (LSTM) |
|---|---|---|
| PR-AUC @ 30s ahead | 0.76 | **0.89** (+0.13) |
| F1 (best threshold) | — | **0.69** |
| Forecast horizon | — | up to 120s (PR-AUC ~0.87) |

**Honest limitation:** at a usable operating point (~0.5% false-alarm target) we currently **miss ~47%** of attacks. We report the real number rather than a tuned-up one, and reducing it is an active next step (see Roadmap).

> **Why this is trustworthy:** we train on **earlier** traffic and test on **later** traffic, and the alert threshold is chosen on a **validation** split only — so the model can't "peek" into the future. This is the honest way to measure a time-series IDS.

## 4. How it works

```
Network traffic (flow CSV / PCAP)
        │
        ▼
Windowing (e.g. 10s windows)  ──►  Feature extraction (flow + packet level)
        │
        ▼
Temporal model (LSTM)  ──►  K-step forecast: P(attack) + MITRE stage
        │
        ├──►  Baseline (Logistic Regression, same features — fair comparison)
        │
        ▼
Explainability (SHAP: top driving features)  ──►  Offline Streamlit dashboard
```

Evaluation is **leakage-free**: earlier traffic trains, later traffic tests, threshold tuned on validation only.

## 5. Repository structure

> Adjust names to match your actual files.

```
.
├── data/                      # put the CIC-IDS-2018 day CSV here (not committed)
├── notebooks/
│   └── ThreatCast_baseline.ipynb   # baseline vs LSTM comparison
├── src/
│   ├── features.py            # windowing + flow/packet feature extraction
│   ├── model.py               # LSTM forecaster (PyTorch)
│   ├── baseline.py            # logistic-regression baseline (scikit-learn)
│   ├── evaluate.py            # leakage-free split, PR-AUC, F1, miss-rate
│   └── explain.py             # SHAP explanations
├── app/
│   └── app.py                 # Streamlit offline dashboard
├── requirements.txt
├── README.md
└── LICENSE
```

## 6. Getting started

### Prerequisites
- Python 3.10+
- A normal laptop (CPU is enough — no GPU/cloud required)

### Install
```bash
git clone https://github.com/GMinnu/SIH26153_AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data.git
cd SIH26153_AI-based-Network-Attack-Forecasting-from-Network-Traffic-Data

python -m venv venv
# Windows:  venv\Scripts\activate
# Linux/Mac: source venv/bin/activate

pip install -r requirements.txt
```

### Get the data
This repo does **not** ship the dataset (it's large). Download **CSE-CIC-IDS-2018** and place the Infiltration day file (`02-28-2018.csv`) in `data/`.

- Dataset: https://www.unb.ca/cic/datasets/ids-2018.html

### Run the notebook (reproduce the results)
```bash
jupyter notebook notebooks/ThreatCast_baseline.ipynb
```

### Run the offline dashboard
```bash
streamlit run app/app.py
```
Then open `http://localhost:8501`. In the sidebar set:

| Setting | Default |
|---|---|
| Path to CIC-IDS-2018 day CSV | `data/02-28-2018.csv` |
| Window seconds | `10` |
| History windows | `8` |
| Forecast ahead (windows) | `3`  (= 30s) |
| Operating false-alarm rate | `0.05` |

Click **Run forecast** to see the probability timeline, top-risk windows, and SHAP reasons.

### `requirements.txt` (suggested)
```
torch
scikit-learn
shap
streamlit
pandas
numpy
matplotlib
scapy        # optional, for packet-level features
pyshark      # optional, for PCAP parsing
```

## 7. Tech stack

| Layer | Tool | Why |
|---|---|---|
| Read traffic | Scapy / PyShark | flow CSV + PCAP |
| Temporal model | PyTorch **LSTM** | learns the time pattern |
| Baseline | scikit-learn (LogReg) | fair comparison |
| Explainability | **SHAP** | reason for every alert |
| Dashboard | **Streamlit** | offline, no cloud |
| Attack framework | **MITRE ATT&CK** | standard attack stages |

## 8. Roadmap / Next steps

Ordered by impact — this is what we are building toward the finale.

- [ ] **Lead-time metric (highest priority).** Report the **median seconds of early warning** before the labeled attack onset, at a fixed false-alarm rate, plus a **recall-vs-lead-time curve**. This is exactly what the problem statement means by "warn before it happens," and it turns the miss-rate into a mature, honest curve.
- [ ] **Packet-level features.** Add TTL variance, port-scan patterns, and retransmissions (the PS names these explicitly). Should also lower the miss rate on stealthy scans that flow-level thresholds miss.
- [ ] **Concrete MITRE ATT&CK stage output.** Map dataset labels to the 5 stages so the predicted stage is real, not just conceptual — giving a full "forecast + stage + reason + lead time" line per alert.
- [ ] **Second-dataset validation.** Run the same pipeline on a second attack type / day (e.g. a DoS or Brute-Force day) or **CTU-13**, to show it generalizes and isn't tuned to one file.
- [ ] **Lower the ~47% miss rate.** Via the new features above + threshold calibration.
- [ ] **Deliverables.** 2-page architecture document, demo video, and a cleaner packaged repo.
- [ ] **(Stretch) World-model upgrade.** Have the model predict the next window's feature vector and derive attack probability from the rollout — a defensible P(Sₜ₊₁ | Sₜ) "world model", matching the sponsor's own framing. Try a Transformer/GNN only after the above.

## 9. Current limitations (honest)

- Miss rate is ~47% at a usable operating point — improving via packet features + calibration.
- MITRE stage output is currently conceptual (mapping in progress).
- Validated on the CIC-IDS-2018 Infiltration day so far; broader validation is planned.
- Features are flow-level today; packet-level features are being added.

## 10. Regulatory relevance

Protecting Critical Information Infrastructure is the mandate of **NCIIPC**, which is a unit of **NTRO** — the sponsor of this problem statement (IT Act **§70A**). Early-warning + evidence also support **CERT-In** (MeitY, **§70B**) and the IT (Protected System) Rules, 2018. ThreatCast is designed to run offline in exactly these sensitive, air-gapped environments.

## 11. References

- CSE-CIC-IDS-2018 & CTU-13 — public network-traffic datasets
- MITRE ATT&CK — standard list of attack stages (attack.mitre.org)
- Ha & Schmidhuber, *World Models*, 2018
- Lundberg & Lee, *SHAP*, NeurIPS 2017
- Ding et al., ICSE 2025 — miss-rate at a capped false-alarm rate
- Gartner NDR Magic Quadrant 2025; Salt Typhoon telecom breaches (2024–25)

## 12. Team

**Foresight** — Smart India Hackathon 2026, Problem Statement `SIH26153`.

## 13. License

Released under the **MIT License** — see [`LICENSE`](LICENSE). (Change if your team prefers another open-source license.)

---

*ThreatCast runs fully offline on open-source tools and free public data — a made-in-India early-warning add-on for network defenders.*
