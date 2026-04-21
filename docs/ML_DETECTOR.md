# ML Anomaly Detector — Design & Working

This document describes the unsupervised machine-learning detector added to the
NIDS pipeline. It explains *what* it does, *why* IsolationForest was chosen,
*how* it plugs into the existing architecture, and *how* to train, deploy, and
operate it.

---

## 1. Why ML at all?

Rate-based and YARA-based detectors catch **known** attack shapes — thresholds
on port counts, signatures for known payloads. They are blind to anything that
does not look exactly like a rule they carry. An unsupervised anomaly detector
fills that gap: it learns what *normal* traffic on this network looks like, and
flags packets that deviate from that baseline. No attack labels are required at
training time — only a short window of "known-good" traffic.

Design goals for this V1:

| Goal                                | How we meet it                                           |
| ----------------------------------- | -------------------------------------------------------- |
| Run on a laptop (i5 / 8 GB)         | IsolationForest — small, fast, O(log n) inference        |
| Train in minutes on local capture   | 10–30 min of browsing traffic is enough                  |
| No ground-truth labels required     | Unsupervised: model learns from benign traffic only      |
| Degrade gracefully under load       | Hooks into the existing `DegradationController`          |
| Don't crash the pipeline if missing | Missing model file → detector disables itself, logs warn |
| Composable with other detectors     | Emits the same `SignalEvent` shape → correlator handles it |

A supervised classifier (RandomForest / NSL-KDD) is **deliberately deferred**
until a flow-level aggregator exists. That will live alongside this detector,
not replace it.

---

## 2. Why IsolationForest?

IsolationForest is an ensemble of random "isolation" trees. Each tree
recursively splits the feature space along random features at random
thresholds. Anomalous points are isolated in *fewer* splits than normal points,
because they sit in sparse regions of the distribution.

For each packet we get a continuous **anomaly score** via
`model.score_samples(X)`:

- Higher (closer to 0)  → more normal
- Lower (more negative) → more anomalous

Properties we care about:

- **Unsupervised** — we don't need labeled attacks.
- **Robust to high-dimensional noise** — handles our 10 heterogenous features
  without heavy preprocessing.
- **Fast** — single-packet inference is sub-millisecond with 100 trees.
- **Small memory footprint** — fits the "lite" runtime profile.
- **Deterministic** — `random_state=42`, so two machines training on the same
  capture get the same model.

---

## 3. Where it sits in the pipeline

```
           ┌───────────────┐
  NIC ───▶ │ ScapyCapture  │  ── PacketEvent ──┐
           └───────────────┘                   │
                                               ▼
                                    ┌──────────────────────┐
                                    │  NIDSPipeline        │
                                    │  _process_packet()   │
                                    └──────────┬───────────┘
                                               │
                ┌──────────────┬────────────────┼────────────────┐
                ▼              ▼                ▼                ▼
          RateDetector    YaraDetector    **MLDetector**    (future)
                │              │                │
                └─────┬────────┴─────┬──────────┘
                      ▼              ▼
                     Signals → AlertCorrelator → AlertEvent → DB / WS
```

All three detectors emit the same `SignalEvent` dataclass
(`nids/core/schemas.py`). The `AlertCorrelator` composes them — when rate + ML
both fire on the same `src_ip`, the composite alert score is the sum of their
`score_contribution` values weighted by `CorrelatorConfig.score_weights["ml"]`
(default **45**, between `rate=30` and `yara=50`).

The ML detector is gated by `DegradationController.is_enabled(Feature.ML_ANOMALY)`.
Under CPU / memory / queue pressure the controller disables features in order
`ML_ANOMALY → REPUTATION → YARA`, so ML is the **first** thing to shed. This
matches the "keep rate detection alive at all costs" invariant of the lite
profile.

---

## 4. The model

### 4.1 Features (10 per packet)

Computed by `extract_features()` in `nids/detectors/ml_engine.py`. All
packet-level; **no flow state is required** in V1. The fixed feature order
(`FEATURE_NAMES`) is the contract between training and inference — **do not
reorder without retraining**.

| # | Name                 | Meaning                                                    |
| - | -------------------- | ---------------------------------------------------------- |
| 0 | `size`               | Total packet size in bytes                                 |
| 1 | `proto_code`         | TCP=1, UDP=2, ICMP=3, other=0                              |
| 2 | `dst_port`           | Destination port (0–65535)                                 |
| 3 | `src_port_ephemeral` | 1 if `src_port >= 49152`, else 0                           |
| 4 | `tcp_flags_bitmap`   | Bitmap of FIN/SYN/RST/PSH/ACK/URG/ECE/CWR flags            |
| 5 | `is_syn`             | 1 if SYN without ACK (connection attempts)                 |
| 6 | `is_ack`             | 1 if ACK set                                               |
| 7 | `is_private_src`     | 1 if `src_ip` is RFC1918 / loopback / link-local           |
| 8 | `hour_of_day`        | Local hour (0–23) — time-of-day encodes usage rhythm       |
| 9 | `payload_len`        | Bytes in `payload_preview` (capped at 256 by the capturer) |

**Why these?** They capture the three axes attacks most often perturb:
*volume* (size, payload_len), *topology* (ports, private/public, proto), and
*protocol state* (flags, SYN/ACK patterns). `hour_of_day` lets the model learn
"this network is quiet at 3 AM" — 3 AM bursts become anomalous even if each
packet looks individually normal.

**What's intentionally absent?** Flow-level aggregates (packets-per-flow,
bytes-per-flow, inter-arrival times). Those require the flow aggregator
(Module 2 in the architecture), which is not built yet. When it lands the
feature vector can be extended and a new model version shipped — bump
`model_version` in the signal metadata to distinguish them.

### 4.2 Training

```python
IsolationForest(
    n_estimators=100,
    contamination=0.01,   # assume ~1% of the baseline is still "weird"
    random_state=42,
    n_jobs=-1,
)
```

- `n_estimators=100` — standard; diminishing returns beyond this.
- `contamination=0.01` — even a "clean" baseline has 1% oddballs (DNS glitches,
  software updates, keepalives). Setting this too low biases the model toward
  *everything* looking normal; too high and benign traffic gets flagged.
- `random_state=42` — reproducibility.

Training is driven by `nids/detectors/ml_train.py`:

```bash
# Option A — offline pcap
python -m nids.detectors.ml_train --pcap baseline.pcap --out models/iforest.pkl

# Option B — live capture (recommended for first deployment)
python -m nids.detectors.ml_train --live --duration 600 \
    --iface wlan0 --out models/iforest.pkl
```

Both paths apply the **same** `extract_features()` used at inference — no
train/serve skew. Output is a joblib pickle plus a sidecar
`iforest.pkl.meta.json` recording `trained_at`, `packet_count`,
`feature_names`, `contamination`, `model_version`. Keep the sidecar next to the
model for later drift analysis.

### 4.3 Inference & scoring

Per packet, in the hot loop:

```
features = extract_features(packet)        # list[float], length 10
score    = model.score_samples([features])[0]
```

Score → severity mapping (`MLDetector._grade`):

| Score range                                 | Severity  | `score_contribution` |
| ------------------------------------------- | --------- | -------------------- |
| `score <= high_threshold` (default −0.25)   | `high`    | 8                    |
| `−0.25 < score <= medium_threshold (−0.10)` | `medium`  | 5                    |
| otherwise                                   | *no signal* | — |

Thresholds are configurable via `.env`:

```
ML__HIGH_THRESHOLD=-0.25
ML__MEDIUM_THRESHOLD=-0.10
```

Tune them by running the detector in shadow mode (see §7) and observing the
score distribution.

### 4.4 Cooldown / dedupe

A single anomalous source IP can generate hundreds of packets per second.
Without rate-limiting the detector would spam signals and DoS the correlator.
`MLDetector._in_cooldown()` keeps a per-source-IP timestamp of the last
emission and suppresses re-emits within `ML__COOLDOWN_SEC` (default 60s).
This mirrors the `(rule_id, src_ip)` cooldown used by `RateDetector`.

### 4.5 SignalEvent emitted

```python
SignalEvent(
    source="ml",
    rule_id="ML-IFOREST-ANOMALY",
    severity="high" | "medium",
    score_contribution=8 | 5,
    metadata={
        "anomaly_score": -0.31,
        "model_version": "iforest-v1",
        "features": {"size": 1500.0, "proto_code": 1.0, ...},
    },
)
```

The raw features are preserved so a human triaging an alert can see *why* the
model flagged it.

---

## 5. Startup & failure behaviour

```
RUNTIME__ENABLE_ML=true
 └─ pipeline builds MLDetector(ml_cfg)
     └─ ml_detector.initialize()
         ├─ model file exists → joblib.load → _initialized=True
         │     └─ DegradationController.set_override(ML_ANOMALY, True)
         └─ model file missing → log warning, return False
               └─ pipeline sets self.ml_detector = None; capture keeps running
```

Delete `models/iforest.pkl` and restart — the pipeline **must** start cleanly
with ML silently disabled. This is covered by
`tests/test_ml_engine.py::test_missing_model_disables_detector`.

---

## 6. Operational playbook

### 6.1 First-time enablement

1. `pip install -r requirements.txt`   (pulls scikit-learn, joblib, numpy).
2. Train on 10–30 minutes of typical-day traffic:
   ```
   python -m nids.detectors.ml_train --live --duration 1800 \
       --iface wlan0 --out models/iforest.pkl
   ```
3. In `.env` set `RUNTIME__ENABLE_ML=true` (already the case in the shipped
   template).
4. `python main.py`.
5. Generate a known-anomalous event from another host, e.g.
   `nmap -sS <nids-host>`. You should see ML signals alongside rate signals
   and a higher composite alert score than rate alone.

### 6.2 Tuning thresholds

- **Too many medium alerts** — raise `ML__MEDIUM_THRESHOLD` toward `−0.05`.
- **Missing obvious attacks** — lower `ML__HIGH_THRESHOLD` toward `−0.20`.
- Always retune after retraining on a new baseline.

### 6.3 Retraining

Retrain whenever the network's normal behaviour shifts meaningfully — new
services, new offices, new upstream, seasonal traffic change. The sidecar
`meta.json` stores the previous training timestamp; a monthly retrain cadence
is a reasonable starting point.

### 6.4 Degradation & shedding

Under sustained CPU > 80% / memory > 85% / queue > 800 / drops > 100 the
`DegradationController` disables ML first. While disabled the detector is
skipped in the hot loop but the model stays resident. The controller
re-enables it once metrics recover.

---

## 7. Verification checklist

| # | Check                                                                 |
| - | --------------------------------------------------------------------- |
| 1 | `pytest tests/test_ml_engine.py` — 5/5 green                          |
| 2 | `python -c "from nids.pipeline import NIDSPipeline"` imports cleanly  |
| 3 | With `ENABLE_ML=false`, pipeline logs "ML detector disabled"          |
| 4 | With `ENABLE_ML=true` but no model file, pipeline logs warning & runs |
| 5 | `nmap -sS` from another host produces a signal with `source="ml"`    |
| 6 | Composite alert score > score from rate detector alone                |
| 7 | Deleting model + restart — no crash, ML auto-disabled                 |

---

## 8. File map

| File                                   | Purpose                                       |
| -------------------------------------- | --------------------------------------------- |
| `nids/detectors/ml_engine.py`          | `MLDetector`, `extract_features`, scoring     |
| `nids/detectors/ml_train.py`           | CLI training tool (pcap / live)               |
| `nids/core/config.py`                  | `MLDetectorConfig`, correlator weight for ML  |
| `nids/pipeline.py`                     | Instantiation + hot-loop wiring + gate        |
| `nids/core/degradation.py`             | `Feature.ML_ANOMALY` gate                     |
| `tests/test_ml_engine.py`              | Unit + cooldown + missing-model tests         |
| `.env`                                 | `ML__*` knobs + `RUNTIME__ENABLE_ML`          |

---

## 9. Limitations (honest list)

- **Packet-level features only.** A single benign-looking packet inside a
  malicious flow will slip through. Flow aggregator is the fix.
- **No drift detection.** If your network pattern shifts, stale model =
  false-positive flood. Mitigation: retrain on a schedule; monitor
  `ml.signals_emitted / ml.inferences` ratio — a sustained jump means the
  baseline drifted.
- **Threshold tuning is manual.** We do not auto-calibrate thresholds from a
  validation set. A later iteration can sweep thresholds against a held-out
  capture to target a false-positive budget.
- **No explainability beyond raw features.** The `metadata.features` dict lets
  humans eyeball which feature is weird, but there is no per-feature
  attribution (SHAP etc.). Acceptable for V1, addressable later.
- **No adversarial robustness.** An attacker who knows the feature set can
  craft traffic that stays inside the learned manifold. Defence-in-depth
  (YARA, rate, reputation) is the answer — ML is one signal, never the only
  one.
