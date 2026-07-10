"""
evaluator.py — System Performance Evaluation Script

Computes Precision, Recall, F1, and ROC-AUC for the Isolation Forest model.
Compares against a traditional rule-based firewall baseline.
Generates charts suitable for FYP report inclusion.

Usage:
    python evaluator.py
Outputs:
    evaluation_report.txt
    charts/roc_curve.png
    charts/pr_curve.png
    charts/confusion_matrix.png
    charts/comparison_bar.png
"""

import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from datetime import datetime

from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, precision_recall_curve,
    confusion_matrix, ConfusionMatrixDisplay,
)

from anomaly_detector_engine import (
    AnomalyDetectorEngine,
    FEATURE_COLS,
    _generate_normal_samples,
)

os.makedirs("charts", exist_ok=True)

# ── Synthetic Labelled Test Dataset ──────────────────────────────────────────
ANOMALY_RATIO = 0.15
N_TEST        = 1000


def _generate_attack_samples_eval(n: int = 150) -> np.ndarray:
    """
    Synthetic attacker patterns that match the three FEATURE_COLS:
      [total_requests, failed_status_rate, payload_size_variance]
    """
    rng     = np.random.default_rng(99)
    samples = []
    for _ in range(n):
        attack_type = rng.integers(0, 3)
        if attack_type == 0:
            # DDoS: very high request volume
            samples.append([
                rng.integers(200, 500),
                rng.uniform(0.0, 0.15),
                rng.uniform(0, 300_000),
            ])
        elif attack_type == 1:
            # Brute force: high failure rate
            samples.append([
                rng.integers(30, 120),
                rng.uniform(0.6, 1.0),
                rng.uniform(0, 80_000),
            ])
        else:
            # Fuzzing / exfiltration: extreme payload variance
            samples.append([
                rng.integers(5, 60),
                rng.uniform(0.0, 0.2),
                rng.uniform(5e9, 1e11),
            ])
    return np.array(samples, dtype=np.float64)


def build_test_set():
    n_normal = N_TEST - int(N_TEST * ANOMALY_RATIO)
    n_attack = N_TEST - n_normal

    X_normal = _generate_normal_samples(n_normal)
    X_attack = _generate_attack_samples_eval(n_attack)

    X = np.vstack([X_normal, X_attack])
    y = np.array([0] * n_normal + [1] * n_attack)

    idx = np.random.default_rng(7).permutation(len(y))
    return X[idx], y[idx]


# ── Rule-Based Baseline (uses same FEATURE_COLS) ──────────────────────────────

def rule_based_predict(X: np.ndarray) -> np.ndarray:
    """
    Simple static threshold rules (simulates a traditional WAF).
    Column indices are derived from FEATURE_COLS so they always stay aligned:
      total_requests, failed_status_rate, payload_size_variance
    """
    col = {name: i for i, name in enumerate(FEATURE_COLS)}

    preds = (
        (X[:, col["total_requests"]]       >= 60)  |
        (X[:, col["failed_status_rate"]]   >= 0.5) |
        (X[:, col["payload_size_variance"]] >= 1e10)
    ).astype(int)
    return preds


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate():
    print("=" * 56)
    print("  ACS Sentinel — Performance Evaluator")
    print("=" * 56)

    engine      = AnomalyDetectorEngine()
    X_test, y_true = build_test_set()
    X_scaled    = engine.scaler.transform(X_test)

    # ML predictions
    scores_raw  = engine.model.decision_function(X_scaled)
    threshold   = -0.15
    y_ml        = (scores_raw < threshold).astype(int)
    y_scores    = -scores_raw   # invert so higher = more anomalous

    # Rule-based baseline
    y_rules     = rule_based_predict(X_test)

    def metrics(y_pred, label):
        p   = precision_score(y_true, y_pred, zero_division=0)
        r   = recall_score(y_true,    y_pred, zero_division=0)
        f1  = f1_score(y_true,        y_pred, zero_division=0)
        try:
            auc = roc_auc_score(y_true, y_pred)
        except Exception:
            auc = float("nan")
        print(f"\n  [{label}]")
        print(f"    Precision : {p:.4f}  ({p*100:.1f}%)")
        print(f"    Recall    : {r:.4f}  ({r*100:.1f}%)")
        print(f"    F1-Score  : {f1:.4f}")
        print(f"    ROC-AUC   : {auc:.4f}")
        return {"label": label, "Precision": p, "Recall": r, "F1": f1, "ROC-AUC": auc}

    results_ml    = metrics(y_ml,    "Isolation Forest (ML)")
    results_rules = metrics(y_rules, "Rule-Based Firewall (Baseline)")

    plot_roc_curve(y_true, y_scores, y_rules)
    plot_pr_curve(y_true, y_scores)
    plot_confusion_matrix(y_true, y_ml, y_rules)
    plot_comparison_bar([results_ml, results_rules])
    write_report(results_ml, results_rules, y_true, y_ml, y_rules)

    print("\n  Evaluation complete.")
    print("     Charts : charts/")
    print("     Report : evaluation_report.txt")


# ── Plot Helpers ──────────────────────────────────────────────────────────────

COLORS = {"ml": "#1a56db", "rule": "#f59e0b"}


def plot_roc_curve(y_true, y_scores_ml, y_pred_rules):
    fpr_ml, tpr_ml, _  = roc_curve(y_true, y_scores_ml)
    auc_ml              = roc_auc_score(y_true, y_scores_ml)
    fpr_r,  tpr_r,  _  = roc_curve(y_true, y_pred_rules)
    auc_r               = roc_auc_score(y_true, y_pred_rules)

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(fpr_ml, tpr_ml, color=COLORS["ml"],   lw=2, label=f"Isolation Forest (AUC={auc_ml:.3f})")
    ax.plot(fpr_r,  tpr_r,  color=COLORS["rule"],  lw=2, label=f"Rule-Based (AUC={auc_r:.3f})", linestyle="--")
    ax.plot([0, 1], [0, 1], color="#94a3b8", linestyle=":", lw=1)
    ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve: ML vs Rule-Based"); ax.legend(); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig("charts/roc_curve.png", dpi=150); plt.close(fig)
    print("  ROC curve saved.")


def plot_pr_curve(y_true, y_scores_ml):
    prec, rec, _ = precision_recall_curve(y_true, y_scores_ml)
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(rec, prec, color=COLORS["ml"], lw=2)
    ax.fill_between(rec, prec, alpha=0.1, color=COLORS["ml"])
    ax.set_xlabel("Recall"); ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve: Isolation Forest")
    ax.grid(alpha=0.3); fig.tight_layout(); fig.savefig("charts/pr_curve.png", dpi=150); plt.close(fig)
    print("  PR curve saved.")


def plot_confusion_matrix(y_true, y_ml, y_rules):
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for ax, y_pred, title in zip(axes, [y_ml, y_rules], ["Isolation Forest", "Rule-Based Firewall"]):
        cm   = confusion_matrix(y_true, y_pred)
        disp = ConfusionMatrixDisplay(cm, display_labels=["Normal", "Anomaly"])
        disp.plot(ax=ax, colorbar=False, cmap="Blues")
        ax.set_title(title)
    fig.tight_layout(); fig.savefig("charts/confusion_matrix.png", dpi=150); plt.close(fig)
    print("  Confusion matrix saved.")


def plot_comparison_bar(results: list):
    metrics_keys = ["Precision", "Recall", "F1", "ROC-AUC"]
    x     = np.arange(len(metrics_keys))
    width = 0.35

    fig, ax   = plt.subplots(figsize=(9, 5))
    vals_ml   = [results[0][k] for k in metrics_keys]
    vals_rule = [results[1][k] for k in metrics_keys]

    bars1 = ax.bar(x - width/2, vals_ml,   width, label="Isolation Forest", color=COLORS["ml"],  alpha=.85)
    bars2 = ax.bar(x + width/2, vals_rule, width, label="Rule-Based",       color=COLORS["rule"], alpha=.85)

    ax.set_ylabel("Score")
    ax.set_title("ML vs Rule-Based: Performance Comparison")
    ax.set_xticks(x); ax.set_xticklabels(metrics_keys); ax.set_ylim(0, 1.15)
    ax.legend(); ax.grid(axis="y", alpha=0.3)

    for bar in list(bars1) + list(bars2):
        h = bar.get_height()
        ax.annotate(f"{h:.2f}", xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8)

    fig.tight_layout(); fig.savefig("charts/comparison_bar.png", dpi=150); plt.close(fig)
    print("  Comparison bar chart saved.")


# ── Text Report ───────────────────────────────────────────────────────────────

def write_report(ml: dict, rules: dict, y_true, y_ml, y_rules):
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cm_ml    = confusion_matrix(y_true, y_ml)
    cm_rules = confusion_matrix(y_true, y_rules)

    lines = [
        "=" * 56,
        "  ACS Sentinel: Evaluation Report",
        f"  Generated : {ts}",
        "=" * 56,
        "",
        "  Test Set Composition:",
        f"    Total samples  : {len(y_true)}",
        f"    Normal  (0)    : {(y_true == 0).sum()}",
        f"    Anomaly (1)    : {(y_true == 1).sum()}",
        "",
        "  Isolation Forest (ML)",
        f"    Precision : {ml['Precision']:.4f}",
        f"    Recall    : {ml['Recall']:.4f}",
        f"    F1-Score  : {ml['F1']:.4f}",
        f"    ROC-AUC   : {ml['ROC-AUC']:.4f}",
        f"    TN={cm_ml[0,0]}  FP={cm_ml[0,1]}  FN={cm_ml[1,0]}  TP={cm_ml[1,1]}",
        "",
        "  Rule-Based Firewall (Baseline)",
        f"    Precision : {rules['Precision']:.4f}",
        f"    Recall    : {rules['Recall']:.4f}",
        f"    F1-Score  : {rules['F1']:.4f}",
        f"    ROC-AUC   : {rules['ROC-AUC']:.4f}",
        f"    TN={cm_rules[0,0]}  FP={cm_rules[0,1]}  FN={cm_rules[1,0]}  TP={cm_rules[1,1]}",
        "",
        "  Delta (ML minus Baseline)",
        f"    Precision : {ml['Precision'] - rules['Precision']:+.4f}",
        f"    Recall    : {ml['Recall']    - rules['Recall']   :+.4f}",
        f"    F1        : {ml['F1']        - rules['F1']       :+.4f}",
        f"    ROC-AUC   : {ml['ROC-AUC']  - rules['ROC-AUC']  :+.4f}",
        "",
        "  Charts: charts/roc_curve.png | pr_curve.png",
        "          confusion_matrix.png | comparison_bar.png",
        "=" * 56,
    ]
    report = "\n".join(lines)
    print("\n" + report)
    with open("evaluation_report.txt", "w") as f:
        f.write(report)


if __name__ == "__main__":
    evaluate()
