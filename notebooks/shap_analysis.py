"""
SHAP Explainability Analysis
=============================
Explains XGBoost model predictions using SHAP values.
Generates:
  - Summary plot (top features globally)
  - Feature importance bar chart
  - Waterfall plot (single prediction explanation)
  - Force plot (single prediction)
  - Dependence plots (top 3 features)

Run: python notebooks/shap_analysis.py
"""

import os, sys, pickle, warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import shap
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

warnings.filterwarnings("ignore")

MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# ──────────────────────────────────────────────────────────────
# Load Model & Data
# ──────────────────────────────────────────────────────────────

print("=" * 60)
print("  SHAP Explainability Analysis")
print("=" * 60)

print("\n[1/6] Loading model artifacts...")
with open(MODEL_DIR / "nids_xgboost_7class.pkl", "rb") as f:
    model = pickle.load(f)
with open(MODEL_DIR / "scaler_7class.pkl", "rb") as f:
    scaler = pickle.load(f)
with open(MODEL_DIR / "label_encoder_7class.pkl", "rb") as f:
    encoder = pickle.load(f)
with open(MODEL_DIR / "feature_names_7class.pkl", "rb") as f:
    feature_names = pickle.load(f)

print(f"  Model: XGBoost ({len(feature_names)} features, {len(encoder.classes_)} classes)")
print(f"  Classes: {encoder.classes_.tolist()}")

# ──────────────────────────────────────────────────────────────
# Load Sample Test Data
# ──────────────────────────────────────────────────────────────

print("\n[2/6] Loading test data...")
from src.train_model import load_all_data, clean_data, map_labels, handle_missing, split_data, scale_data, encode_labels

DATA_DIR = Path("data")
DATA_FILES = sorted(DATA_DIR.glob("*_plus.csv"))

df = load_all_data(DATA_FILES)
df = clean_data(df)
df = map_labels(df)
df = handle_missing(df)
(X_train, y_train), (X_val, y_val), (X_test, y_test) = split_data(df)

# Sample for SHAP (SHAP is computationally expensive)
sample_size = min(2000, len(X_test))
X_sample = X_test.sample(n=sample_size, random_state=42)
y_sample = y_test.loc[X_sample.index]

X_sample_s = scaler.transform(X_sample)
y_sample_e = encoder.transform(y_sample)

print(f"  Test sample: {len(X_sample)} flows")

# ──────────────────────────────────────────────────────────────
# Create SHAP Explainer
# ──────────────────────────────────────────────────────────────

print("\n[3/6] Creating SHAP explainer...")
explainer = shap.TreeExplainer(model)
print(f"  Explainer type: TreeExplainer")

# Calculate SHAP values
print("  Calculating SHAP values (this may take 1-2 minutes)...")
shap_values = explainer.shap_values(X_sample_s)
print(f"  SHAP values shape: {np.array(shap_values).shape}")

# ──────────────────────────────────────────────────────────────
# Plot 1: Summary Plot (Global Feature Importance)
# ──────────────────────────────────────────────────────────────

print("\n[4/6] Generating SHAP summary plot...")
fig, ax = plt.subplots(figsize=(14, 10))
shap.summary_plot(shap_values, X_sample_s, feature_names=feature_names, 
                  class_names=encoder.classes_.tolist(), show=False, max_display=20)
plt.title('SHAP Summary Plot: Global Feature Importance Across All Classes', 
          fontsize=14, fontweight='bold', pad=20)
plt.tight_layout()
path = REPORT_DIR / "shap_summary.png"
plt.savefig(path, dpi=150, bbox_inches='tight')
plt.close()
print(f"  Saved: {path}")

# ──────────────────────────────────────────────────────────────
# Plot 2: Feature Importance Bar Chart
# ──────────────────────────────────────────────────────────────

print("\n[5/6] Generating SHAP bar charts per class...")
n_classes = len(encoder.classes_)
fig, axes = plt.subplots(2, 4, figsize=(20, 12))
axes = axes.flatten()

for i in range(n_classes):
    plt.sca(axes[i])
    if n_classes > 2:
        shap_values_i = shap_values[:, :, i]
    else:
        shap_values_i = shap_values
    shap.summary_plot(shap_values_i, 
                      X_sample_s, feature_names=feature_names, 
                      plot_type="bar", show=False, max_display=10)
    axes[i].set_title(f'Class: {encoder.classes_[i]}', fontsize=12, fontweight='bold')

# Hide extra subplots
for i in range(n_classes, 8):
    axes[i].set_visible(False)

plt.suptitle('SHAP Feature Importance by Attack Class', fontsize=16, fontweight='bold', y=1.01)
plt.tight_layout()
path = REPORT_DIR / "shap_importance_by_class.png"
plt.savefig(path, dpi=150, bbox_inches='tight')
plt.close()
print(f"  Saved: {path}")

# ──────────────────────────────────────────────────────────────
# Plot 3: Waterfall Plot (Single Prediction)
# ──────────────────────────────────────────────────────────────

print("\n[6/6] Generating single prediction explanation...")

# Find an attack sample (not Benign)
attack_idx = None
for i, y in enumerate(y_sample_e):
    if y != 0:  # 0 = Benign
        attack_idx = i
        break

if attack_idx is None:
    attack_idx = 0

# Generate waterfall for the detected attack class
predicted_class = model.predict(X_sample_s[attack_idx:attack_idx+1])[0]
class_name = encoder.classes_[predicted_class]

fig, ax = plt.subplots(figsize=(12, 8))
if n_classes > 2:
    shap.waterfall_plot(
        shap.Explanation(
            values=shap_values[predicted_class][attack_idx],
            base_values=explainer.expected_value[predicted_class],
            data=X_sample_s[attack_idx],
            feature_names=feature_names,
        ),
        show=False,
        max_display=15,
    )
else:
    shap.waterfall_plot(
        shap.Explanation(
            values=shap_values[attack_idx],
            base_values=explainer.expected_value,
            data=X_sample_s[attack_idx],
            feature_names=feature_names,
        ),
        show=False,
        max_display=15,
    )

plt.title(f'SHAP Waterfall: Why this flow was classified as "{class_name}"\n'
          f'Actual: {encoder.classes_[y_sample_e[attack_idx]]}',
          fontsize=13, fontweight='bold', pad=20)
plt.tight_layout()
path = REPORT_DIR / "shap_waterfall.png"
plt.savefig(path, dpi=150, bbox_inches='tight')
plt.close()
print(f"  Saved: {path}")

# ──────────────────────────────────────────────────────────────
# Plot 4: Top 3 Dependence Plots
# ──────────────────────────────────────────────────────────────

# Get global feature importance
if n_classes > 2:
    feature_importance = np.abs(shap_values[:, :, 0]).mean(axis=0)
else:
    feature_importance = np.abs(shap_values).mean(axis=0)
top_indices = np.argsort(feature_importance)[-3:][::-1]

fig, axes = plt.subplots(1, 3, figsize=(18, 5))

for i, feat_idx in enumerate(top_indices):
    plt.sca(axes[i])
    if n_classes > 2:
        shap.dependence_plot(feat_idx, shap_values[:, :, 0], X_sample_s, 
                            feature_names=feature_names, show=False, ax=axes[i])
    else:
        shap.dependence_plot(feat_idx, shap_values, X_sample_s,
                            feature_names=feature_names, show=False, ax=axes[i])
    axes[i].set_title(f'Top {i+1}: {feature_names[feat_idx]}', fontsize=11, fontweight='bold')

plt.suptitle('SHAP Dependence Plots: Top 3 Most Important Features', 
             fontsize=14, fontweight='bold', y=1.02)
plt.tight_layout()
path = REPORT_DIR / "shap_dependence.png"
plt.savefig(path, dpi=150, bbox_inches='tight')
plt.close()
print(f"  Saved: {path}")

# ──────────────────────────────────────────────────────────────
# Generate Insights Report
# ──────────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("  SHAP ANALYSIS COMPLETE")
print("=" * 60)

# Top features
top_features = []
for i in top_indices:
    top_features.append({
        "rank": len(top_features) + 1,
        "feature": feature_names[i],
        "importance": float(feature_importance[i]),
    })

print("\n  Top 3 Most Important Features:")
for f in top_features:
    print(f"    #{f['rank']}: {f['feature']} (importance: {f['importance']:.4f})")

print(f"\n  Waterfall plot explains classification of: {class_name}")
print(f"\n  All outputs saved to: {REPORT_DIR}/")
print("    - shap_summary.png")
print("    - shap_importance_by_class.png")
print("    - shap_waterfall.png")
print("    - shap_dependence.png")

# Save insights
with open(REPORT_DIR / "shap_insights.txt", "w") as f:
    f.write("SHAP Explainability Analysis\n")
    f.write("=" * 50 + "\n\n")
    f.write("Top 3 Features Driving Detection:\n")
    for feat in top_features:
        f.write(f"  #{feat['rank']}: {feat['feature']} (importance: {feat['importance']:.4f})\n")
    f.write(f"\nWaterfall plot demonstrates why a flow was classified as: {class_name}\n")
    f.write("\nThese SHAP values explain the model's decision-making process,\n")
    f.write("providing transparency for security analysts and auditors.\n")

print(f"  Saved: reports/shap_insights.txt")
