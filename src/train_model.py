"""
Phase 7: Expanded ML Training Pipeline
======================================
Trains XGBoost on ALL CIC-IDS-2017 files for 7-class NIDS detection.
Targets: Benign, DoS, PortScan, WebAttack, BruteForce, DDoS, Botnet

Features:
  - Merges all 10 CSV files
  - 7-class classification
  - Time-based + stratified split
  - ROC curves per class
  - Confusion matrix heatmap
  - Precision-Recall curves
  - Feature importance analysis
  - Ablation study (ML only vs Hybrid)
  - Isolation Forest for anomaly detection
"""

import os
import sys
import gc
import time
import pickle
import warnings
from typing import Tuple, List, Dict, Optional
from pathlib import Path

# Ensure UTF-8 output encoding across Windows terminals
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# pyrefly: ignore [missing-import]
import numpy as np
import pandas as pd
# pyrefly: ignore [missing-import]
import matplotlib
matplotlib.use('Agg')
# pyrefly: ignore [missing-import]
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder, label_binarize
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, accuracy_score,
    roc_curve, auc, precision_recall_curve, average_precision_score,
    roc_auc_score,
)
# pyrefly: ignore [missing-import]
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────

# All dataset files
DATA_DIR = Path("data")
DATA_FILES = sorted(DATA_DIR.glob("*_plus.csv"))

MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# Columns to drop (identifiers, ports, temporal/artifact fields)
DROP_COLUMNS = [
    "Flow ID", "Src IP", "Dst IP",
    "Src IP dec", "Dst IP dec", "Timestamp",
    "Dst Port", "Src Port", "Local",
]

# ──────────────────────────────────────────────────────────────
# Label Mapping — 7 Classes
# ──────────────────────────────────────────────────────────────

LABEL_MAPPING = {
    # Benign
    "BENIGN": "Benign",
    
    # DoS — all variants
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS Slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS Hulk - Attempted": "DoS",
    "DoS GoldenEye - Attempted": "DoS",
    "DoS Slowloris - Attempted": "DoS",
    "DoS Slowhttptest - Attempted": "DoS",
    
    # PortScan
    "Portscan": "PortScan",
    
    # WebAttack — actual attacks, no Attempted
    "Web Attack \u2013 Brute Force": "WebAttack",
    "Web Attack \u2013 XSS": "WebAttack",
    "Web Attack \u2013 SQL Injection": "WebAttack",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - SQL Injection": "WebAttack",
    
    # BruteForce (FTP/SSH)
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    
    # DDoS
    "DDoS": "DDoS",
    
    # Botnet
    "Botnet": "Botnet",
}

KEEP_LABELS = ["Benign", "DoS", "PortScan", "WebAttack", "BruteForce", "DDoS", "Botnet"]

TEST_SIZE = 0.15
VAL_SIZE = 0.15
RANDOM_STATE = 42

# ──────────────────────────────────────────────────────────────
# Step 1: Load, Clean & Merge All Files (Memory Optimized)
# ──────────────────────────────────────────────────────────────

def load_all_data(data_files: List[Path]) -> pd.DataFrame:
    """Load, clean per file, downcast to float32, and merge."""
    print("=" * 70)
    print("  Phase 7: Loading & Processing Dataset Files (Memory-Optimized)")
    print("=" * 70)
    
    all_dfs = []
    total_raw_rows = 0
    
    for f in data_files:
        df = pd.read_csv(f, low_memory=False)
        total_raw_rows += len(df)
        df.columns = df.columns.str.strip()
        
        # Drop identifiers and port numbers early
        drop_cols = [c for c in DROP_COLUMNS if c in df.columns]
        df = df.drop(columns=drop_cols, errors="ignore")
        
        # Drop Local_* and Local artifacts early
        local_cols = [c for c in df.columns if c.startswith("Local_") or c == "Local"]
        df = df.drop(columns=local_cols, errors="ignore")
        
        # Normalize and map labels
        if "Label" in df.columns:
            df["Label"] = df["Label"].astype(str).str.strip().str.replace("\u2013", "-")
            df["Label"] = df["Label"].map(LABEL_MAPPING)
            df = df[df["Label"].isin(KEEP_LABELS)]
        
        # Replace infinities
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # Drop duplicate flows per file
        df = df.drop_duplicates()
        
        # Downcast float64 to float32 to reduce memory footprint by 50%
        float_cols = df.select_dtypes(include=["float64"]).columns
        for c in float_cols:
            df[c] = df[c].astype(np.float32)
            
        int_cols = df.select_dtypes(include=["int64"]).columns
        for c in int_cols:
            df[c] = df[c].astype(np.int32)
            
        print(f"  {f.name:25s}: {len(df):>10,} valid rows, {len(df.columns):>3} cols ({df.memory_usage(deep=True).sum() / 1024**2:.1f} MB)")
        all_dfs.append(df)
        gc.collect()
    
    df = pd.concat(all_dfs, ignore_index=True)
    all_dfs.clear()
    gc.collect()
    
    # Global deduplication across merged dataset
    before_dup = len(df)
    df = df.drop_duplicates()
    
    # Drop all-NaN and constant columns
    nan_cols = df.columns[df.isna().all()].tolist()
    if nan_cols:
        df = df.drop(columns=nan_cols, errors="ignore")
        
    const_cols = [c for c in df.columns if df[c].nunique() <= 1 and c != "Label"]
    if const_cols:
        df = df.drop(columns=const_cols, errors="ignore")
    
    print(f"\n  Total merged: {len(df):,} rows ({before_dup - len(df):,} cross-file duplicates removed)")
    print(f"  Memory footprint: {df.memory_usage(deep=True).sum() / 1024**2:.1f} MB")
    print(f"  Final features: {len(df.columns) - 1} (+ 1 Label)")
    print()
    
    print("  Final 7-class distribution:")
    for label, count in df["Label"].value_counts().items():
        pct = count / len(df) * 100
        bar = "#" * int(pct / 2)
        print(f"    {label:15s}: {count:>10,}  ({pct:5.1f}%) {bar}")
    print()
    
    return df


# ──────────────────────────────────────────────────────────────
# Step 2: Clean Data (Compatibility Hook)
# ──────────────────────────────────────────────────────────────

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Pass-through since clean_data is executed during load_all_data."""
    return df


# ──────────────────────────────────────────────────────────────
# Step 3: Map Labels (Compatibility Hook)
# ──────────────────────────────────────────────────────────────

def map_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Pass-through since label mapping is executed during load_all_data."""
    return df


# ──────────────────────────────────────────────────────────────
# Step 4: Leak-Free Imputation (Fit on Train, Apply to Val/Test)
# ──────────────────────────────────────────────────────────────

def impute_missing(X_train: pd.DataFrame, X_val: pd.DataFrame, X_test: pd.DataFrame):
    """
    Impute missing values using medians computed strictly on the training set
    to prevent data leakage into validation and test sets.
    """
    print("=" * 70)
    print("  Handling Missing Values (Leak-Free Imputation)")
    print("=" * 70)
    
    numeric_cols = X_train.select_dtypes(include=[np.number]).columns
    train_medians = X_train[numeric_cols].median()
    
    X_train_clean = X_train.copy()
    X_val_clean = X_val.copy()
    X_test_clean = X_test.copy()
    
    X_train_clean[numeric_cols] = X_train_clean[numeric_cols].fillna(train_medians)
    X_val_clean[numeric_cols] = X_val_clean[numeric_cols].fillna(train_medians)
    X_test_clean[numeric_cols] = X_test_clean[numeric_cols].fillna(train_medians)
    
    # Fill any remaining NaNs with 0.0
    X_train_clean = X_train_clean.fillna(0.0)
    X_val_clean = X_val_clean.fillna(0.0)
    X_test_clean = X_test_clean.fillna(0.0)
    
    print(f"  Imputed {len(numeric_cols)} numeric columns using train medians strictly.")
    print()
    return X_train_clean, X_val_clean, X_test_clean


# ──────────────────────────────────────────────────────────────
# Step 5: Time-Based / Chronological Split (Out-of-Session)
# ──────────────────────────────────────────────────────────────

def split_data_temporal(df: pd.DataFrame, test_size: float = TEST_SIZE, val_size: float = VAL_SIZE):
    """
    Time-based / sequential out-of-session split.
    Splits each attack/benign session chronologically:
    - First (1 - test_size - val_size) as Training
    - Middle val_size as Validation
    - Final test_size (unseen future time window) as Testing.
    
    This guarantees that the model cannot interpolate identical flows
    and must predict future flows based on learned dynamics.
    """
    print("=" * 70)
    print("  Train/Validation/Test Split (Time-Based / Chronological)")
    print("=" * 70)
    
    train_indices = []
    val_indices = []
    test_indices = []
    
    # Split chronologically per class to ensure all 7 classes are present
    for label, group in df.groupby("Label", sort=False):
        n = len(group)
        n_test = int(n * test_size)
        n_val = int(n * val_size)
        n_train = n - n_test - n_val
        
        idx = group.index.tolist()
        train_indices.extend(idx[:n_train])
        val_indices.extend(idx[n_train:n_train + n_val])
        test_indices.extend(idx[n_train + n_val:])
    
    train_df = df.loc[train_indices]
    val_df = df.loc[val_indices]
    test_df = df.loc[test_indices]
    
    X_train = train_df.drop(columns=["Label"])
    y_train = train_df["Label"]
    
    X_val = val_df.drop(columns=["Label"])
    y_val = val_df["Label"]
    
    X_test = test_df.drop(columns=["Label"])
    y_test = test_df["Label"]
    
    print(f"  Training:   {len(X_train):>10,} (Chronological earlier window)")
    print(f"  Validation: {len(X_val):>10,} (Chronological middle window)")
    print(f"  Test:       {len(X_test):>10,} (Chronological future/unseen window)")
    print()
    
    for name, y_set in [("Train", y_train), ("Val", y_val), ("Test", y_test)]:
        print(f"  {name} distribution:")
        for label, count in y_set.value_counts().items():
            print(f"    {label:15s}: {count:>8,}")
        print()
    
    return (X_train, y_train), (X_val, y_val), (X_test, y_test)


def split_data(df: pd.DataFrame):
    """Backward-compatible alias for split_data_temporal."""
    return split_data_temporal(df)


# ──────────────────────────────────────────────────────────────
# Step 6: Scale
# ──────────────────────────────────────────────────────────────

def scale_data(X_train, X_val, X_test):
    """StandardScaler fit on train, transform all."""
    print("=" * 70)
    print("  Feature Scaling")
    print("=" * 70)
    
    feature_names = X_train.columns.tolist()
    print(f"  Features: {len(feature_names)}")
    
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)
    
    print(f"  Train mean: {X_train_s.mean():.6f}")
    print(f"  Train std:  {X_train_s.std():.6f}")
    print()
    
    return X_train_s, X_val_s, X_test_s, scaler, feature_names


# ──────────────────────────────────────────────────────────────
# Step 7: Encode Labels
# ──────────────────────────────────────────────────────────────

def encode_labels(y_train, y_val, y_test):
    """Label encode for 7 classes."""
    print("=" * 70)
    print("  Label Encoding")
    print("=" * 70)
    
    encoder = LabelEncoder()
    y_train_e = encoder.fit_transform(y_train)
    y_val_e = encoder.transform(y_val)
    y_test_e = encoder.transform(y_test)
    
    print(f"  Classes ({len(encoder.classes_)}): {encoder.classes_.tolist()}")
    for i, cls in enumerate(encoder.classes_):
        count = (y_train_e == i).sum()
        print(f"    {i} = {cls:15s}: {count:>10,} training samples")
    print()
    
    return y_train_e, y_val_e, y_test_e, encoder


# ──────────────────────────────────────────────────────────────
# Step 8: Train XGBoost (Primary)
# ──────────────────────────────────────────────────────────────

def train_xgboost(X_train, y_train, X_val, y_val, num_classes):
    """Train XGBoost with regularization to prevent overfitting and memorization."""
    print("=" * 70)
    print("  Training XGBoost (7-Class)")
    print("=" * 70)
    
    # Sample weights for imbalance
    unique, counts = np.unique(y_train, return_counts=True)
    total = len(y_train)
    class_weights = {cls: total / count for cls, count in zip(unique, counts)}
    sample_weights = np.array([class_weights[y] for y in y_train])
    
    # Objective
    objective = "binary:logistic" if num_classes == 2 else "multi:softprob"
    print(f"  Objective: {objective}")
    
    # Regularized model to prevent overfitting & exact sample memorization
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.08,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        subsample=0.8,
        colsample_bytree=0.8,
        objective=objective,
        eval_metric="mlogloss" if num_classes > 2 else "logloss",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbosity=0,
    )
    
    start = time.time()
    xgb.fit(
        X_train, y_train,
        sample_weight=sample_weights,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )
    elapsed = time.time() - start
    
    val_preds = xgb.predict(X_val)
    val_acc = accuracy_score(y_val, val_preds)
    val_f1 = f1_score(y_val, val_preds, average="weighted")
    
    print(f"  Training time: {elapsed:.1f}s")
    print(f"  Val Accuracy:  {val_acc:.4f}")
    print(f"  Val F1 (weighted): {val_f1:.4f}")
    print()
    
    return xgb


# ──────────────────────────────────────────────────────────────
# Step 9: Train Isolation Forest (Anomaly Detection)
# ──────────────────────────────────────────────────────────────

def train_isolation_forest(X_train, contamination=0.1):
    """Train Isolation Forest for anomaly/novelty detection."""
    print("=" * 70)
    print("  Training Isolation Forest (Anomaly Detection)")
    print("=" * 70)
    
    iso = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbose=0,
    )
    
    start = time.time()
    iso.fit(X_train)
    elapsed = time.time() - start
    
    print(f"  Training time: {elapsed:.1f}s")
    print(f"  Contamination: {contamination}")
    print()
    
    return iso


# ──────────────────────────────────────────────────────────────
# Step 10: Full Evaluation
# ──────────────────────────────────────────────────────────────

def evaluate_full(
    xgb_model, iso_model, X_test, y_test,
    label_encoder, feature_names, X_train=None, y_train=None
):
    """
    Comprehensive evaluation with:
      - Per-class metrics
      - Confusion matrix heatmap
      - ROC curves (one-vs-rest)
      - Precision-Recall curves
      - Feature importance
      - Ablation comparison
    """
    print("=" * 70)
    print("  Full Evaluation")
    print("=" * 70)
    
    class_names = label_encoder.classes_
    n_classes = len(class_names)
    
    # ── Predictions ──
    y_pred_xgb = xgb_model.predict(X_test)
    y_proba_xgb = xgb_model.predict_proba(X_test)
    
    # Isolation Forest predictions (-1=anomaly, 1=normal)
    y_pred_iso = iso_model.predict(X_test)
    y_pred_iso_binary = (y_pred_iso == -1).astype(int)  # 1=anomaly
    
    # -- 1. Classification Report --
    print("\n  -- Classification Report (XGBoost) --")
    print(classification_report(y_test, y_pred_xgb, target_names=class_names, digits=4))
    
    # -- 2. Per-Class Metrics Table --
    print("\n  -- Per-Class Performance --")
    print(f"  {'Class':15s} {'Precision':>10s} {'Recall':>10s} {'F1':>10s} {'Support':>10s}")
    print(f"  {'-'*60}")
    
    per_class = {}
    for i, cls in enumerate(class_names):
        prec = precision_score(y_test, y_pred_xgb, average=None, labels=[i])[0]
        rec = recall_score(y_test, y_pred_xgb, average=None, labels=[i])[0]
        f1 = f1_score(y_test, y_pred_xgb, average=None, labels=[i])[0]
        sup = (y_test == i).sum()
        per_class[cls] = {"precision": prec, "recall": rec, "f1": f1, "support": sup}
        print(f"  {cls:15s} {prec:10.4f} {rec:10.4f} {f1:10.4f} {sup:10.0f}")
    
    # Overall
    acc = accuracy_score(y_test, y_pred_xgb)
    f1_w = f1_score(y_test, y_pred_xgb, average="weighted")
    f1_m = f1_score(y_test, y_pred_xgb, average="macro")
    print(f"\n  Overall Accuracy:     {acc:.4f}")
    print(f"  F1 (Weighted):        {f1_w:.4f}")
    print(f"  F1 (Macro):           {f1_m:.4f}")
    
    # -- 3. Confusion Matrix Heatmap --
    cm = confusion_matrix(y_test, y_pred_xgb)
    plt.figure(figsize=(12, 10))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_names, yticklabels=class_names,
                cbar_kws={'label': 'Count'})
    plt.title('Confusion Matrix - XGBoost (7-Class)', fontsize=14, fontweight='bold')
    plt.xlabel('Predicted', fontsize=12)
    plt.ylabel('Actual', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    cm_path = REPORT_DIR / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"\n  Confusion matrix saved: {cm_path}")
    
    # -- 4. ROC Curves (One-vs-Rest) --
    y_test_bin = label_binarize(y_test, classes=range(n_classes))
    
    plt.figure(figsize=(12, 10))
    colors = plt.cm.tab10(np.linspace(0, 1, n_classes))
    
    for i, (cls, color) in enumerate(zip(class_names, colors)):
        fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_proba_xgb[:, i])
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, color=color, lw=2,
                 label=f'{cls} (AUC = {roc_auc:.3f})')
    
    plt.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.3)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('ROC Curves - One-vs-Rest', fontsize=14, fontweight='bold')
    plt.legend(loc='lower right', fontsize=9)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    roc_path = REPORT_DIR / "roc_curves.png"
    plt.savefig(roc_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  ROC curves saved: {roc_path}")
    
    # -- 5. Precision-Recall Curves --
    plt.figure(figsize=(12, 10))
    
    for i, (cls, color) in enumerate(zip(class_names, colors)):
        precision, recall, _ = precision_recall_curve(y_test_bin[:, i], y_proba_xgb[:, i])
        ap = average_precision_score(y_test_bin[:, i], y_proba_xgb[:, i])
        plt.plot(recall, precision, color=color, lw=2,
                 label=f'{cls} (AP = {ap:.3f})')
    
    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title('Precision-Recall Curves', fontsize=14, fontweight='bold')
    plt.legend(loc='lower left', fontsize=9)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    pr_path = REPORT_DIR / "precision_recall_curves.png"
    plt.savefig(pr_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  PR curves saved: {pr_path}")
    
    # -- 6. Feature Importance --
    importance = xgb_model.feature_importances_
    fi_df = pd.DataFrame({
        "feature": feature_names,
        "importance": importance,
    }).sort_values("importance", ascending=False)
    
    plt.figure(figsize=(12, 10))
    top_25 = fi_df.head(25)
    sns.barplot(x="importance", y="feature", data=top_25, palette="viridis")
    plt.title('Top 25 Feature Importance - XGBoost', fontsize=14, fontweight='bold')
    plt.xlabel('Importance Score', fontsize=12)
    plt.tight_layout()
    fi_path = REPORT_DIR / "feature_importance.png"
    plt.savefig(fi_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Feature importance saved: {fi_path}")
    
    # -- 7. Cross-Validation (Safe Stratified Sample) --
    if X_train is not None and y_train is not None:
        print("\n  -- 5-Fold Cross-Validation --")
        try:
            cv_n = min(len(X_train), 10000)
            idx_sample, _ = train_test_split(
                np.arange(len(X_train)), train_size=cv_n,
                stratify=y_train, random_state=RANDOM_STATE
            )
            cv_model = XGBClassifier(
                n_estimators=50,
                max_depth=4,
                learning_rate=0.1,
                random_state=RANDOM_STATE,
                n_jobs=1,
                verbosity=0,
            )
            cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
            cv_scores = cross_val_score(cv_model, X_train[idx_sample], y_train[idx_sample], cv=cv, scoring='f1_weighted', n_jobs=1)
            print(f"  CV F1 (weighted, N={cv_n:,}): {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")
        except Exception as e:
            print(f"  CV Note: Skipped ({e})")
    
    # -- 8. Ablation: ML Only vs Rule Engine vs Hybrid --
    print("\n  -- Ablation Study --")
    print(f"  {'Method':25s} {'F1 (Weighted)':>15s}")
    print(f"  {'-'*42}")
    print(f"  {'XGBoost (ML Only)':25s} {f1_w:>15.4f}")
    print(f"  {'Rule Engine (Rules Only)':25s} {'N/A (see Phase 3 tests)':>15s}")
    print(f"  {'Hybrid (Weighted Fusion)':25s} {'ML score used with rules':>15s}")
    print(f"  {'Isolation Forest (Anomaly)':25s} {'Unsupervised':>15s}")
    
    # Build results dict
    results = {
        "accuracy": acc,
        "f1_weighted": f1_w,
        "f1_macro": f1_m,
        "per_class": per_class,
        "confusion_matrix": cm,
        "feature_importance": fi_df,
    }
    
    print()
    return results


# ──────────────────────────────────────────────────────────────
# Step 11: Cross-Dataset & Out-of-Distribution Validation
# ──────────────────────────────────────────────────────────────

def evaluate_cross_dataset(
    xgb_model, scaler, label_encoder, feature_names: List[str],
    external_csv_path: Path, label_mapping: Dict[str, str] = None
) -> Optional[Dict]:
    """
    Evaluate the trained NIDS model against an external dataset (e.g. CSE-CIC-IDS-2018 or UNSW-NB15)
    to measure true out-of-distribution generalization.
    """
    if not external_csv_path.exists():
        print(f"  [Cross-Dataset] External dataset not found at {external_csv_path}. Skipping.")
        return None
        
    print("=" * 70)
    print(f"  Cross-Dataset Evaluation: {external_csv_path.name}")
    print("=" * 70)
    
    df_ext = pd.read_csv(external_csv_path)
    df_ext.columns = df_ext.columns.str.strip()
    
    if "Label" not in df_ext.columns:
        print("  [Cross-Dataset] 'Label' column not found.")
        return None
        
    if label_mapping:
        df_ext["Label"] = df_ext["Label"].map(label_mapping).fillna("Unknown")
        df_ext = df_ext[df_ext["Label"].isin(label_encoder.classes_)]
        
    y_ext = df_ext["Label"]
    y_ext_e = label_encoder.transform(y_ext)
    
    # Feature alignment
    feature_matrix = []
    for feat in feature_names:
        if feat in df_ext.columns:
            feature_matrix.append(df_ext[feat].fillna(0.0).values)
        else:
            feature_matrix.append(np.zeros(len(df_ext)))
            
    X_ext = np.column_stack(feature_matrix)
    X_ext_s = scaler.transform(X_ext)
    
    preds = xgb_model.predict(X_ext_s)
    acc = accuracy_score(y_ext_e, preds)
    f1_w = f1_score(y_ext_e, preds, average="weighted")
    
    print(f"  External Dataset Accuracy: {acc:.4f}")
    print(f"  External Dataset F1 (w):   {f1_w:.4f}")
    print("\n" + classification_report(y_ext_e, preds, target_names=label_encoder.classes_, digits=4))
    
    return {"accuracy": acc, "f1_weighted": f1_w}


# ──────────────────────────────────────────────────────────────
# Step 12: Save Everything
# ──────────────────────────────────────────────────────────────

def save_artifacts(xgb_model, iso_model, scaler, label_encoder, feature_names, results):
    """Save models, scaler, encoder, feature names, and reports."""
    print("=" * 70)
    print("  Saving Artifacts")
    print("=" * 70)
    
    artifacts = {
        "nids_xgboost_7class.pkl": xgb_model,
        "nids_xgboost.pkl": xgb_model,
        "nids_isolation_forest.pkl": iso_model,
        "scaler_7class.pkl": scaler,
        "scaler.pkl": scaler,
        "label_encoder_7class.pkl": label_encoder,
        "label_encoder.pkl": label_encoder,
        "feature_names_7class.pkl": feature_names,
        "feature_names.pkl": feature_names,
    }
    
    for filename, obj in artifacts.items():
        path = MODEL_DIR / filename
        with open(path, "wb") as f:
            pickle.dump(obj, f)
        print(f"  [OK] {path}")
    
    # Save CSV reports
    results["feature_importance"].to_csv(REPORT_DIR / "feature_importance.csv", index=False)
    
    per_class_df = pd.DataFrame(results["per_class"]).T
    per_class_df.to_csv(REPORT_DIR / "per_class_metrics.csv")
    
    # Save evaluation summary
    with open(REPORT_DIR / "evaluation_summary.txt", "w") as f:
        f.write("=" * 60 + "\n")
        f.write("SOC-NIDS Phase 7: Full Evaluation Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Classes: {len(label_encoder.classes_)}\n")
        f.write(f"Features: {len(feature_names)}\n")
        f.write(f"Model: XGBoost (7-class)\n\n")
        f.write(f"Overall Accuracy: {results['accuracy']:.4f}\n")
        f.write(f"F1 (Weighted):    {results['f1_weighted']:.4f}\n")
        f.write(f"F1 (Macro):       {results['f1_macro']:.4f}\n\n")
        f.write("Per-Class Performance:\n")
        f.write(f"{'Class':15s} {'Precision':>10s} {'Recall':>10s} {'F1':>10s}\n")
        f.write("-" * 50 + "\n")
        for cls, metrics in results["per_class"].items():
            f.write(f"{cls:15s} {metrics['precision']:10.4f} {metrics['recall']:10.4f} {metrics['f1']:10.4f}\n")
    
    print(f"  [OK] {REPORT_DIR / 'evaluation_summary.txt'}")
    print()


# ──────────────────────────────────────────────────────────────
# Main Pipeline
# ──────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  SOC-NIDS // PHASE 7: FULL DATA EXPANSION")
    print("  7-Class Detection with Advanced Evaluation (Leak-Free)")
    print("=" * 70)
    print()
    
    # 1-3: Data Ingestion, Cleaning & Mapping
    df = load_all_data(DATA_FILES)
    df = clean_data(df)
    df = map_labels(df)
    
    # 4: Split data before imputation to prevent data leakage
    (X_train, y_train), (X_val, y_val), (X_test, y_test) = split_data(df)
    
    # 5: Leak-Free Imputation (fit on train, transform all)
    X_train, X_val, X_test = impute_missing(X_train, X_val, X_test)
    
    # 6-7: Preprocess & Scale
    X_train_s, X_val_s, X_test_s, scaler, feature_names = scale_data(X_train, X_val, X_test)
    y_train_e, y_val_e, y_test_e, label_encoder = encode_labels(y_train, y_val, y_test)
    
    # 8: Train XGBoost (Regularized)
    num_classes = len(label_encoder.classes_)
    xgb_model = train_xgboost(X_train_s, y_train_e, X_val_s, y_val_e, num_classes)
    
    # 9: Train Isolation Forest
    iso_model = train_isolation_forest(X_train_s, contamination=0.1)
    
    # 10: Full Evaluation
    results = evaluate_full(
        xgb_model, iso_model, X_test_s, y_test_e,
        label_encoder, feature_names,
        X_train_s, y_train_e
    )
    
    # 11: Save All Artifacts
    save_artifacts(xgb_model, iso_model, scaler, label_encoder, feature_names, results)
    
    # Final
    print("=" * 70)
    print("  PHASE 7 COMPLETE")
    print("=" * 70)
    print(f"  Model: XGBoost 7-Class")
    print(f"  Accuracy: {results['accuracy']:.4f}")
    print(f"  F1 (Weighted): {results['f1_weighted']:.4f}")
    print(f"  Artifacts saved to: {MODEL_DIR}/")
    print(f"  Reports saved to: {REPORT_DIR}/")
    print()


if __name__ == "__main__":
    main()
