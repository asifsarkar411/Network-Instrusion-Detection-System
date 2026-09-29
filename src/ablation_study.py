"""
Phase 8: Ablation Study
========================
Compares detection performance across:
  - ML Model Only (XGBoost)
  - Rule Engine Only
  - Hybrid (Weighted Fusion)
  - Isolation Forest (Anomaly)

Uses the test set to measure detection rates.
"""

import sys, os, pickle, time
import numpy as np
import pandas as pd
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.rule_engine import RuleEngine
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score

MODEL_DIR = Path("models")

def load_model(filename):
    with open(MODEL_DIR / filename, "rb") as f:
        return pickle.load(f)

def main():
    print("=" * 60)
    print("  Phase 8: Ablation Study")
    print("  ML Only vs Rules Only vs Hybrid vs Anomaly")
    print("=" * 60)
    
    # Load artifacts
    xgb = load_model("nids_xgboost_7class.pkl")
    iso = load_model("nids_isolation_forest.pkl")
    scaler = load_model("scaler_7class.pkl")
    encoder = load_model("label_encoder_7class.pkl")
    feature_names = load_model("feature_names_7class.pkl")
    
    # Load test data
    from src.train_model import load_all_data, clean_data, map_labels, handle_missing, split_data, scale_data, encode_labels
    from src.train_model import DATA_FILES
    
    df = load_all_data(DATA_FILES)
    df = clean_data(df)
    df = map_labels(df)
    df = handle_missing(df)
    (X_train, y_train), (X_val, y_val), (X_test, y_test) = split_data(df)
    X_train_s, X_val_s, X_test_s, scaler2, fnames = scale_data(X_train, X_val, X_test)
    y_train_e, y_val_e, y_test_e, encoder2 = encode_labels(y_train, y_val, y_test)
    
    # ── ML Only ──
    print("\n1. ML Model Only (XGBoost)")
    y_pred_ml = xgb.predict(X_test_s)
    ml_acc = accuracy_score(y_test_e, y_pred_ml)
    ml_f1 = f1_score(y_test_e, y_pred_ml, average="weighted")
    ml_prec = precision_score(y_test_e, y_pred_ml, average="weighted")
    ml_rec = recall_score(y_test_e, y_pred_ml, average="weighted")
    print(f"   Accuracy:  {ml_acc:.4f}")
    print(f"   Precision: {ml_prec:.4f}")
    print(f"   Recall:    {ml_rec:.4f}")
    print(f"   F1:        {ml_f1:.4f}")
    
    # ── Rule Engine Only ──
    print("\n2. Rule Engine Only")
    rule_engine = RuleEngine()
    y_true_rule = []
    y_pred_rule = []
    
    # Convert test flows back to dicts for rule engine
    X_test_dicts = X_test.to_dict("records")
    
    for i, flow in enumerate(X_test_dicts[:5000]):  # Sample 5000 for speed
        result = rule_engine.evaluate_flow(flow)
        detected = result.get("detected_type")
        actual = y_test.iloc[i]
        
        y_true_rule.append(actual)
        y_pred_rule.append(detected if detected else "Benign")
    
    # Map rule predictions to encoded labels
    y_true_rule_mapped = []
    y_pred_rule_mapped = []
    for t, p in zip(y_true_rule, y_pred_rule):
        if p in encoder.classes_:
            y_true_rule_mapped.append(encoder.transform([t])[0])
            y_pred_rule_mapped.append(encoder.transform([p])[0])
        elif p == "Portscan":
            y_true_rule_mapped.append(encoder.transform([t])[0])
            y_pred_rule_mapped.append(encoder.transform(["PortScan"])[0])
        elif p == "dos":
            y_true_rule_mapped.append(encoder.transform([t])[0])
            y_pred_rule_mapped.append(encoder.transform(["DoS"])[0])
        elif p == "webattack":
            y_true_rule_mapped.append(encoder.transform([t])[0])
            y_pred_rule_mapped.append(encoder.transform(["WebAttack"])[0])
        else:
            y_true_rule_mapped.append(encoder.transform([t])[0])
            y_pred_rule_mapped.append(encoder.transform(["Benign"])[0])
    
    rule_acc = accuracy_score(y_true_rule_mapped, y_pred_rule_mapped)
    rule_f1 = f1_score(y_true_rule_mapped, y_pred_rule_mapped, average="weighted", zero_division=0)
    rule_prec = precision_score(y_true_rule_mapped, y_pred_rule_mapped, average="weighted", zero_division=0)
    rule_rec = recall_score(y_true_rule_mapped, y_pred_rule_mapped, average="weighted", zero_division=0)
    print(f"   Accuracy:  {rule_acc:.4f}")
    print(f"   Precision: {rule_prec:.4f}")
    print(f"   Recall:    {rule_rec:.4f}")
    print(f"   F1:        {rule_f1:.4f}")
    print(f"   (Note: Rule engine is signature-based, misses behavioral attacks)")
    
    # ── Hybrid (Weighted Fusion) ──
    print("\n3. Hybrid (Weighted Fusion)")
    W_RULE, W_ML = 0.4, 0.6
    
    y_pred_hybrid = []
    for i, (flow_dict, ml_pred) in enumerate(zip(X_test_dicts[:5000], y_pred_ml[:5000])):
        # Rule score
        rule_result = rule_engine.evaluate_flow(flow_dict)
        rule_score = rule_result.get("max_score", 0)
        
        # ML score
        ml_proba = xgb.predict_proba(X_test_s[i:i+1])[0]
        ml_score = max(ml_proba)
        ml_class = encoder.classes_[np.argmax(ml_proba)]
        
        # Fusion
        if rule_score > 0.8 and ml_score < 0.5:
            final_class = rule_result.get("detected_type", "Benign")
            if final_class == "portscan": final_class = "PortScan"
            elif final_class == "dos": final_class = "DoS"
            elif final_class == "webattack": final_class = "WebAttack"
            else: final_class = "Benign"
        else:
            final_class = ml_class
        
        if final_class in encoder.classes_:
            y_pred_hybrid.append(encoder.transform([final_class])[0])
        else:
            y_pred_hybrid.append(encoder.transform(["Benign"])[0])
    
    y_true_hybrid = [encoder.transform([y_test.iloc[i]])[0] for i in range(5000)]
    
    hyb_acc = accuracy_score(y_true_hybrid, y_pred_hybrid)
    hyb_f1 = f1_score(y_true_hybrid, y_pred_hybrid, average="weighted")
    hyb_prec = precision_score(y_true_hybrid, y_pred_hybrid, average="weighted")
    hyb_rec = recall_score(y_true_hybrid, y_pred_hybrid, average="weighted")
    print(f"   Accuracy:  {hyb_acc:.4f}")
    print(f"   Precision: {hyb_prec:.4f}")
    print(f"   Recall:    {hyb_rec:.4f}")
    print(f"   F1:        {hyb_f1:.4f}")
    
    # ── Isolation Forest ──
    print("\n4. Isolation Forest (Anomaly Detection)")
    y_pred_iso = iso.predict(X_test_s[:5000])
    # Convert: -1=anomaly(attack), 1=normal(benign)
    y_pred_iso_bin = (y_pred_iso == -1).astype(int)
    y_true_bin = (y_test_e[:5000] != 0).astype(int)  # 0=Benign, 1=Attack
    
    iso_acc = accuracy_score(y_true_bin, y_pred_iso_bin)
    iso_f1 = f1_score(y_true_bin, y_pred_iso_bin, average="binary", zero_division=0)
    iso_prec = precision_score(y_true_bin, y_pred_iso_bin, zero_division=0)
    iso_rec = recall_score(y_true_bin, y_pred_iso_bin, zero_division=0)
    print(f"   Accuracy:  {iso_acc:.4f}")
    print(f"   Precision: {iso_prec:.4f}")
    print(f"   Recall:    {iso_rec:.4f}")
    print(f"   F1:        {iso_f1:.4f}")
    print(f"   (Binary anomaly detection only — not per-class)")
    
    # ── Summary Table ──
    print("\n" + "=" * 60)
    print("  ABLATION STUDY SUMMARY")
    print("=" * 60)
    print(f"  {'Method':25s} {'Accuracy':>10s} {'Precision':>10s} {'Recall':>10s} {'F1':>10s}")
    print(f"  {'─'*65}")
    print(f"  {'XGBoost (ML Only)':25s} {ml_acc:10.4f} {ml_prec:10.4f} {ml_rec:10.4f} {ml_f1:10.4f}")
    print(f"  {'Rule Engine Only':25s} {rule_acc:10.4f} {rule_prec:10.4f} {rule_rec:10.4f} {rule_f1:10.4f}")
    print(f"  {'Hybrid (Fusion)':25s} {hyb_acc:10.4f} {hyb_prec:10.4f} {hyb_rec:10.4f} {hyb_f1:10.4f}")
    print(f"  {'Isolation Forest':25s} {iso_acc:10.4f} {iso_prec:10.4f} {iso_rec:10.4f} {iso_f1:10.4f}")
    print()
    print("  ✓ Ablation study complete")
    
    # Save
    with open("reports/ablation_study.txt", "w", encoding="utf-8") as f:
        f.write("SOC-NIDS Ablation Study\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"{'Method':25s} {'Accuracy':>10s} {'Precision':>10s} {'Recall':>10s} {'F1':>10s}\n")
        f.write("-" * 65 + "\n")
        f.write(f"{'XGBoost (ML Only)':25s} {ml_acc:10.4f} {ml_prec:10.4f} {ml_rec:10.4f} {ml_f1:10.4f}\n")
        f.write(f"{'Rule Engine Only':25s} {rule_acc:10.4f} {rule_prec:10.4f} {rule_rec:10.4f} {rule_f1:10.4f}\n")
        f.write(f"{'Hybrid (Fusion)':25s} {hyb_acc:10.4f} {hyb_prec:10.4f} {hyb_rec:10.4f} {hyb_f1:10.4f}\n")
        f.write(f"{'Isolation Forest':25s} {iso_acc:10.4f} {iso_prec:10.4f} {iso_rec:10.4f} {iso_f1:10.4f}\n")
    print("  Saved: reports/ablation_study.txt")

if __name__ == "__main__":
    main()
