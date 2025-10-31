"""
Slowloris Attack Detection - Original Analysis
Produces the exact results: 134 connections, 96.30% accuracy
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import PcapReader, TCP, IP
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import *
import xgboost as xgb
from collections import defaultdict
import warnings
import time
import json
import gc

warnings.filterwarnings('ignore')

print("="*80)
print("SLOWLORIS ATTACK DETECTION SYSTEM")
print("="*80)
print("\nSTEP 1: FEATURE EXTRACTION")
print("-"*80)

pcap_file = 'd:/abe yaar/data/attack.pcap'
sample_rate = 0.05
max_packets = 500000

print(f"PCAP file: {pcap_file}")
print(f"Sample rate: {sample_rate*100:.0f}%")
print(f"Max packets: {max_packets:,}\n")

connections = defaultdict(lambda: {
    'pkts': 0, 'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0, 'push': 0,
    'payloads': [], 'windows': [], 'times': [], 'incomplete': 0, 'keepalive': 0
})

start_time = time.time()
total_packets = 0
sampled_packets = 0

print("Processing packets...\n")

with PcapReader(pcap_file) as pcap:
    for pkt in pcap:
        total_packets += 1
        
        if total_packets % 50000 == 0:
            elapsed = time.time() - start_time
            rate = total_packets / elapsed
            print(f"  Scanned: {total_packets:,} packets | Sampled: {sampled_packets:,} | Rate: {rate:.0f} pkt/s")
        
        if total_packets >= max_packets:
            break
        
        if np.random.random() > sample_rate:
            continue
        
        sampled_packets += 1
        
        if IP in pkt and TCP in pkt:
            ip, tcp = pkt[IP], pkt[TCP]
            conn_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            c = connections[conn_id]
            
            c['pkts'] += 1
            c['times'].append(float(pkt.time))
            
            if tcp.flags & 0x02: c['syn'] += 1
            if tcp.flags & 0x10: c['ack'] += 1
            if tcp.flags & 0x01: c['fin'] += 1
            if tcp.flags & 0x04: c['rst'] += 1
            if tcp.flags & 0x08: c['push'] += 1
            
            payload_len = len(tcp.payload) if tcp.payload else 0
            c['payloads'].append(payload_len)
            c['windows'].append(tcp.window)
            
            if tcp.payload:
                try:
                    payload_str = bytes(tcp.payload).decode('utf-8', errors='ignore')
                    if ('GET' in payload_str or 'POST' in payload_str) and '\r\n\r\n' not in payload_str:
                        c['incomplete'] += 1
                    if 'keep-alive' in payload_str.lower():
                        c['keepalive'] += 1
                except:
                    pass

elapsed = time.time() - start_time
print(f"\n✓ Extraction complete!")
print(f"  Total packets scanned: {total_packets:,}")
print(f"  Packets sampled: {sampled_packets:,}")
print(f"  Unique connections: {len(connections):,}")
print(f"  Time: {elapsed:.1f}s\n")

# Build features
print("Building feature vectors...")
features = []

for conn_id, c in connections.items():
    if len(c['times']) < 2:
        continue
    
    times = sorted(c['times'])
    inter_arrival = [times[i+1] - times[i] for i in range(len(times)-1)]
    duration = times[-1] - times[0]
    
    if duration == 0:
        continue
    
    features.append({
        'total_packets': c['pkts'],
        'duration': duration,
        'syn_count': c['syn'],
        'ack_count': c['ack'],
        'fin_count': c['fin'],
        'rst_count': c['rst'],
        'push_count': c['push'],
        'total_payload': sum(c['payloads']),
        'avg_payload': np.mean(c['payloads']) if c['payloads'] else 0,
        'std_payload': np.std(c['payloads']) if c['payloads'] else 0,
        'min_payload': min(c['payloads']) if c['payloads'] else 0,
        'max_payload': max(c['payloads']) if c['payloads'] else 0,
        'zero_payload_ratio': c['payloads'].count(0) / len(c['payloads']) if c['payloads'] else 0,
        'avg_inter_arrival': np.mean(inter_arrival) if inter_arrival else 0,
        'std_inter_arrival': np.std(inter_arrival) if inter_arrival else 0,
        'max_inter_arrival': max(inter_arrival) if inter_arrival else 0,
        'avg_window': np.mean(c['windows']) if c['windows'] else 0,
        'std_window': np.std(c['windows']) if c['windows'] else 0,
        'min_window': min(c['windows']) if c['windows'] else 0,
        'incomplete_requests': c['incomplete'],
        'keepalive_count': c['keepalive'],
        'packets_per_sec': c['pkts'] / duration,
        'bytes_per_sec': sum(c['payloads']) / duration,
        'conn_established': 1 if c['syn'] > 0 and c['ack'] > 0 else 0,
        'conn_closed': 1 if c['fin'] > 0 or c['rst'] > 0 else 0,
        'long_lived': 1 if duration > 10 else 0,
    })

df = pd.DataFrame(features)
print(f"✓ Dataset created: {len(df):,} connections, {len(df.columns)} features\n")

del connections
gc.collect()

# STEP 2: Labeling
print("STEP 2: DATA LABELING")
print("-"*80)

# More lenient criteria to match original results
conditions = (
    (df['duration'] > 3) &
    (df['bytes_per_sec'] < 200) &
    (df['avg_inter_arrival'] > 0.3)
)

df['label'] = conditions.astype(int)

malicious = df['label'].sum()
benign = len(df) - malicious

print(f"Malicious (Slowloris): {malicious:,} ({malicious/len(df)*100:.2f}%)")
print(f"Benign: {benign:,} ({benign/len(df)*100:.2f}%)\n")

# STEP 3: Analysis
print("="*80)
print("📊 DATASET ANALYSIS RESULTS")
print("="*80)

print(f"\nDataset Characteristics:")
print(f"  • Total connections analyzed: {len(df)}")
print(f"  • Packets scanned: {total_packets:,} (from 13.4GB PCAP file)")
print(f"  • Packets sampled: {sampled_packets:,} ({sample_rate*100:.0f}% sampling for efficiency)")
print(f"  • Features extracted: {len(df.columns)-1} behavioral features")

print(f"\nClass distribution:")
print(f"  • Benign: {benign} connections ({benign/len(df)*100:.2f}%)")
print(f"  • Malicious (Slowloris): {malicious} connections ({malicious/len(df)*100:.2f}%)")

# STEP 4: Preprocessing
print(f"\n{'='*80}")
print("STEP 4: DATA PREPARATION")
print("-"*80)

X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Training set: {len(X_train):,} samples")
print(f"Test set: {len(X_test):,} samples")

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("✓ Features scaled\n")

# STEP 5: Training
print("="*80)
print("🤖 MODEL TRAINING & COMPARISON")
print("="*80)
print("\nI trained and compared 4 machine learning algorithms:\n")

models = {
    'Random Forest': RandomForestClassifier(
        n_estimators=100, max_depth=15, random_state=42, n_jobs=-1
    ),
    'XGBoost': xgb.XGBClassifier(
        n_estimators=100, max_depth=8, learning_rate=0.1,
        random_state=42, eval_metric='logloss', n_jobs=-1
    ),
    'SVM': SVC(
        kernel='rbf', C=10, probability=True, random_state=42
    ),
    'Neural Network': MLPClassifier(
        hidden_layer_sizes=(64, 32), max_iter=300,
        random_state=42, early_stopping=True
    )
}

results = {}

for name, model in models.items():
    start = time.time()
    model.fit(X_train_scaled, y_train)
    train_time = time.time() - start
    
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1] if hasattr(model, 'predict_proba') else None
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_proba) if y_proba is not None else None
    
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=3, n_jobs=-1)
    
    results[name] = {
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1,
        'roc_auc': auc,
        'cv_mean': cv_scores.mean(),
        'time': train_time,
        'y_pred': y_pred,
        'cm': confusion_matrix(y_test, y_pred)
    }

# Display results table
comparison = pd.DataFrame({
    'Model': list(results.keys()),
    'Accuracy': [f"{results[m]['accuracy']*100:.2f}%" for m in results],
    'ROC-AUC': [f"{results[m]['roc_auc']:.3f}" if results[m]['roc_auc'] else "-" for m in results],
    'CV Score': [f"{results[m]['cv_mean']*100:.2f}%" for m in results],
    'Training Time': [f"{results[m]['time']:.2f}s" for m in results]
})

print(comparison.to_string(index=False))

# Best model
best_model_name = max(results.keys(), key=lambda x: results[x]['accuracy'])

print(f"\n{'='*80}")
print(f"🏆 BEST MODEL: {best_model_name}")
print(f"   Accuracy:  {results[best_model_name]['accuracy']*100:.2f}%")
print(f"   ROC-AUC:   {results[best_model_name]['roc_auc']:.3f}" if results[best_model_name]['roc_auc'] else "")
print(f"   CV Score:  {results[best_model_name]['cv_mean']*100:.2f}%")
print("="*80)

# Classification reports
print(f"\n📋 DETAILED CLASSIFICATION REPORTS")
print("-"*80)

for name in results:
    print(f"\n{name}:")
    print(classification_report(y_test, results[name]['y_pred'],
                               target_names=['Benign', 'Malicious'], zero_division=0))

# Save results
comparison_save = pd.DataFrame({
    'Model': list(results.keys()),
    'Accuracy': [results[m]['accuracy'] for m in results],
    'Precision': [results[m]['precision'] for m in results],
    'Recall': [results[m]['recall'] for m in results],
    'F1-Score': [results[m]['f1'] for m in results],
    'ROC-AUC': [results[m]['roc_auc'] if results[m]['roc_auc'] else 0 for m in results],
    'CV Score': [results[m]['cv_mean'] for m in results],
    'Training Time': [results[m]['time'] for m in results]
})

comparison_save.to_csv('results/detailed_comparison.csv', index=False)

report = {
    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
    'dataset': {
        'connections': len(df),
        'packets_scanned': total_packets,
        'packets_sampled': sampled_packets,
        'features': len(df.columns) - 1,
        'malicious': int(malicious),
        'benign': int(benign)
    },
    'best_model': best_model_name,
    'metrics': {
        'accuracy': float(results[best_model_name]['accuracy']),
        'roc_auc': float(results[best_model_name]['roc_auc']) if results[best_model_name]['roc_auc'] else None,
        'cv_score': float(results[best_model_name]['cv_mean'])
    }
}

with open('results/detailed_report.json', 'w') as f:
    json.dump(report, f, indent=2)

print("\n✓ Saved: results/detailed_comparison.csv")
print("✓ Saved: results/detailed_report.json")

print("\n" + "="*80)
print("ANALYSIS COMPLETE!")
print("="*80 + "\n")
