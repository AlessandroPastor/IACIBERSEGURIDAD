"""
Genera los modelos requeridos por los Caps. 03, 04 y guarda en ../models/.
Ejecutar desde la raiz del proyecto:  python generar_modelos.py
"""
import numpy as np
import pandas as pd
import joblib
from pathlib import Path

MODELS_DIR = Path("models")
DATA_DIR   = Path("data")
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── CAP 03: Isolation Forest + MinMaxScaler ───────────────────────────────────
print("=== Cap.03: Isolation Forest ===")
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.ensemble import IsolationForest

rng = np.random.default_rng(seed=42)
N, NA = 4750, 250

normal = pd.DataFrame({
    "bytes_sent": rng.normal(50_000,  15_000, N).clip(0),
    "bytes_recv": rng.normal(120_000, 40_000, N).clip(0),
    "duration"  : rng.normal(30, 12, N).clip(1),
    "src_port"  : rng.integers(1024, 65535, N),
    "dst_port"  : rng.choice([80, 443, 22, 3306, 8080], N),
    "protocol"  : rng.choice(["TCP","UDP","TCP","TCP","ICMP"], N),
    "label"     : 0,
})
n3    = NA // 3
exfil = pd.DataFrame({
    "bytes_sent": rng.normal(5_000_000, 500_000, n3).clip(0),
    "bytes_recv": rng.normal(10_000, 5_000, n3).clip(0),
    "duration"  : rng.normal(120, 30, n3).clip(1),
    "src_port"  : rng.integers(1024, 65535, n3),
    "dst_port"  : rng.choice([443, 80], n3),
    "protocol"  : "TCP", "label": 1,
})
scan  = pd.DataFrame({
    "bytes_sent": rng.normal(64, 10, n3).clip(0),
    "bytes_recv": rng.normal(64, 10, n3).clip(0),
    "duration"  : rng.uniform(0.001, 0.5, n3),
    "src_port"  : rng.integers(1024, 65535, n3),
    "dst_port"  : rng.integers(1, 1024, n3),
    "protocol"  : "TCP", "label": 1,
})
r  = NA - 2 * n3
c2 = pd.DataFrame({
    "bytes_sent": rng.normal(10_000, 3_000, r).clip(0),
    "bytes_recv": rng.normal(8_000,  2_000, r).clip(0),
    "duration"  : rng.normal(7200, 1800, r).clip(1),
    "src_port"  : rng.integers(1024, 65535, r),
    "dst_port"  : rng.choice([4444, 1337, 31337], r),
    "protocol"  : "TCP", "label": 1,
})

df_red = pd.concat([normal, exfil, scan, c2], ignore_index=True)
df_red["protocol"] = LabelEncoder().fit_transform(df_red["protocol"])
df_red.to_csv(DATA_DIR / "network_traffic.csv", index=False)
print(f"  network_traffic.csv  -> {len(df_red):,} filas")

FEAT_RED = ["bytes_sent","bytes_recv","duration","src_port","dst_port","protocol"]
scaler   = MinMaxScaler().fit(df_red[FEAT_RED])
X_sc     = scaler.transform(df_red[FEAT_RED])
model_if = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
model_if.fit(X_sc)

joblib.dump(model_if, MODELS_DIR / "isolation_forest.pkl")
joblib.dump(scaler,   MODELS_DIR / "scaler_red.pkl")
print("  isolation_forest.pkl + scaler_red.pkl  -> OK")

# ── CAP 04: Random Forest + SMOTE ─────────────────────────────────────────────
print("\n=== Cap.04: Random Forest Malware ===")
from sklearn.ensemble import RandomForestClassifier
try:
    from imblearn.over_sampling import SMOTE
    use_smote = True
except ImportError:
    use_smote = False
    print("  (imblearn no disponible, se omite SMOTE)")

rng2 = np.random.default_rng(seed=42)
NB, NM = 1500, 500
MAL_COLS = [
    "entry_point","image_base","size_of_image","size_code_section",
    "dll_flag","num_sections","entropia_max","entropia_media",
    "num_importaciones","num_dlls_importadas","num_exportaciones","file_size",
]

benign = pd.DataFrame({
    "entry_point"        : rng2.integers(0x1000, 0x10000, NB),
    "image_base"         : rng2.choice([0x400000, 0x1000000], NB),
    "size_of_image"      : rng2.integers(50_000, 5_000_000, NB),
    "size_code_section"  : rng2.integers(10_000, 2_000_000, NB),
    "dll_flag"           : rng2.integers(0, 2, NB),
    "num_sections"       : rng2.integers(3, 8, NB),
    "entropia_max"       : rng2.uniform(4.0, 6.5, NB),
    "entropia_media"     : rng2.uniform(3.5, 5.5, NB),
    "num_importaciones"  : rng2.integers(50, 250, NB),
    "num_dlls_importadas": rng2.integers(3, 15, NB),
    "num_exportaciones"  : rng2.integers(0, 50, NB),
    "file_size"          : rng2.integers(10_000, 10_000_000, NB),
    "label": 0,
})
malware = pd.DataFrame({
    "entry_point"        : rng2.integers(0x1000, 0x10000, NM),
    "image_base"         : rng2.choice([0x400000, 0x10000000], NM),
    "size_of_image"      : rng2.integers(10_000, 1_000_000, NM),
    "size_code_section"  : rng2.integers(5_000, 500_000, NM),
    "dll_flag"           : rng2.integers(0, 2, NM),
    "num_sections"       : rng2.integers(1, 12, NM),
    "entropia_max"       : rng2.uniform(7.2, 8.0, NM),
    "entropia_media"     : rng2.uniform(6.5, 7.8, NM),
    "num_importaciones"  : rng2.integers(2, 30, NM),
    "num_dlls_importadas": rng2.integers(1, 5, NM),
    "num_exportaciones"  : rng2.integers(0, 10, NM),
    "file_size"          : rng2.integers(5_000, 500_000, NM),
    "label": 1,
})

df_mal = pd.concat([benign, malware], ignore_index=True)
df_mal.to_csv(DATA_DIR / "file_features.csv", index=False)
print(f"  file_features.csv  -> {len(df_mal):,} filas")

Xm = df_mal[MAL_COLS].values
ym = df_mal["label"].values
if use_smote:
    Xm, ym = SMOTE(random_state=42).fit_resample(Xm, ym)

rf = RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42)
rf.fit(Xm, ym)

joblib.dump(rf,       MODELS_DIR / "random_forest_malware.pkl")
joblib.dump(MAL_COLS, MODELS_DIR / "malware_feature_cols.pkl")
print("  random_forest_malware.pkl + malware_feature_cols.pkl  -> OK")

# ── Verificacion final ────────────────────────────────────────────────────────
print("\n=== Archivos generados ===")
for f in sorted(MODELS_DIR.glob("*.pkl")):
    print(f"  {f}  ({f.stat().st_size/1024:.1f} KB)")
for f in sorted(DATA_DIR.glob("*.csv")):
    print(f"  {f}  ({f.stat().st_size/1024:.1f} KB)")
print("\nListo. Ahora puedes ejecutar el Cap.05 en JupyterLab.")
