# Inteligencia Artificial en Ciberseguridad

**Guia Tecnica con Python** | IX Ciclo — Seguridad Informatica | Mayo 2026

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15-FF6F00?style=flat-square&logo=tensorflow&logoColor=white)
![Jupyter](https://img.shields.io/badge/JupyterLab-4.x-F37626?style=flat-square&logo=jupyter&logoColor=white)
![SHAP](https://img.shields.io/badge/SHAP-0.45-6C3483?style=flat-square)
![License](https://img.shields.io/badge/Uso-Academico-2E86C1?style=flat-square)

---

## ◈  Descripcion general

Serie de **10 notebooks interactivos** que construyen un sistema de seguridad con IA completo,
desde la deteccion de anomalias de red hasta un pipeline integrado de respuesta automatica a incidentes.
Cada capitulo genera datos, entrena modelos y los persiste para que el siguiente los reutilice.

---

## ◈  Estructura del proyecto

```
IACIBERSEGURIDAD/
  ├─ notebooks/            ◂ Cuadernos Jupyter (Cap. 01 al 11)
  ├─ models/               ◂ Modelos entrenados (.pkl)
  ├─ data/                 ◂ Datasets y graficos generados
  ├─ src/                  ◂ PDF guia tecnica
  ├─ env/                  ◂ Entorno virtual Python
  ├─ generar_modelos.py    ◂ Genera todos los .pkl sin Jupyter
  ├─ activar_entorno.ps1   ◂ Activa venv y lanza JupyterLab
  └─ requirements.txt      ◂ Dependencias del proyecto
```

---

## ◈  Cadena de dependencias

```
  Cap 01  Setup y configuracion
      │
      ├──▶  Cap 03  Deteccion de amenazas de red
      │         generates ▸ network_traffic.csv
      │         saves     ▸ isolation_forest.pkl  scaler_red.pkl
      │
      ├──▶  Cap 04  Deteccion de malware
      │         generates ▸ file_features.csv
      │         saves     ▸ random_forest_malware.pkl  malware_feature_cols.pkl
      │
      ├──▶  Cap 05  Respuesta a incidentes (SOAR)
      │         loads     ▸ Cap 03 + Cap 04
      │         generates ▸ incident_data.csv
      │         saves     ▸ svm_severity.pkl
      │
      ├──▶  Cap 06  Analisis de comportamiento (UBA)
      │         generates ▸ user_activity_logs.csv
      │         saves     ▸ user_profiles.pkl
      │
      ├──▶  Cap 07  Explicabilidad XAI / SHAP       ← carga Cap 04
      ├──▶  Cap 08  Ataques adversariales            ← carga Cap 04
      ├──▶  Cap 09  Desafios y buenas practicas      ← carga Cap 04 y 05
      │
      ├──▶  Cap 10  Pipeline integrado               ← carga TODOS
      │         saves ▸ pipeline_seguridad.pkl
      │
      └──▶  Cap 11  Resumen y verificacion final
```

---

## ◈  Notebooks

| ▸ | Nombre | Tecnica principal | Salida |
|---|--------|-------------------|--------|
| 01 | Configuracion del entorno | venv, pip, verificacion de imports | — |
| 03 | Deteccion de amenazas de red | Isolation Forest · Autoencoder | isolation_forest.pkl |
| 04 | Deteccion de malware | Decision Tree · Random Forest · SMOTE | random_forest_malware.pkl |
| 05 | Respuesta a incidentes | SVM RBF · Motor SOAR | svm_severity.pkl |
| 06 | Comportamiento de usuarios UBA | Perfiles estadisticos · Z-score | user_profiles.pkl |
| 07 | Explicabilidad XAI | SHAP TreeExplainer · waterfall · summary | shap_*.png |
| 08 | Ataques adversariales | Ruido gaussiano · ataque dirigido · defensa | adversarial_resultados.png |
| 09 | Desafios y buenas practicas | Test KS · monitoreo de drift · ROC/PR | drift_resultados.png |
| 10 | Pipeline integrado | PipelineSeguridad end-to-end | pipeline_seguridad.pkl |
| 11 | Resumen y perspectivas | Verificacion final · roadmap | — |

---

## ◈  Modelos persistidos  `models/`

| Archivo | Cap | Tecnica | Tamano |
|---------|-----|---------|--------|
| `isolation_forest.pkl` | 03 | Isolation Forest · 200 estimadores · contamination=0.05 | ~2.4 MB |
| `scaler_red.pkl` | 03 | MinMaxScaler sobre 6 features de red | 1 KB |
| `random_forest_malware.pkl` | 04 | Random Forest · 300 arboles · SMOTE | ~216 KB |
| `malware_feature_cols.pkl` | 04 | Lista de 12 features PE extraidas con pefile | 1 KB |
| `svm_severity.pkl` | 05 | Pipeline StandardScaler + SVC kernel RBF | — |
| `user_profiles.pkl` | 06 | Dict {usuario → {metrica → {mean, std}}} | — |
| `pipeline_seguridad.pkl` | 10 | PipelineSeguridad con todos los modelos | — |

---

## ◈  Datasets sinteticos  `data/`

| Archivo | Cap | Filas | Descripcion |
|---------|-----|-------|-------------|
| `network_traffic.csv` | 03 | 5 000 | 4 750 normal + 250 anomalos (exfiltracion · scan · C2) |
| `file_features.csv` | 04 | 2 000 | 1 500 benignos + 500 maliciosos (entropia_max > 7.2 bits) |
| `incident_data.csv` | 05 | 1 200 | Senales IF+RF + contexto sintetico + etiqueta severidad |
| `user_activity_logs.csv` | 06 | ~18 000 | Actividad de 15 usuarios durante 60 dias |

---

## ◈  Graficos generados  `data/`

| Imagen | Cap | Contenido |
|--------|-----|-----------|
| `incident_eda.png` | 05 | Distribucion de severidad · cruce anomalia × malware · bytes exfiltrados |
| `svm_resultados.png` | 05 | Matriz de confusion SVM · probabilidades para incidente de prueba |
| `uba_resultados.png` | 06 | Heatmap Z-score por usuario · histograma bytes_sent con umbral de alerta |
| `shap_summary.png` | 07 | Dot plot global: importancia y direccion de cada feature |
| `shap_bar.png` | 07 | Ranking importancia media |SHAP| por feature |
| `shap_waterfall.png` | 07 | Explicacion local: contribucion por feature en muestra maliciosa vs benigna |
| `shap_vs_rf.png` | 07 | Comparacion SHAP vs feature_importances_ nativo del RF |
| `adversarial_resultados.png` | 08 | Tasa de evasion vs epsilon · accuracy original vs modelo robusto |
| `drift_resultados.png` | 09 | Heatmap KS por ventana/feature · distribucion con drift severo |
| `monitoreo_produccion.png` | 09 | Degradacion semanal de accuracy · precision · recall · F1 |
| `fp_tradeoff.png` | 09 | Curvas ROC y Precision-Recall para deteccion de Criticos |
| `pipeline_dashboard.png` | 10 | Dashboard 4 escenarios: severidad · probabilidades · senales · acciones |

---

## ◈  Resultados por capitulo

#### ▸ Cap 03 — Deteccion de amenazas de red
- Isolation Forest detecta exfiltracion (bytes_sent > 5M), escaneo (duracion < 0.5s) y C2 (puertos 4444/1337/31337)
- Autoencoder `6→16→8→16→6` entrenado solo con trafico normal; umbral en percentil 95 del MSE

#### ▸ Cap 04 — Deteccion de malware
- Feature mas discriminativa: `entropia_max` — benigno: 4.0–6.5 bits | malware: 7.2–8.0 bits
- Random Forest 300 arboles + SMOTE logra alta precision con desbalance 3:1

#### ▸ Cap 05 — Respuesta a incidentes
- Score de severidad: `anomalia_red×2 + malware×2 + priv + (hosts>10) + (exfil>1M)`
- SVM RBF clasifica 4 niveles: Bajo · Medio · Alto · Critico
- Motor SOAR: Critico → aislar sistema + bloquear IP + notificar equipo

#### ▸ Cap 06 — Analisis de comportamiento UBA
- Perfil por usuario: µ y σ de hora_login, bytes_sent, failed_logins, num_accesos_dia
- Z-score umbral 3σ: acceso 3AM + 8M bytes + 8 logins fallidos → alerta en 3/4 metricas

#### ▸ Cap 07 — Explicabilidad SHAP
- `entropia_max` y `entropia_media` dominan la prediccion de malware
- Waterfall muestra como cada feature desplaza f(x) desde el valor base E[f(x)]

#### ▸ Cap 08 — Robustez adversarial
- Ataque gaussiano ε=0.40: tasa de evasion ~60% sobre el modelo original
- Defensa por entrenamiento adversarial reduce la evasion ~40% bajo ε=0.10

#### ▸ Cap 09 — Buenas practicas
- Test KS detecta drift severo (p < 0.05) en Semana 3 para `bytes_sent`
- F1 cae bajo 0.80 en semana 8 → umbral de reentrenamiento automatico
- ROC-AUC > 0.95 para clasificacion binaria Critico vs resto

#### ▸ Cap 10 — Pipeline integrado
- `PipelineSeguridad.analizar()` encadena IF + RF + SVM + UBA en una sola llamada
- Escenario Critico: 9M bytes · 45 hosts · privilegios elevados → AISLAR + BLOQUEAR + NOTIFICAR

---

## ◈  Inicio rapido

```powershell
# 1. Activar entorno virtual y abrir JupyterLab
.\activar_entorno.ps1

# 2. Generar todos los modelos desde cero (sin Jupyter)
.\env\Scripts\python.exe generar_modelos.py

# 3. Ejecutar notebooks en orden
# 01 → 03 → 04 → 05 → 06 → 07 → 08 → 09 → 10 → 11
```

---

## ◈  Dependencias principales

![scikit-learn](https://img.shields.io/badge/scikit--learn-%3E%3D1.4-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)
![TensorFlow](https://img.shields.io/badge/TensorFlow-%3E%3D2.15-FF6F00?style=flat-square&logo=tensorflow&logoColor=white)
![pandas](https://img.shields.io/badge/pandas-%3E%3D2.0-150458?style=flat-square&logo=pandas&logoColor=white)
![NumPy](https://img.shields.io/badge/NumPy-%3E%3D1.26-013243?style=flat-square&logo=numpy&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-%3E%3D3.8-11557C?style=flat-square)
![SciPy](https://img.shields.io/badge/SciPy-%3E%3D1.12-8CAAE6?style=flat-square&logo=scipy&logoColor=white)

| Libreria | Version | Uso |
|----------|---------|-----|
| scikit-learn | >= 1.4 | IF · SVM · RF · pipelines · metricas |
| tensorflow / keras | >= 2.15 | Autoencoder (Cap 03) |
| shap | >= 0.45 | Explicabilidad XAI (Cap 07) |
| imbalanced-learn | >= 0.12 | SMOTE (Cap 04) |
| pandas / numpy | >= 2.0 / 1.26 | Manipulacion de datos |
| matplotlib | >= 3.8 | Visualizaciones |
| scipy | >= 1.12 | Test Kolmogorov-Smirnov (Cap 09) |
| joblib | >= 1.3 | Persistencia de modelos |

---

*IX Ciclo — Seguridad Informatica · Mayo 2026*