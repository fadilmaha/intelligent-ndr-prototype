#!/bin/bash

set -e

PROJECT="/home/maha/ndr-project"
PYTHON="$PROJECT/venv/bin/python"


echo "========================================"
echo "         PIPELINE NDR AUTOMATISE"
echo "========================================"

echo ""
echo "[1/6] Preparation des donnees de test..."
$PYTHON "$PROJECT/scripts/prepare_test.py"


echo ""
echo "[2/6] Detection des anomalies..."
$PYTHON "$PROJECT/scripts/detect_anomalies.py"

echo ""
echo "[3/6] Correlation ML + Zeek..."
$PYTHON "$PROJECT/scripts/correlate_ml_zeek.py"

echo ""
echo "[4/6] Calcul du score de risque..."
$PYTHON "$PROJECT/scripts/risk_scoring.py"

echo ""
echo "[5/6] Chargement vers PostgreSQL..."
$PYTHON "$PROJECT/scripts/load_scores_to_db.py"

echo ""
echo "[6/6] Moteur de rponse..."
$PYTHON "$PROJECT/scripts/response_engine.py"

echo ""
echo "========================================"
echo "          PIPELINE NDR TERMINE"
echo "========================================"
