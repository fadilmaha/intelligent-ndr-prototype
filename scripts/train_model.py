import joblib 
import pandas as pd
from sklearn.ensemble import IsolationForest 

DATA_FILE = "/home/maha/ndr-project/data/prepared_data.csv"

df = pd.read_csv(DATA_FILE)

print("===ENTRAINEMENT DU ;ODELE NDR ===")
print("Dimensions du dataset :", df.shape)

model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

model.fit(df)

print("Modele Isolation Forest entraine avec succes.")

print("Modele Isolation Forest entraine avec succes.")

predictions = model.predict(df)

scores = model.decision_function(df)

df["prediction"] = predictions 
df["anomaly_score"] = scores

print("\n=== RESULTATS DE LA DETECTION ===")

print("Nombre de paquets normaux :", (df["prediction"] == 1).sum())
print("Nombre de paquets anormaux :", (df["prediction"] == -1).sum())

print("\nPaquets detectes comme anormaux :")
print(df[df["prediction"] == -1])

MODEL_FILE = "/home/maha/ndr-project/models/isolation_forest.pkl"

joblib.dump(model, MODEL_FILE)

print("\nModele sauvegarde dans :", MODEL_FILE)

