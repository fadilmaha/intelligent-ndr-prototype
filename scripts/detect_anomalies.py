import pandas as pd
import joblib

MODEL_FILE = "/home/maha/ndr-project/models/isolation_forest.pkl"
TEST_FILE = "/home/maha/ndr-project/data/prepared_test.csv"
RAW_TEST_FILE = "/home/maha/ndr-project/data/test_data.csv"

OUTPUT_FILE = "/home/maha/ndr-project/data/detection_results_enriched.csv"
model = joblib.load(MODEL_FILE)

df = pd.read_csv(TEST_FILE)

raw_df = pd.read_csv(RAW_TEST_FILE)

print("=== DETECTION DES ANOMALIES SUR LE TRAFFIC DE TEST ===")
print("Dimensions du dataset :", df.shape)

predictions = model.predict(df)

scores = model.decision_function(df)

df["prediction"] = predictions
df["anomaly_score"] = scores

context_columns = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "_ws.col.protocol"
]
context = raw_df[context_columns].copy()

results = pd.concat(
    [
        context.reset_index(drop=True),
        df.reset_index(drop=True),
    ],
    axis=1
)

normal_count = (df["prediction"] == 1).sum()
anomaly_count = (df["prediction"] == -1).sum()

print("\nNombre de paquets normaux :", normal_count)
print("Nombre de paquets anormaux :", anomaly_count)

print("\nPourcentage d'anomalies :")
print(round((anomaly_count / len(df)) / 0.01, 2), "%")

print("\n=== ANOMALIES LES PLUS FORTES ===")

anomalies = results[
    results["prediction"] == -1
].sort_values("anomaly_score")

print(
    anomalies[
        [
             "frame.time_epoch",
             "ip.src",
             "ip.dst",
             "_ws.col.protocol",
             "frame.len",
             "tcp.srcport",
             "tcp.dstport",
             "prediction",
             "anomaly_score"
        ]
      ].head(15)
)

results.to_csv(OUTPUT_FILE, index=False)


print("\nResultats sauvegardes dans :", OUTPUT_FILE)

