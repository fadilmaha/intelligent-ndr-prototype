

import pandas as pd 
CSV_FILE= "/home/maha/ndr-project/data/network_data.csv"
df = pd.read_csv(CSV_FILE)

print("=== NDR - Analyse du traffic reseau ===")
print(f"Nombre total de paquets : {len(df)}")

print("\nColonnes disponibles :")
print(df.columns.tolist())

print("\nPremiers paquets :")
print(df.head())

print("\n=== Repartition des  protocoles ===")
print(df["_ws.col.protocol"].value_counts())

print("\n=== Statistiques sur la taille des paquets ===")
print(df["frame.len"].describe())

print("\n=== Feature Engineering ===")

df["timestamp"] = pd.to_numeric(
    df["frame.time_epoch"],
    errors="coerce"
)

df["time_delta"] = df["timestamp"].diff().fillna(0)

df["is_icmp"] = (
    df["_ws.col.protocol"] == "ICMP"
).astype(int)

df["is_arp"] = (
    df["_ws.col.protocol"] == "ARP" 
).astype(int)

print(
    df[
       [
          "timestamp",
          "time_delta", 
          "frame.len",
          "is_icmp",
          "is_arp"
        ]
       ]
)

