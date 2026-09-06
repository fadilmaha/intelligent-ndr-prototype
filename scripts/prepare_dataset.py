import pandas as pd 
import numpy as np 

INPUT_FILE = "training_data.csv"
OUTPUT_FILE = "prepared_data.csv"

df = pd.read_csv(INPUT_FILE)

print("=== PREPARATION DU DATASET NDR ===")
print("Nombre de paquets :", len(df))
print("Nombre de colonnes :", len(df.columns))

print("\nColonnes disponible :")
print(df.columns.tolist())

print("\n=== NETTOYAGE DES DONNEES ===")

print("\nVleurs manquantes avant traitememt :")
print(df.isnull().sum())

port_columns = [
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport"
]

for column in port_columns:
    df[column] = df[column].fillna(0)

ip_columns = [ 
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst"
]

for column in ip_columns:
    df[column] = df[column].fillna("N/A")

before = len(df)
df = df.drop_duplicates()
after = len(df)

print("\nDoublons supprimes :", before - after)

print("\nValeurs manquantes apres traitement :")
print(df.isnull().sum())

print("\nNombre de paquets apres nettoyage :", len(df))

print("\n=== FEATURE ENGINEERING ===")

df["timestamp"] = pd.to_numeric(
    df["frame.time_epoch"],
    errors="coerce"
)

df["time_delta"] = df["timestamp"].diff().fillna(0)

df["is_tcp"] = (df["_ws.col.protocol"] == "TCP").astype(int)
df["is_udp"] = (df["_ws.col.protocol"] == "UDP").astype(int)
df["is_icmp"] = (df["_ws.col.protocol"] == "ICMP").astype(int)
df["is_arp"] = (df["_ws.col.protocol"] == "ARP").astype(int)
df["is_ssh"] = (df["_ws.col.protocol"] == "SSH").astype(int)

print("\nNouvelles features creees :")
print(
   df[
       [
         "timestamp",
         "time_delta",
         "frame.len",
         "is_tcp",
         "is_udp",
         "is_icmp",
         "is_arp",
         "is_ssh"
       ]
    ].head(15)
) 

print("\n=== PREPARATION DES FEATURES DU MODELE ===")

port_columns = [ 
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
]

for column in port_columns:
    df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0)
features = [
    "time_delta",
    "frame.len",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "is_tcp",
    "is_udp",
    "is_icmp",
    "is_arp",
    "is_ssh",
]

model_data = df[features].copy()

print("\nFeatures selectionnes :")
print(model_data.columns.tolist())

print("\nDimensions du dataset final :")
print(model_data.shape)

print("\nApercu du dataset final :")
print(model_data.head(15))

print("\nValeurs manquantes dans le dataset final :")
print(model_data.isnull().sum())

OUTPUT_FILE = "/home/maha/ndr-project/data/prepared_data.csv"

model_data.to_csv(OUTPUT_FILE, index=False)

print("\n=== SAUVEGARDE ===")
print("Dataset prepare sauvegarde dans :", OUTPUT_FILE)
print("Dimensions :", model_data.shape)

