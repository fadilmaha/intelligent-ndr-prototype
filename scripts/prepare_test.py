
import pandas as pd 

INPUT_FILE = "/home/maha/ndr-project/data/test_data.csv"
OUTPUT_FILE = "/home/maha/ndr-project/data/prepared_test.csv"

df = pd.read_csv(INPUT_FILE)

print("=== PREPARATION DU TRAFFIC DE TEST ===")
print("Nombre de paquets :", len(df))

port_columns = [ 
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
]

for column in port_columns:
    df[column] = pd.to_numeric(
        df[column],
        errors="coerce"
   ).fillna(0)

df["timestamp"] = pd.to_numeric(
    df["frame.time_epoch"],
    errors="coerce"

)

df["time_delta"] = df["timestamp"].diff().fillna(0)

df["is_tcp"] = (df["_ws.col.protocol"] =="TCP").astype(int)
df["is_udp"] = (df["_ws.col.protocol"] == "UDP").astype(int)
df["is_icmp"] = (df["_ws.col.protocol"] == "ICMP").astype(int)
df["is_arp"] = (df["_ws.col.protocol"] == "ARP").astype(int)
df["is_ssh"] = (df["_ws.col.protocol"] == "SSH").astype(int)

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

test_data = df[features].copy()

test_data.to_csv(OUTPUT_FILE, index=False)

print("Dimensions du dataset de test :", test_data.shape)
print("valeurs manquantes :", test_data.isnull().sum().sum())
print("Dataset sauvegarde dans :", OUTPUT_FILE)




