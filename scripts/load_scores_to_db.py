import getpass
import pandas as pd
import psycopg

CSV_FILE = "/home/maha/ndr-project/data/final_risk_scores.csv"

DB_HOST = "127.0.0.1"
DB_PORT = 5432
DB_NAME = "ndr_db"
DB_USER = "ndr_writer"


COLUMNS = [
    "flow_key",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "packet_count",
    "min_anomaly_score",
    "auth_success",
    "auth_attempts",
    "client",
    "server",
    "suricata_alerts",
    "suricata_severity",
    "signatures",
    "risk_score",
    "risk_level"
]

print("=== CHARGEMENT DES SCORES NDR VERS POSTGRESQL ===")

df = pd.read_csv(CSV_FILE)

missing = [col for col in COLUMNS if col not in df.columns]

if missing:
    raise ValueError(f"Colonnes manquantes : {missing}")


password = getpass.getpass("Mot de passe ndr_writer : ")

with psycopg.connect(
     host=DB_HOST,
     port=DB_PORT,
     dbname=DB_NAME,
     user=DB_USER,
     password=password
) as conn:

   with conn.cursor() as cur:

      cur.execute("DELETE FROM ndr_events")

      for _, row in df.iterrows():

         values = []

         for column in COLUMNS:
             value = row[column]

             if pd.isna(value):
                 value = None

             elif column in [
                 "src_port",
                 "dst_port",
                 "packet_count",
                 "suricata_alerts",
                 "suricata_severity",
                 "risk_score"
             ]:
                 value = int(value)

             values.append(value)
         cur.execute(
             """
              INSERT INTO ndr_events (
                  flow_key,
                  src_ip,
                  src_port,
                  dst_ip,
                  dst_port,
                  packet_count,
                  min_anomaly_score,
                  auth_success,
                  auth_attempts,
                  client,
                  server,
                  suricata_alerts,
                  suricata_severity,
                  signatures,
                  risk_score,
                  risk_level
              )
              VALUES (
                 %s, %s, %s, %s,
                 %s, %s, %s, %s,
                 %s, %s, %s, %s,
                 %s, %s, %s, %s
              )
              """,
              values
          )

print(f"{len(df)} evenement(s) cherge(s) dans PostgresSQL.")
print("=== CHARGEMENT TERMINE ===")

