import pandas as pd 
import json 
import os

CORR_FILE = "/home/maha/ndr-project/data/correlation_ml_zeek.csv"
SURICATA_FILE = "/home/maha/ndr-project/data/suricata_real_alerts.jsonl"
OUTPUT_FILE = "/home/maha/ndr-project/data/final_risk_scores.csv"

corr = pd.read_csv(CORR_FILE)

print("=== MOTEUR DE SCORING NDR ===")
print("Lignes ML + Zeek :", len(corr))

corr["anomaly_score"] = pd.to_numeric(
    corr["anomaly_score"],
    errors="coerce"
)

corr["auth_attempts"] = pd.to_numeric(
    corr["auth_attempts"],
    errors="coerce"
).fillna(0)

def first_valid(series):
    for value in series:
        if pd.notna(value):
            value = str(value)


            if value not in ["-", "", "nan"]:
                return value 
 
    return "-"


flows = corr.groupby(
    "flow_key",
    as_index=False
).agg(
    src_ip=("id.orig_h", first_valid),
    src_port=("id.orig_p", first_valid),
    dst_ip=("id.resp_h", first_valid),
    dst_port=("id.resp_p", first_valid),

    packet_count=("prediction", "size"),
    
    min_anomaly_score=("anomaly_score", "min"),

    auth_success=("auth_success", first_valid),
    auth_attempts=("auth_attempts", "max"),

    client=("client", first_valid),
    server=("server", first_valid),
)

print("Connexions uniques :", len(flows))

suricata_events = []

def make_flow_key(src_ip, src_port, dst_ip, dst_port):

    try:
        src_port = int(src_port)
    except:
        src_port = -1
    try:
       dst_port = int(dst_port)
    except:
       dst_port = -1

    endpoint1 = str(src_ip) + ":" + str(src_port)
    endpoint2 = str(dst_ip) + ":" + str(dst_port)


    return "|" .join(
        sorted([
            endpoint1,
            endpoint2
        ])
    )


if (
   os.path.exists(SURICATA_FILE)
   and os.path.getsize(SURICATA_FILE) > 0
): 

   with open(SURICATA_FILE, "r") as file:

       for line in file:
           line = line.strip()
           if not line:
               continue
           event = json.loads(line)

           flow_key = make_flow_key(
               event.get("src.ip"),
               event.get("src_port"),
               event.get("dest_ip"),
               event.get("dest_port")
           )

           alert = event.get("alert", {})

           suricata_events.append({
                "flow_key": flow_key,
                "signature": alert.get(
                    "signature:",
                     "Unknown",
                ),
                "severity": alert.get("severity")
           })

if len(suricata_events) > 0:
   suricata_df = pd.DataFrame(
       suricata_events
   )

   suricata_summary = suricata_df.groupby(
       "flow_key",
       as_index=False
   ).agg(
       suricata_alerts=("signature", "size"),
       suricata_severity=("severity", "min"),
       signatures=( 
           "signature",
           lambda x: "; ",join(
               sorted(set(x))
           )
       )
   )

   flows = flows.merge(
       suricata_summary,
       on="flow_key",
       how="left"
   )


else: 
    
    flows["suricata_alerts"] = 0
    flows["suricata_severity"] = pd.NA
    flows["signatures"] = "-"

flows["suricata_alerts"] = (
    flows["suricata_alerts"]
    .fillna(0)
    .astype(int)
)

flows["signatures"] = (
    flows["signatures"]
    .fillna("-")
)

def calculate_risk(row):
    score = 15 

    anomaly = row["min_anomaly_score"]

    if anomaly <= -0.10:
        score += 15
    elif anomaly <= -0.05:
        score += 10
    else:
        score += 5 

    auth = str(row["auth_success"]).upper()
    attempts = row["auth_attempts"]

    if auth == "F" or attempts >=3:
        score += 20
    elif auth == "T" and attempts <= 1:
        score -= 10 

    if row["suricata_alerts"] > 0:
        score += 40

        severity = row["suricata_severity"]

        if pd.notna(severity):
            if severity == 1:
                score += 10
            elif severity == 2:
                score += 5
    return max(0, min(100, score))

flows["risk_score"] = flows.apply(
    calculate_risk,
    axis=1
)

def risk_level(score):
    if score < 25:
        return "FAIBLE"
    elif score < 50:
        return "MOYEN"
    elif score < 75:
        return "ELEVE"
    else:
        return "CRITIQUE"


flows["risk_level"] = flows["risk_score"].apply(risk_level)

print("\n=== RESULTATS DU SCORING ===")

for _, row in flows.iterrows():
    print("\n--------------")

    print("Connexion :",
           row["src_ip"],
           ":",
           row["src_port"],
           "->",
           row["dst_ip"],
           ":",
           row["dst_port"]
    )

    print(
        "Paquets ML correles :",
         row["packet_count"]
    )

    print(
         "Score anomlie ML :",
          row["min_anomaly_score"]
    )

    print(
         "Authentification SSH :",
          row["auth_success"]
    )

    print(
         "Tentatives SSH :",
          row["auth_attempts"]
    )

    print(
        "Alertes Suricata :",
         row["suricata_alerts"]
    )

    print(
         "Score de risque :",
         row["risk_score"],
        "/ 100"
    )

    print(
         "Niveau:",
         row["risk_level"]
    )

flows.to_csv(
   OUTPUT_FILE,
   index=False
)

print(
    "\nResultats sauvegardes dans :",
    OUTPUT_FILE
) 

