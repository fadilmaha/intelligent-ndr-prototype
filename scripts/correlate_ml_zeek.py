import pandas as pd 

ML_FILE = "/home/maha/ndr-project/data/detection_results_enriched.csv"
ZEEK_FILE = "/home/maha/ndr-project/data/zeek_ssh.tsv"
OUTPUT_FILE = "/home/maha/ndr-project/data/correlation_ml_zeek.csv"

ml = pd.read_csv(ML_FILE)

zeek_columns = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "version",
    "auth_success",
    "auth_attempts",
    "client",
    "server",
]

zeek = pd.read_csv(
    ZEEK_FILE,
    sep="\t",
    header=None,
    names=zeek_columns
)

ml["tcp.srcport"] = pd.to_numeric(
     ml["tcp.srcport"],
     errors="coerce"
).fillna(-1).astype(int)

ml["tcp.dstport"] = pd.to_numeric(
    ml["tcp.dstport"],
    errors="coerce"
).fillna(-1).astype(int)

zeek["id.orig_p"] = pd.to_numeric(
    zeek["id.orig_p"],
    errors="coerce"
).fillna(-1).astype(int)

zeek["id.resp_p"] = pd.to_numeric(
    zeek["id.resp_p"],
    errors="coerce"
).fillna(-1).astype(int)

ml["src_endpoint"] = (
    ml["ip.src"].astype(str)
    + ":"
    + ml["tcp.srcport"].astype(str)
)

ml["dst_endpoint"] = (
    ml["ip.dst"].astype(str)
    + ":"
    + ml["tcp.dstport"].astype(str)
)

ml["flow_key"] = ml.apply(
    lambda row: "|".join(
       sorted([
          str(row["src_endpoint"]),
          str(row["dst_endpoint"])
       ])
    ),
    axis=1
)

zeek["orig_endpoint"] = (
    zeek["id.orig_h"].astype(str)
    + ":"
    + zeek["id.orig_p"].astype(str)
)

zeek["resp_endpoint"] = (
    zeek["id.resp_h"].astype(str)
    + ":"
    + zeek["id.resp_p"].astype(str)
)

zeek["flow_key"] = zeek.apply(
    lambda row: "|".join(
        sorted([
           str(row["orig_endpoint"]),
           str(row["resp_endpoint"])
        ])
    ),
    axis=1
)

anomalies = ml[
    ml['prediction'] == -1
].copy()

correlation = anomalies.merge(
    zeek,
    on="flow_key",
    how="left"
)

ssh_correlated = correlation[
    correlation["uid"].notna()
].copy()

print("=== CORRELATION ML + ZEEK ===")

print(
    "Nombre total d'anomalies ML :",
    len(anomalies)
)

print(
    "Anomalies correlees avec SSH Zeek :",
    len(ssh_correlated)
)

print("\n=== EVENEMENTS CORRELES ===")

print(
    ssh_correlated[
        [
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "anomaly_score",
            "auth_success",
            "auth_attempts",
            "client",
            "server",
        ]
    ]
)

ssh_correlated.to_csv(
    OUTPUT_FILE,
    index=False
)

print(
    "\nCorrelation sauvegardee dans :",
    OUTPUT_FILE
)

