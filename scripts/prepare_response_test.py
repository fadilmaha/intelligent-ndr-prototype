import pandas as pd 

path = "/home/maha/ndr-project/data/final_risk_scores.csv"


df = pd.read_csv(path)

test_eleve = df.iloc[0].copy()
test_eleve["flow_key"] = "TEST_ELEVE"
test_eleve["src_ip"] = "10.10.10.60"
test_eleve["risk_score"] = 60
test_eleve["risk_level"] = "ELEVE"

test_critique = df.iloc[0].copy()
test_critique["flow_key"] = "TEST_CRITIQUE"
test_critique["src_ip"] = "10.10.10.85"
test_critique["risk_score"] = 85
test_critique["risk_level"] = "CRITIQUE"


df = pd.concat(
     [df, pd.DataFrame([test_eleve, test_critique])],
     ignore_index=True
)

df.to_csv(path, index=False)

print(
    df[
        ["flow_key", "src_ip", "risk_score", "risk_level"]
     ]
)


