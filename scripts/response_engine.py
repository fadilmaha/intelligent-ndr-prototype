from datetime import datetime
import ipaddress 
import os
import subprocess 
import pandas as pd 

INPUT_FILE = "/home/maha/ndr-project/data/final_risk_scores.csv"
LOG_FILE = "/home/maha/ndr-project/logs/response/response_actions.log"

MODE = "DRY_RUN"


WHITELIST = {
     "192.168.174.1",
     "192.168.174.10",
     "127.0.0.1"
}


def can_block(ip):
    if ip in WHITELIST:
        return False 
    try:
       address = ipaddress.ip_address(ip)
       return address.is_private
    except ValueError:
       return False 



def block_ip(ip):
    if MODE == "DRY_RUN":
        return f"DRY-RUN - blocage propose pour {ip}"

    if os.geteuid() != 0:
        return "ERREUR - ;ode ENFORCE necessite sudo"


    check = subprocess.run(
        ["/usr/sbin/iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if check.returncode == 0:
         return f"DEJA BLOQUE - {ip}"


    subprocess.run(
        ["/usr/sbin/iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        check=True
    )

    return f"BLOQUE - {ip}"


print(f"=== MOTEUR DE REPONSE NDR - MODE {MODE} ===")

df = pd.read_csv(INPUT_FILE)
for _, row in df.iterrows():

    src_ip = str(row["src_ip"])
    risk_score = int(row["risk_score"])
    risk_level = str(row["risk_level"]).upper()

    if src_ip in WHITELIST:
        action = "WHITELIST - aucune action"

    elif risk_score >= 75 or risk_level == "CRITIQUE":

        if can_block(src_ip):
            action = block_ip(src_ip)
        else:
            action = "BLOCAGE REFUSE - IP non autorisee"

    elif risk_score >= 50 or risk_level == "ELEVE":
        action = f"ALERTE - surveillance renforcee de {src_ip}"

    else:
        action = "Aucune action"

    message = (
        f"{datetime.now()} | "
        f"IP={src_ip} | "
        f"score={risk_score} | "
        f"niveau={risk_level} | "
        f"action={action}"
    )

    print(message)

    with open(LOG_FILE, "a") as log:
        log.write(message + "\n")


print("\n=== FIN DU MOTEUR DE REPONSE ===")
print("journal :", LOG_FILE)


