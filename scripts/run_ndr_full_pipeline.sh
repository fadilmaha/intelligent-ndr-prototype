#!/bin/bash

set -e

PROJECT="/home/maha/ndr-project"
PCAP="$PROJECT/captures/test_traffic.pcap"


echo "===================================="
echo "           PIPELINE NDR COMPLET"
echo "===================================="


if [ ! -f "$PCAP" ]; then
    echo "ERREUR : PCAP introuvable : $PCAP"
    exit 1
fi


echo "PCAP trouve : $PCAP"

echo ""
echo "[1] Extraction TShark..."

TEST_DATA="$PROJECT/data/test_data.csv"
TMP_DATA="$PROJECT/data/test_data_auto.tmp.csv"

tshark -r "$PCAP" \
-T fields \
-E header=y \
-E separator=, \
-E quote=d \
-e frame.time_epoch \
-e ip.src \
-e ip.dst \
-e ipv6.src \
-e ipv6.dst \
-e _ws.col.protocol \
-e frame.len \
-e tcp.srcport \
-e tcp.dstport \
-e udp.srcport \
-e udp.dstport \
> "$TMP_DATA"


if [ ! -s "$TMP_DATA" ]; then
    echo "ERREUR : extraction TShark vide."
    exit 1 

fi

mv "$TMP_DATA" "$TEST_DATA"

echo "TShark termine : $TEST_DATA"

echo ""
echo "[2] Analyse Zeek..."

ZEEK_DIR="$PROJECT/logs/zeek_auto"
ZEEK_SSH="$PROJECT/data/zeek_ssh.tsv"

rm -rf "$ZEEK_DIR"
mkdir -p "$ZEEK_DIR"


(

   cd "$ZEEK_DIR"
   /opt/zeek/bin/zeek -C -r "$PCAP"
)

if [ ! -f "$ZEEK_DIR/ssh.log" ]; then
    echo "ERREUR : Zeek n'a pas genere ssh.log"
    exit 1
fi

/opt/zeek/bin/zeek-cut \
ts \
uid \
id.orig_h \
id.orig_p \
id.resp_h \
id.resp_p \
version \
auth_success \
auth_attempts \
client \
server \
< "$ZEEK_DIR/ssh.log" \
> "$ZEEK_SSH"

echo "Zeek termine : $ZEEK_SSH"


echo ""
echo "[3] Analyse Suricata..."

SURICATA_DIR="$PROJECT/logs/suricata_auto"
SURICATA_REAL="$PROJECT/data/suricata_real_alerts.jsonl"

rm -rf "$SURICATA_DIR"
mkdir -p "$SURICATA_DIR"

sudo /usr/bin/suricata \
-r "$PCAP" \
-l "$SURICATA_DIR" \
-k none

if [ ! -f "$SURICATA_DIR/eve.json" ]; then
    echo "ERREUR : Suricata n'a pas genere eve.json"
    exit 1
fi

jq -c 'select(.event_type == "alert") | select((.alert.signature // "") | test("invalid checksum"; "i") | not)' "$SURICATA_DIR/eve.json" > "$SURICATA_REAL"

echo "Suricata termine : $SURICATA_REAL"
echo "Alertes reelles Suricata : $(wc -l < "$SURICATA_REAL")"


echo ""
echo "[4] Pipeline analytique NDR..."

if ! grep -q '^MODE = "DRY_RUN"' "$PROJECT/scripts/response_engine.py"; then
     echo "ERREUR : response_engine.py doit etre en mode DRY_RUN."
     exit 1
fi 

bash "$PROJECT/scripts/run_ndr_pipeline.sh"

echo ""
echo "====================================="
echo "       PIPELINE NDR COMPLET TERMINE"
echo "======================================"

