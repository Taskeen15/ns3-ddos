#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="results/icmp-flood"

./ns3 build
mkdir -p "$OUTPUT_DIR"

./ns3 run "scratch/icmp-flood-ddos \
  --outputDir=$OUTPUT_DIR \
  --nLegitClients=3 \
  --nAttackers=10 \
  --accessRate=100Mbps \
  --accessDelay=1ms \
  --bottleneckRate=10Mbps \
  --bottleneckDelay=10ms \
  --legitTcpType=ns3::TcpNewReno \
  --legitDataRate=6Mbps \
  --legitSendSize=1200 \
  --legitPort=5000 \
  --icmpPpsPerAttacker=700 \
  --icmpPayloadSize=512 \
  --attackStartJitterMax=0.20 \
  --attackRateJitterFrac=0.05 \
  --attackStart=6.0 \
  --attackStop=14.0 \
  --simStop=20.0 \
  --sampleInterval=0.1 \
  --enablePcap=1 \
  --enableFlowMonitor=1"

python3 utils/plot_icmp_flood.py "$OUTPUT_DIR"

echo "Done. Check $OUTPUT_DIR for CSV, PCAP, XML, and PNG files."