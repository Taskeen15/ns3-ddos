#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="results/udp-flood"

./ns3 build
mkdir -p "$OUTPUT_DIR"

./ns3 run "scratch/udp-flood-ddos \
  --outputDir=$OUTPUT_DIR \
  --nLegitClients=4 \
  --nAttackers=8 \
  --accessRate=100Mbps \
  --accessDelay=1ms \
  --bottleneckRate=10Mbps \
  --bottleneckDelay=10ms \
  --legitTcpRate=3Mbps \
  --legitSendSize=1000 \
  --attackRatePerAttacker=5Mbps \
  --attackPacketSize=1000 \
  --legitStart=1.0 \
  --attackStart=6.0 \
  --attackStop=14.0 \
  --simTime=20.0 \
  --sampleInterval=0.1 \
  --queueSizePackets=100 \
  --enablePcap=1 \
  --enableFlowMonitor=1"

python3 utils/plot_udp.py --input "$OUTPUT_DIR" --output "$OUTPUT_DIR"

echo "Done. Check $OUTPUT_DIR for CSV, PCAP, XML, and PNG files."
