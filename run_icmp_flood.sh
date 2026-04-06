#!/bin/bash
set -e

NS3_ROOT="${NS3_ROOT:-.}"
OUTPUT_DIR="${1:-results/icmp-flood}"

cd "$NS3_ROOT"
./ns3 build
./ns3 run "scratch/icmp-flood-ddos \
  --outputDir=$OUTPUT_DIR \
  --nLegitClients=3 \
  --nAttackers=10 \
  --accessRate=100Mbps \
  --accessDelay=1ms \
  --bottleneckRate=10Mbps \
  --bottleneckDelay=10ms \
  --legitDataRate=6Mbps \
  --legitSendSize=1200 \
  --legitPort=5000 \
  --icmpPpsPerAttacker=700 \
  --icmpPayloadSize=512 \
  --attackStart=6 \
  --attackStop=14 \
  --simStop=20 \
  --sampleInterval=0.1 \
  --enablePcap=true \
  --enableFlowMonitor=true"
