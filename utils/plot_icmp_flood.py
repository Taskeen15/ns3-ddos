import csv
import os
import sys
import matplotlib.pyplot as plt

base = sys.argv[1] if len(sys.argv) > 1 else "results/icmp-flood"
plots_dir = os.path.join(base, "plots")
os.makedirs(plots_dir, exist_ok=True)

attack_start = 6.0
attack_stop = 14.0
summary_csv = os.path.join(base, "summary.csv")
if os.path.exists(summary_csv):
    pass

# throughput.csv
x, legit, icmp = [], [], []
with open(os.path.join(base, "throughput.csv"), "r") as f:
    r = csv.DictReader(f)
    for row in r:
        x.append(float(row["time_s"]))
        legit.append(float(row["legit_tcp_mbps"]))
        icmp.append(float(row["icmp_mbps"]))

plt.figure(figsize=(10, 6))
plt.plot(x, legit, label="Legitimate TCP throughput (Mbps)")
plt.plot(x, icmp, label="ICMP flood rate (Mbps)")
plt.axvline(attack_start, linestyle="--")
plt.axvline(attack_stop, linestyle="--")
plt.xlabel("Time (s)")
plt.ylabel("Mbps")
plt.title("Throughput vs Time")
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(plots_dir, "throughput_vs_time.png"), dpi=300)
plt.close()

# queue.csv
x, q = [], []
with open(os.path.join(base, "queue.csv"), "r") as f:
    r = csv.DictReader(f)
    for row in r:
        x.append(float(row["time_s"]))
        q.append(float(row["qdisc_packets"]))

plt.figure(figsize=(10, 6))
plt.plot(x, q, label="Bottleneck qdisc occupancy (packets)")
plt.axvline(attack_start, linestyle="--")
plt.axvline(attack_stop, linestyle="--")
plt.xlabel("Time (s)")
plt.ylabel("Packets")
plt.title("Queue Occupancy vs Time")
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(plots_dir, "queue_occupancy_vs_time.png"), dpi=300)
plt.close()

# drops.csv
x, d_int, d_cum = [], [], []
with open(os.path.join(base, "drops.csv"), "r") as f:
    r = csv.DictReader(f)
    for row in r:
        x.append(float(row["time_s"]))
        d_int.append(float(row["drop_packets_interval"]))
        d_cum.append(float(row["drop_packets_cumulative"]))

plt.figure(figsize=(10, 6))
plt.plot(x, d_int, label="Interval drops (packets)")
plt.axvline(attack_start, linestyle="--")
plt.axvline(attack_stop, linestyle="--")
plt.xlabel("Time (s)")
plt.ylabel("Packets")
plt.title("Drops per Interval vs Time")
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(plots_dir, "drops_interval_vs_time.png"), dpi=300)
plt.close()

plt.figure(figsize=(10, 6))
plt.plot(x, d_cum, label="Cumulative drops (packets)")
plt.axvline(attack_start, linestyle="--")
plt.axvline(attack_stop, linestyle="--")
plt.xlabel("Time (s)")
plt.ylabel("Packets")
plt.title("Cumulative Drops vs Time")
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(plots_dir, "drops_cumulative_vs_time.png"), dpi=300)
plt.close()
