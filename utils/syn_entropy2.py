#!/usr/bin/env python3
import argparse
import csv
import math
import os
import subprocess
from collections import Counter
from glob import glob

import matplotlib.pyplot as plt


def shannon_entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0

    h = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            h -= p * math.log2(p)
    return h


def merge_counters(counters):
    merged = Counter()
    for c in counters:
        merged.update(c)
    return merged


def resolve_pcaps(path_or_glob):
    matches = sorted(glob(path_or_glob))
    if matches:
        return matches
    if os.path.exists(path_or_glob):
        return [path_or_glob]
    raise FileNotFoundError(f"No PCAP matched: {path_or_glob}")


def run_tshark(pcap_paths, syn_only=False):
    """
    Extract:
      frame.time_epoch, ip.dst, tcp.dstport, tcp.flags.syn, tcp.flags.ack
    from one or more PCAP files.
    """
    rows = []

    for pcap_path in pcap_paths:
        cmd = [
            "tshark",
            "-r", pcap_path,
            "-T", "fields",
            "-E", "separator=,",
            "-E", "quote=n",
            "-e", "frame.time_epoch",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.ack",
            "-Y", "ip && tcp"
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)

        for line in proc.stdout.splitlines():
            parts = line.strip().split(",")
            if len(parts) < 5:
                continue

            t, ip_dst, dport, syn_flag, ack_flag = parts[:5]

            if not t or not ip_dst or not dport:
                continue

            try:
                t = float(t)
                dport = int(dport)
                syn_flag = int(syn_flag) if syn_flag else 0
                ack_flag = int(ack_flag) if ack_flag else 0
            except ValueError:
                continue

            if syn_only and not (syn_flag == 1 and ack_flag == 0):
                continue

            rows.append((t, ip_dst, dport))

    return rows


def compute_entropy_series(rows, interval, window_bins, dst_prefix=None, dst_ips=None):
    if not rows:
        return [], [], []

    rows.sort(key=lambda x: x[0])
    t0 = rows[0][0]
    t_last = rows[-1][0]
    n_bins = int(math.floor((t_last - t0) / interval)) + 1

    ip_bins = [Counter() for _ in range(n_bins)]
    port_bins = [Counter() for _ in range(n_bins)]

    allowed_ips = None
    if dst_ips:
        allowed_ips = set(ip.strip() for ip in dst_ips.split(",") if ip.strip())

    for t, ip_dst, dport in rows:
        if dst_prefix is not None and not ip_dst.startswith(dst_prefix):
            continue
        if allowed_ips is not None and ip_dst not in allowed_ips:
            continue

        idx = int((t - t0) // interval)
        if 0 <= idx < n_bins:
            ip_bins[idx][ip_dst] += 1
            port_bins[idx][dport] += 1

    times = []
    ip_entropy = []
    port_entropy = []

    for end_bin in range(window_bins - 1, n_bins):
        start_bin = end_bin - window_bins + 1

        merged_ip = merge_counters(ip_bins[start_bin:end_bin + 1])
        merged_port = merge_counters(port_bins[start_bin:end_bin + 1])

        t_rel = (end_bin + 1) * interval
        times.append(t_rel)
        ip_entropy.append(shannon_entropy(merged_ip))
        port_entropy.append(shannon_entropy(merged_port))

    return times, ip_entropy, port_entropy


def save_csv(out_csv, times, ip_entropy, port_entropy):
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["time_s", "dst_ip_entropy", "dst_port_entropy"])
        for t, h_ip, h_port in zip(times, ip_entropy, port_entropy):
            writer.writerow([f"{t:.6f}", f"{h_ip:.6f}", f"{h_port:.6f}"])


def plot_series(times, values, title, ylabel, out_png, attack_start=None, attack_stop=None):
    plt.figure(figsize=(10, 5))
    plt.plot(times, values, linewidth=2)

    if attack_start is not None:
        plt.axvline(attack_start, linestyle="--", linewidth=1)
    if attack_stop is not None:
        plt.axvline(attack_stop, linestyle="--", linewidth=1)

    plt.xlabel("Time (s)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_png, dpi=300)
    plt.close()


def plot_combined(times, ip_entropy, port_entropy, out_png, attack_start=None, attack_stop=None):
    plt.figure(figsize=(10, 5))
    plt.plot(times, ip_entropy, label="Destination IP entropy", linewidth=2)
    plt.plot(times, port_entropy, label="Destination port entropy", linewidth=2)

    if attack_start is not None:
        plt.axvline(attack_start, linestyle="--", linewidth=1)
    if attack_stop is not None:
        plt.axvline(attack_stop, linestyle="--", linewidth=1)

    plt.xlabel("Time (s)")
    plt.ylabel("Entropy (bits)")
    plt.title("Sliding-window Shannon entropy")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_png, dpi=300)
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="Compute entropy graphs from ns-3 SYN flood PCAP(s)")
    parser.add_argument("--pcap", required=True,
                        help="PCAP path or glob, e.g. results/.../*.pcap")
    parser.add_argument("--outdir", required=True,
                        help="Output directory for CSV and plots")
    parser.add_argument("--interval", type=float, default=0.5,
                        help="Sampling interval in seconds")
    parser.add_argument("--window-bins", type=int, default=10,
                        help="Sliding window size in number of bins")
    parser.add_argument("--dst-prefix", default=None,
                        help="Only analyze packets whose destination IP starts with this prefix")
    parser.add_argument("--dst-ips", default=None,
                        help="Comma-separated list of destination IPs to keep, e.g. 10.10.0.16,10.10.0.17")
    parser.add_argument("--syn-only", action="store_true",
                        help="Use only pure SYN packets (SYN=1, ACK=0)")
    parser.add_argument("--attack-start", type=float, default=None,
                        help="Optional vertical marker for attack start")
    parser.add_argument("--attack-stop", type=float, default=None,
                        help="Optional vertical marker for attack stop")

    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    pcaps = resolve_pcaps(args.pcap)

    rows = run_tshark(pcaps, syn_only=args.syn_only)
    times, ip_entropy, port_entropy = compute_entropy_series(
        rows,
        interval=args.interval,
        window_bins=args.window_bins,
        dst_prefix=args.dst_prefix,
        dst_ips=args.dst_ips
    )

    if not times:
        raise RuntimeError("No usable packets found after filtering. Check the PCAP path/filter.")

    csv_path = os.path.join(args.outdir, "entropy_timeseries.csv")
    ip_png = os.path.join(args.outdir, "entropy_dst_ip.png")
    port_png = os.path.join(args.outdir, "entropy_dst_port.png")
    combined_png = os.path.join(args.outdir, "entropy_combined.png")

    save_csv(csv_path, times, ip_entropy, port_entropy)

    plot_series(
        times,
        ip_entropy,
        title="Entropy of destination IPs",
        ylabel="Entropy (bits)",
        out_png=ip_png,
        attack_start=args.attack_start,
        attack_stop=args.attack_stop,
    )

    plot_series(
        times,
        port_entropy,
        title="Entropy of destination ports",
        ylabel="Entropy (bits)",
        out_png=port_png,
        attack_start=args.attack_start,
        attack_stop=args.attack_stop,
    )

    plot_combined(
        times,
        ip_entropy,
        port_entropy,
        out_png=combined_png,
        attack_start=args.attack_start,
        attack_stop=args.attack_stop,
    )

    print("PCAP(s) used:")
    for p in pcaps:
        print(" ", p)
    print(f"Saved: {csv_path}")
    print(f"Saved: {ip_png}")
    print(f"Saved: {port_png}")
    print(f"Saved: {combined_png}")


if __name__ == "__main__":
    main()