#!/usr/bin/env python3
import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


ATTACK_START = 6.0
ATTACK_STOP = 14.0


def add_attack_markers():
    plt.axvline(ATTACK_START, linestyle="--", alpha=0.7, label="Attack start")
    plt.axvline(ATTACK_STOP, linestyle="--", alpha=0.7, label="Attack stop")


def save_throughput_plot(df: pd.DataFrame, outdir: Path) -> None:
    plt.figure(figsize=(10, 5))
    plt.plot(df["time_s"], df["legit_rx_mbps"], label="Legitimate TCP throughput")
    plt.plot(df["time_s"], df["attack_rx_mbps"], label="Attack UDP throughput")
    add_attack_markers()
    plt.xlabel("Time (s)")
    plt.ylabel("Throughput (Mbps)")
    plt.title("Victim-side received throughput over time")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(outdir / "throughput.png", dpi=200)
    plt.close()


def save_queue_plot(df: pd.DataFrame, outdir: Path) -> None:
    plt.figure(figsize=(10, 5))
    plt.plot(df["time_s"], df["bottleneck_qdisc_packets"], label="Bottleneck qdisc occupancy")
    add_attack_markers()
    plt.xlabel("Time (s)")
    plt.ylabel("Queue occupancy (packets)")
    plt.title("Bottleneck queue occupancy over time")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(outdir / "queue.png", dpi=200)
    plt.close()


def save_drops_plot(df: pd.DataFrame, outdir: Path) -> None:
    plt.figure(figsize=(10, 5))
    plt.plot(
        df["time_s"],
        df["bottleneck_qdisc_drops_in_interval"],
        label="Drops per interval"
    )
    plt.plot(
        df["time_s"],
        df["bottleneck_qdisc_cumulative_drops"],
        label="Cumulative drops"
    )
    add_attack_markers()
    plt.xlabel("Time (s)")
    plt.ylabel("Packets dropped")
    plt.title("Bottleneck qdisc drops over time")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(outdir / "drops.png", dpi=200)
    plt.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot ns-3 UDP flood CSV outputs")
    parser.add_argument("--input", required=True, help="Directory containing throughput.csv, queue.csv, drops.csv")
    parser.add_argument("--output", default=None, help="Directory to save plots; defaults to input directory")
    args = parser.parse_args()

    input_dir = Path(args.input)
    output_dir = Path(args.output) if args.output else input_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    throughput_df = pd.read_csv(input_dir / "throughput.csv")
    queue_df = pd.read_csv(input_dir / "queue.csv")
    drops_df = pd.read_csv(input_dir / "drops.csv")

    save_throughput_plot(throughput_df, output_dir)
    save_queue_plot(queue_df, output_dir)
    save_drops_plot(drops_df, output_dir)

    print(f"Saved plots to {output_dir}")


if __name__ == "__main__":
    main()