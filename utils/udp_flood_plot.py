#!/usr/bin/env python3
import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def save_throughput_plot(df: pd.DataFrame, outdir: Path) -> None:
    plt.figure(figsize=(10, 5))
    plt.plot(df["time_s"], df["legit_mbps"], label="Legitimate TCP throughput")
    plt.plot(df["time_s"], df["attack_mbps"], label="Attack UDP throughput")
    plt.xlabel("Time (s)")
    plt.ylabel("Throughput (Mbps)")
    plt.title("Victim-side throughput over time")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(outdir / "throughput.png", dpi=200)
    plt.close()


def save_queue_plot(df: pd.DataFrame, outdir: Path) -> None:
    plt.figure(figsize=(10, 5))
    plt.plot(df["time_s"], df["queue_packets"])
    plt.xlabel("Time (s)")
    plt.ylabel("Queue occupancy (packets)")
    plt.title("Bottleneck queue occupancy over time")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(outdir / "queue.png", dpi=200)
    plt.close()


def save_drops_plot(df: pd.DataFrame, outdir: Path) -> None:
    plt.figure(figsize=(10, 5))
    plt.plot(df["time_s"], df["drops_in_interval"], label="Drops per interval")
    plt.plot(df["time_s"], df["cumulative_drops"], label="Cumulative drops")
    plt.xlabel("Time (s)")
    plt.ylabel("Packets dropped")
    plt.title("Bottleneck drops over time")
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
