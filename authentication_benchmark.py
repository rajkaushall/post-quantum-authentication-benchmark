from pathlib import Path
import csv
import os
import tempfile
import time
import statistics

BASE_DIR = Path(__file__).resolve().parent
MPLCONFIG_DIR = Path(tempfile.gettempdir()) / "crystals_dilithium_matplotlib_cache"
MPLCONFIG_DIR.mkdir(exist_ok=True)
os.environ.setdefault("MPLBACKEND", "Agg")
os.environ.setdefault("MPLCONFIGDIR", str(MPLCONFIG_DIR))

import matplotlib.pyplot as plt

from kerberos_authentication import (
    DEFAULT_CLIENT_ID,
    DEFAULT_SERVER_ID,
    decode_kdc_message,
    generate_kdc_message,
    generate_kerberos_keys,
    kerberos_total_authentication_flow,
    sha256_hex
)
from mldsa_signature import (
    generate_mldsa_keys,
    mldsa_sign_message,
    mldsa_total_authentication_flow,
    mldsa_verify_signature,
    verify_mldsa_correctness
)
from rsa_signature import (
    generate_rsa_keys,
    rsa_sign_message,
    rsa_total_authentication_flow,
    rsa_verify_signature
)


GRAPH_DIR = BASE_DIR / "graphs"
MESSAGE_FILE = BASE_DIR / "message.txt"
CSV_FILE = BASE_DIR / "authentication_benchmark_results.csv"

MIN_MESSAGE_SIZE_BYTES = 2 * 1024
MAX_MESSAGE_SIZE_BYTES = 3 * 1024

ITERATIONS = 30


GRAPH_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------
# Utility functions
# ---------------------------------------------------------

def read_message() -> bytes:
    if not MESSAGE_FILE.exists():
        raise FileNotFoundError("message.txt not found.")

    message = MESSAGE_FILE.read_bytes()
    message_size = len(message)

    if not MIN_MESSAGE_SIZE_BYTES <= message_size <= MAX_MESSAGE_SIZE_BYTES:
        raise ValueError(
            "message.txt must be between "
            f"{MIN_MESSAGE_SIZE_BYTES} and {MAX_MESSAGE_SIZE_BYTES} bytes. "
            f"Current size: {message_size} bytes."
        )

    return message


def average(values):
    return statistics.mean(values)


def measure_time(function, *args):
    start = time.perf_counter()
    result = function(*args)
    end = time.perf_counter()
    return result, end - start


# ---------------------------------------------------------
# Benchmarking
# ---------------------------------------------------------

def run_benchmark(iterations=ITERATIONS):
    message = read_message()

    print("\n========== Authentication Benchmark ==========\n")
    print("Input file:", MESSAGE_FILE)
    print("Input paragraph size:", len(message), "bytes")
    print("Message SHA-256:", sha256_hex(message))
    print("Iterations:", iterations)

    client_key, server_key = generate_kerberos_keys()

    rsa_public_key, rsa_private_key, rsa_public_bytes, rsa_private_bytes = generate_rsa_keys()
    mldsa_public_key, mldsa_secret_key = generate_mldsa_keys()

    mldsa_valid, mldsa_tampered_valid = verify_mldsa_correctness(
        mldsa_public_key,
        mldsa_secret_key,
        message
    )

    kerberos_kdc_generation_times = []
    kerberos_decode_times = []
    kerberos_total_auth_times = []

    rsa_sign_times = []
    rsa_verify_times = []
    rsa_total_auth_times = []

    mldsa_sign_times = []
    mldsa_verify_times = []
    mldsa_total_auth_times = []

    for _ in range(iterations):
        # ---------------- Kerberos/KDC ----------------

        _, kdc_gen_time = measure_time(
            generate_kdc_message,
            DEFAULT_CLIENT_ID,
            DEFAULT_SERVER_ID,
            client_key,
            server_key
        )
        kerberos_kdc_generation_times.append(kdc_gen_time)

        kdc_message = generate_kdc_message(
            DEFAULT_CLIENT_ID,
            DEFAULT_SERVER_ID,
            client_key,
            server_key
        )

        _, decode_time = measure_time(
            decode_kdc_message,
            kdc_message,
            client_key,
            server_key
        )
        kerberos_decode_times.append(decode_time)

        kerberos_result, kerberos_total_time = measure_time(
            kerberos_total_authentication_flow,
            message,
            client_key,
            server_key
        )
        kerberos_total_auth_times.append(kerberos_total_time)

        if not kerberos_result:
            raise RuntimeError("Kerberos/KDC authentication flow failed.")

        # ---------------- RSA ----------------

        rsa_signature, rsa_sign_time = measure_time(
            rsa_sign_message,
            rsa_private_key,
            message
        )
        rsa_sign_times.append(rsa_sign_time)

        rsa_result, rsa_verify_time = measure_time(
            rsa_verify_signature,
            rsa_public_key,
            message,
            rsa_signature
        )
        rsa_verify_times.append(rsa_verify_time)

        rsa_total_result, rsa_total_time = measure_time(
            rsa_total_authentication_flow,
            rsa_public_key,
            rsa_private_key,
            message
        )
        rsa_total_auth_times.append(rsa_total_time)

        if not rsa_result or not rsa_total_result:
            raise RuntimeError("RSA authentication flow failed.")

        # ---------------- ML-DSA ----------------

        mldsa_signature, mldsa_sign_time = measure_time(
            mldsa_sign_message,
            mldsa_secret_key,
            message
        )
        mldsa_sign_times.append(mldsa_sign_time)

        mldsa_result, mldsa_verify_time = measure_time(
            mldsa_verify_signature,
            mldsa_public_key,
            message,
            mldsa_signature
        )
        mldsa_verify_times.append(mldsa_verify_time)

        mldsa_total_result, mldsa_total_time = measure_time(
            mldsa_total_authentication_flow,
            mldsa_public_key,
            mldsa_secret_key,
            message
        )
        mldsa_total_auth_times.append(mldsa_total_time)

        if not mldsa_result or not mldsa_total_result:
            raise RuntimeError("ML-DSA authentication flow failed.")

    results = {
        "Kerberos/KDC": {
            "message_generation_time": average(kerberos_kdc_generation_times),
            "decode_or_verify_time": average(kerberos_decode_times),
            "total_authentication_time": average(kerberos_total_auth_times),
            "public_key_size": 0,
            "private_key_size": 0,
            "signature_or_ticket_size": len(kdc_message),
            "quantum_safe": "No"
        },
        "RSA-3072": {
            "message_generation_time": average(rsa_sign_times),
            "decode_or_verify_time": average(rsa_verify_times),
            "total_authentication_time": average(rsa_total_auth_times),
            "public_key_size": len(rsa_public_bytes),
            "private_key_size": len(rsa_private_bytes),
            "signature_or_ticket_size": len(rsa_signature),
            "quantum_safe": "No"
        },
        "ML-DSA-65": {
            "message_generation_time": average(mldsa_sign_times),
            "decode_or_verify_time": average(mldsa_verify_times),
            "total_authentication_time": average(mldsa_total_auth_times),
            "public_key_size": len(mldsa_public_key),
            "private_key_size": len(mldsa_secret_key),
            "signature_or_ticket_size": len(mldsa_signature),
            "quantum_safe": "Yes"
        }
    }

    print_results(results, mldsa_valid, mldsa_tampered_valid)
    save_results_to_csv(results)
    generate_graphs(results)

    print("\nCSV saved as:", CSV_FILE)
    print("Graphs saved inside:", GRAPH_DIR)


def print_results(results, mldsa_valid, mldsa_tampered_valid):
    print("\n========== Final Average Result Table ==========")

    for algorithm, data in results.items():
        print("\nAlgorithm:", algorithm)
        print("Message Generation Time:", round(data["message_generation_time"], 8), "seconds")
        print("Decode/Verify Time:", round(data["decode_or_verify_time"], 8), "seconds")
        print("Total Authentication Time:", round(data["total_authentication_time"], 8), "seconds")
        print("Public Key Size:", data["public_key_size"], "bytes")
        print("Private/Secret Key Size:", data["private_key_size"], "bytes")
        print("Signature/Ticket Size:", data["signature_or_ticket_size"], "bytes")
        print("Quantum Safe:", data["quantum_safe"])

    print("\n========== ML-DSA Correctness Check ==========")
    print("Original 2-3 KB paragraph signature valid:", mldsa_valid)
    print("Tampered paragraph signature valid:", mldsa_tampered_valid)


def save_results_to_csv(results):
    with open(CSV_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Algorithm",
            "Message Generation Time (seconds)",
            "Decode/Verify Time (seconds)",
            "Total Authentication Time (seconds)",
            "Public Key Size (bytes)",
            "Private/Secret Key Size (bytes)",
            "Signature/Ticket Size (bytes)",
            "Quantum Safe"
        ])

        for algorithm, data in results.items():
            writer.writerow([
                algorithm,
                data["message_generation_time"],
                data["decode_or_verify_time"],
                data["total_authentication_time"],
                data["public_key_size"],
                data["private_key_size"],
                data["signature_or_ticket_size"],
                data["quantum_safe"]
            ])


# ---------------------------------------------------------
# Graph generation
# ---------------------------------------------------------

def generate_bar_chart(title, ylabel, filename, labels, values):
    plt.figure(figsize=(10, 6))
    plt.bar(labels, values)

    plt.title(title)
    plt.xlabel("Authentication Method")
    plt.ylabel(ylabel)
    plt.grid(axis="y", linestyle="--", alpha=0.6)

    for i, value in enumerate(values):
        plt.text(i, value, f"{value:.6f}", ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    plt.savefig(GRAPH_DIR / filename, dpi=300)
    plt.close()


def generate_size_chart(results):
    labels = list(results.keys())
    ticket_signature_sizes = [
        results[algo]["signature_or_ticket_size"] for algo in labels
    ]

    plt.figure(figsize=(10, 6))
    plt.bar(labels, ticket_signature_sizes)

    plt.title("Signature/Ticket Size Comparison")
    plt.xlabel("Authentication Method")
    plt.ylabel("Size in Bytes")
    plt.grid(axis="y", linestyle="--", alpha=0.6)

    for i, value in enumerate(ticket_signature_sizes):
        plt.text(i, value, str(value), ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    plt.savefig(GRAPH_DIR / "signature_ticket_size_comparison.png", dpi=300)
    plt.close()


def generate_grouped_time_chart(results):
    labels = list(results.keys())

    generation_times = [
        results[algo]["message_generation_time"] for algo in labels
    ]

    decode_verify_times = [
        results[algo]["decode_or_verify_time"] for algo in labels
    ]

    total_times = [
        results[algo]["total_authentication_time"] for algo in labels
    ]

    x = range(len(labels))
    width = 0.25

    plt.figure(figsize=(12, 7))

    plt.bar([i - width for i in x], generation_times, width, label="KDC Message Generation / Signing")
    plt.bar(list(x), decode_verify_times, width, label="Decode / Verification")
    plt.bar([i + width for i in x], total_times, width, label="Total Authentication")

    plt.title("Authentication Computational Time Comparison")
    plt.xlabel("Authentication Method")
    plt.ylabel("Time in Seconds")
    plt.xticks(list(x), labels)
    plt.legend()
    plt.grid(axis="y", linestyle="--", alpha=0.6)

    plt.tight_layout()
    plt.savefig(GRAPH_DIR / "combined_authentication_time_comparison.png", dpi=300)
    plt.close()


def generate_graphs(results):
    labels = list(results.keys())

    generate_bar_chart(
        title="Total Authentication Time During Communication",
        ylabel="Time in Seconds",
        filename="total_authentication_time_comparison.png",
        labels=labels,
        values=[results[algo]["total_authentication_time"] for algo in labels]
    )

    generate_bar_chart(
        title="KDC Message Generation vs Signature Generation Time",
        ylabel="Time in Seconds",
        filename="message_generation_time_comparison.png",
        labels=labels,
        values=[results[algo]["message_generation_time"] for algo in labels]
    )

    generate_bar_chart(
        title="Decode / Verification Time Comparison",
        ylabel="Time in Seconds",
        filename="decode_verification_time_comparison.png",
        labels=labels,
        values=[results[algo]["decode_or_verify_time"] for algo in labels]
    )

    generate_size_chart(results)
    generate_grouped_time_chart(results)


if __name__ == "__main__":
    run_benchmark(iterations=ITERATIONS)
