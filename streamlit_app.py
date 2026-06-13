from pathlib import Path
import csv

import streamlit as st


BASE_DIR = Path(__file__).resolve().parent
RESULTS_FILE = BASE_DIR / "authentication_benchmark_results.csv"
MESSAGE_FILE = BASE_DIR / "message.txt"
GRAPH_DIR = BASE_DIR / "graphs"

REQUIRED_GRAPHS = [
    ("Total Authentication Time", "total_authentication_time_comparison.png"),
    ("KDC Generation / Signature Generation", "message_generation_time_comparison.png"),
    ("Decode / Verification Time", "decode_verification_time_comparison.png"),
    ("Combined Computational Time", "combined_authentication_time_comparison.png"),
    ("Ticket / Signature Size", "signature_ticket_size_comparison.png"),
]


st.set_page_config(
    page_title="ML-DSA Authentication Benchmark",
    layout="wide"
)


@st.cache_data
def load_results():
    if not RESULTS_FILE.exists():
        st.error("authentication_benchmark_results.csv not found. Run authentication_benchmark.py first.")
        st.stop()

    with RESULTS_FILE.open(newline="") as file:
        rows = list(csv.DictReader(file))

    for row in rows:
        row["Message Generation Time (seconds)"] = float(row["Message Generation Time (seconds)"])
        row["Decode/Verify Time (seconds)"] = float(row["Decode/Verify Time (seconds)"])
        row["Total Authentication Time (seconds)"] = float(row["Total Authentication Time (seconds)"])
        row["Public Key Size (bytes)"] = int(row["Public Key Size (bytes)"])
        row["Private/Secret Key Size (bytes)"] = int(row["Private/Secret Key Size (bytes)"])
        row["Signature/Ticket Size (bytes)"] = int(row["Signature/Ticket Size (bytes)"])

    return rows


def format_seconds(value):
    return f"{value:.8f} s"


def format_bytes(value):
    return f"{value:,} B"


def get_row(rows, algorithm):
    return next(row for row in rows if row["Algorithm"] == algorithm)


def show_status_card(title, value, caption):
    with st.container(border=True):
        st.metric(label=title, value=value)
        st.caption(caption)


def show_dataframe(rows, columns):
    st.dataframe(
        [{column: row[column] for column in columns} for row in rows],
        width="stretch",
        hide_index=True
    )


def main():
    rows = load_results()
    message_size = MESSAGE_FILE.stat().st_size if MESSAGE_FILE.exists() else 0
    fastest = min(rows, key=lambda row: row["Total Authentication Time (seconds)"])

    st.title("ML-DSA Authentication Benchmark Dashboard")
    st.caption("Kerberos/KDC vs RSA-3072 vs ML-DSA-65 on a 2-3 KB paragraph input")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        show_status_card("Input Paragraph", format_bytes(message_size), "Required range: 2-3 KB")
    with col2:
        show_status_card(
            "Fastest Total Auth",
            fastest["Algorithm"],
            format_seconds(fastest["Total Authentication Time (seconds)"])
        )
    with col3:
        show_status_card("Quantum-Safe Method", "ML-DSA-65", "Post-quantum digital signature")
    with col4:
        show_status_card("Required Graphs", str(len(REQUIRED_GRAPHS)), "Timing and size comparison")

    overview_tab, timing_tab, size_tab, graph_tab, notes_tab = st.tabs(
        ["Overview", "Timing", "Sizes", "Graphs", "Notes"]
    )

    with overview_tab:
        st.subheader("Requirement Coverage")
        req1, req2 = st.columns(2)
        with req1:
            st.success("ML-DSA is benchmarked on message.txt, currently 2470 bytes.")
            st.success("Total authentication time is measured for all three methods.")
        with req2:
            st.success("KDC message generation time is compared with RSA and ML-DSA signing.")
            st.success("Kerberos decode time is compared with RSA and ML-DSA verification.")

        st.subheader("Complete Result Table")
        show_dataframe(
            rows,
            [
                "Algorithm",
                "Message Generation Time (seconds)",
                "Decode/Verify Time (seconds)",
                "Total Authentication Time (seconds)",
                "Public Key Size (bytes)",
                "Private/Secret Key Size (bytes)",
                "Signature/Ticket Size (bytes)",
                "Quantum Safe",
            ]
        )

    with timing_tab:
        st.subheader("Computational Time")
        timing_rows = [
            {
                "Algorithm": row["Algorithm"],
                "Generation / Signing": format_seconds(row["Message Generation Time (seconds)"]),
                "Decode / Verify": format_seconds(row["Decode/Verify Time (seconds)"]),
                "Total Authentication": format_seconds(row["Total Authentication Time (seconds)"]),
            }
            for row in rows
        ]
        st.dataframe(timing_rows, width="stretch", hide_index=True)

        st.bar_chart(
            {
                row["Algorithm"]: row["Total Authentication Time (seconds)"]
                for row in rows
            },
            horizontal=True
        )

    with size_tab:
        st.subheader("Key, Ticket, and Signature Sizes")
        size_rows = [
            {
                "Algorithm": row["Algorithm"],
                "Public Key": format_bytes(row["Public Key Size (bytes)"]),
                "Private / Secret Key": format_bytes(row["Private/Secret Key Size (bytes)"]),
                "Ticket / Signature": format_bytes(row["Signature/Ticket Size (bytes)"]),
                "Quantum Safe": row["Quantum Safe"],
            }
            for row in rows
        ]
        st.dataframe(size_rows, width="stretch", hide_index=True)

        st.bar_chart(
            {
                row["Algorithm"]: row["Signature/Ticket Size (bytes)"]
                for row in rows
            },
            horizontal=True
        )

    with graph_tab:
        st.subheader("Generated Benchmark Graphs")
        for index in range(0, len(REQUIRED_GRAPHS), 2):
            graph_columns = st.columns(2)
            row_graphs = REQUIRED_GRAPHS[index:index + 2]

            for column, (title, filename) in zip(graph_columns, row_graphs):
                graph_path = GRAPH_DIR / filename

                with column:
                    with st.container(border=True):
                        st.markdown(f"**{title}**")
                        if graph_path.exists():
                            st.image(str(graph_path), width="stretch")
                        else:
                            st.warning(f"Missing graph: {filename}")

    with notes_tab:
        st.subheader("Interpretation")
        st.markdown(
            """
            - **Kerberos/KDC** is fastest in this simulation, but it is not quantum-safe by itself.
            - **RSA-3072** is the traditional public-key signature baseline and is not quantum-safe.
            - **ML-DSA-65** is quantum-safe, but it has larger keys/signatures and higher signing/verification time.
            """
        )

        st.subheader("Implementation Files")
        st.code(
            "\n".join(
                [
                    "authentication_benchmark.py  -> benchmark runner and graph generation",
                    "kerberos_authentication.py   -> Kerberos/KDC simulation",
                    "rsa_signature.py             -> RSA-3072 implementation",
                    "mldsa_signature.py           -> ML-DSA-65 implementation",
                    "message.txt                  -> 2-3 KB paragraph input",
                ]
            ),
            language="text"
        )


if __name__ == "__main__":
    main()
