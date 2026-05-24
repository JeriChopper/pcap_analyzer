import json
import pyshark
import pandas as pd
import ipaddress

from pathlib import Path
from collections import Counter
from statistics import mean

# CONFIGURATION
PHASE = "idle"

# DYNAMIC PATHS
ROOT_DIR = Path(__file__).resolve().parent
INPUT_DIR = ROOT_DIR / PHASE
OUTPUT_DIR = ROOT_DIR / f"{PHASE}_results"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# LOAD DEVICE MAPPING
with open(ROOT_DIR / "device_mapping.json", "r") as f:
    DEVICES = json.load(f)

# GET PCAP FILES
PCAP_FILES = list(INPUT_DIR.glob("*.pcap")) + \
             list(INPUT_DIR.glob("*.pcapng"))

print(f"Found {len(PCAP_FILES)} capture files")


# HELPER FUNCTION
def is_public_ip(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except:
        return False


# MAIN ANALYSIS
summary_rows = []

for device_name, info in DEVICES.items():

    TARGET_MAC = info["mac"].lower()

    print("\n================================")
    print(f"Analyzing: {device_name}")
    print(f"Target MAC: {TARGET_MAC}")
    print("================================")

    protocol_counter = Counter()

    dns_queries = set()
    dns_counter = Counter()

    endpoints = set()

    packet_times = []

    total_packets = 0

    # PROCESS PCAPS
    for pcap in PCAP_FILES:

        print(f"Processing {pcap.name}")

        capture = pyshark.FileCapture(
            str(pcap),
            keep_packets=False
        )

        for pkt in capture:

            try:
                src_mac = pkt.eth.src.lower()
                dst_mac = pkt.eth.dst.lower()

                if TARGET_MAC not in [src_mac, dst_mac]:
                    continue

                total_packets += 1

                packet_times.append(float(pkt.sniff_timestamp))

                # PROTOCOLS
                protocol_counter[pkt.highest_layer] += 1

                # DNS
                if hasattr(pkt, "dns"):

                    try:
                        query = pkt.dns.qry_name

                        dns_queries.add(query)
                        dns_counter[query] += 1

                    except:
                        pass

                # ENDPOINTS
                if hasattr(pkt, "ip"):

                    try:
                        src_ip = pkt.ip.src
                        dst_ip = pkt.ip.dst

                        # Save only public/external IPs
                        if is_public_ip(src_ip):
                            endpoints.add(src_ip)

                        if is_public_ip(dst_ip):
                            endpoints.add(dst_ip)

                    except:
                        pass

            except:
                continue

        capture.close()

    # FREQUENCY ANALYSIS
    avg_packets_per_min = 0
    avg_interval_seconds = 0

    if len(packet_times) > 1:

        packet_times.sort()

        duration_seconds = max(packet_times) - min(packet_times)

        if duration_seconds > 0:
            avg_packets_per_min = round(
                total_packets / (duration_seconds / 60),
                2
            )

        intervals = [
            packet_times[i + 1] - packet_times[i]
            for i in range(len(packet_times) - 1)
        ]

        if intervals:
            avg_interval_seconds = round(mean(intervals), 2)

    # SAVE JSON OUTPUT
    device_output = {
        "device": device_name,
        "phase": PHASE,
        "mac": TARGET_MAC,
        "total_packets": total_packets,
        "protocols": dict(protocol_counter),
        "dns_queries": sorted(dns_queries),
        "dns_query_frequency": dict(dns_counter),
        "endpoints": sorted(endpoints),
        "avg_packets_per_min": avg_packets_per_min,
        "avg_interval_seconds": avg_interval_seconds
    }

    with open(
        OUTPUT_DIR / f"{device_name}.json",
        "w"
    ) as f:
        json.dump(device_output, f, indent=4)

    # CSV SUMMARY ROW
    protocol_summary = "/".join(
        [
            proto
            for proto, _ in protocol_counter.most_common(5)
        ]
    )

    top_dns = ", ".join(
        [
            f"{dns} ({count})"
            for dns, count in dns_counter.most_common(5)
        ]
    )

    summary_rows.append({
        "Device": device_name,
        "Protocols": protocol_summary,
        "Top DNS Queries": top_dns,
        "Endpoints": ", ".join(sorted(endpoints)[:10]),
        "Avg Packets/Min": avg_packets_per_min,
        "Avg Interval Seconds": avg_interval_seconds
    })

# SAVE CSV SUMMARY
summary_df = pd.DataFrame(summary_rows)

summary_df.to_csv(
    OUTPUT_DIR / "summary.csv",
    index=False
)

print("\n================================")
print("Analysis Complete")
print("================================")
print(summary_df)