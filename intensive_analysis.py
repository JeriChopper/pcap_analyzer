import json
import pyshark
import pandas as pd
import ipaddress
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from pathlib import Path
from collections import Counter


# CONFIGURATION

PHASE = "intensive"

ROOT_DIR = Path(__file__).resolve().parent

INTENSIVE_DIR = ROOT_DIR / PHASE
IDLE_RESULTS_DIR = ROOT_DIR / "idle_results"

OUTPUT_DIR = ROOT_DIR / "intensive_results"

DEVICE_MAPPING_FILE = ROOT_DIR / "device_mapping.json"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

DEVICE_PCAP_MAP = {

    "Dusty520WET":
        "vacuum_tests.pcap",

    "Wiz Bulb":
        "wiz_bulb_tests.pcap",

    "Tapo C100":
        "tapo_camera.pcap"
}



# LOAD DEVICE MAPPING

with open(DEVICE_MAPPING_FILE, "r") as f:
    DEVICES = json.load(f)



# GET PCAP FILES

PCAP_FILES = list(INTENSIVE_DIR.glob("*.pcap")) + \
             list(INTENSIVE_DIR.glob("*.pcapng"))

print(f"Found {len(PCAP_FILES)} intensive capture files")



# HELPER FUNCTIONS

def is_public_ip(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except:
        return False


# MAIN ANALYSIS

for device_name, info in DEVICES.items():

    TARGET_MAC = info["mac"].lower()

    print("\n================================")
    print(f"Analyzing intensive phase: {device_name}")
    print("================================")

    # LOAD IDLE BASELINE
    idle_file = IDLE_RESULTS_DIR / f"{device_name}.json"

    if not idle_file.exists():
        print(f"Idle baseline missing for {device_name}")
        continue

    with open(idle_file, "r") as f:
        idle_data = json.load(f)

    idle_dns = set(idle_data.get("dns_queries", []))
    idle_endpoints = set(idle_data.get("endpoints", []))
    idle_protocols = set(
        idle_data.get("protocols", {}).keys()
    )

    idle_avg_packets = idle_data.get(
        "avg_packets_per_min",
        0
    )

    # INTENSIVE PHASE COLLECTION
    intensive_dns = set()
    intensive_endpoints = set()
    intensive_protocols = Counter()

    packet_rows = []

    total_packets = 0

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

                timestamp = float(pkt.sniff_timestamp)

                packet_length = int(pkt.length)

                direction = "unknown"

                
                # UPLOAD / DOWNLOAD
                if src_mac == TARGET_MAC:
                    direction = "upload"

                elif dst_mac == TARGET_MAC:
                    direction = "download"

                
                # PROTOCOLS
                intensive_protocols[
                    pkt.highest_layer
                ] += 1

                
                # DNS
                if hasattr(pkt, "dns"):

                    try:

                        query = pkt.dns.qry_name

                        intensive_dns.add(query)

                    except:
                        pass

                
                # ENDPOINTS
                if hasattr(pkt, "ip"):

                    try:

                        src_ip = pkt.ip.src
                        dst_ip = pkt.ip.dst

                        if is_public_ip(src_ip):
                            intensive_endpoints.add(src_ip)

                        if is_public_ip(dst_ip):
                            intensive_endpoints.add(dst_ip)

                    except:
                        pass

                
                # SAVE TRAFFIC DATA
                packet_rows.append({
                    "timestamp": timestamp,
                    "packet_length": packet_length,
                    "direction": direction
                })

            except:
                continue

        capture.close()

    # CREATE DATAFRAME
    if not packet_rows:
        print(f"No packets for {device_name}")
        continue

    df = pd.DataFrame(packet_rows)

    df["datetime"] = (
    pd.to_datetime(
        df["timestamp"],
        unit="s",
        utc=True
    )
    .dt.tz_convert("Europe/Helsinki")
)

    df["second"] = df["datetime"].dt.floor("S")

    # UPLOAD / DOWNLOAD TIMESERIES
    upload_df = df[
        df["direction"] == "upload"
    ]

    download_df = df[
        df["direction"] == "download"
    ]

    upload_series = upload_df.groupby(
        "second"
    )["packet_length"].sum()

    download_series = download_df.groupby(
        "second"
    )["packet_length"].sum()

    traffic_df = pd.DataFrame({
        "upload_bytes": upload_series,
        "download_bytes": download_series
    }).fillna(0)

    traffic_df.reset_index(inplace=True)

    # TRAFFIC SPIKE DETECTION
    traffic_df["total_bytes"] = \
        traffic_df["upload_bytes"] + \
        traffic_df["download_bytes"]

    avg_traffic = traffic_df[
        "total_bytes"
    ].mean()

    traffic_df["spike"] = \
        traffic_df["total_bytes"] > \
        (avg_traffic * 2)

    spike_count = int(
        traffic_df["spike"].sum()
    )

    # ANOMALY DETECTION
    new_dns = sorted(
        intensive_dns - idle_dns
    )

    new_endpoints = sorted(
        intensive_endpoints - idle_endpoints
    )

    new_protocols = sorted(
        set(intensive_protocols.keys()) -
        idle_protocols
    )


    # SAVE ANOMALY RESULTS
    anomaly_output = {
        "device": device_name,

        "new_dns_queries": new_dns,

        "new_endpoints": new_endpoints,

        "new_protocols": new_protocols,

        "traffic_spikes_detected": spike_count,

        "idle_avg_packets_per_min":
            idle_avg_packets,

        "intensive_total_packets":
            total_packets
    }

    with open(
        OUTPUT_DIR / f"{device_name}_anomalies.json",
        "w"
    ) as f:

        json.dump(
            anomaly_output,
            f,
            indent=4
        )


    # SAVE TRAFFIC CSV
    traffic_df.to_csv(
        OUTPUT_DIR /
        f"{device_name}_traffic.csv",
        index=False
    )

    # GENERATE GRAPH
    plt.figure(figsize=(14, 6))

    plt.plot(
        traffic_df["second"],
        traffic_df["upload_bytes"],
        label="Upload Bytes/sec"
    )

    plt.plot(
        traffic_df["second"],
        traffic_df["download_bytes"],
        label="Download Bytes/sec"
    )

    
    # MARK SPIKES
    spike_df = traffic_df[
        traffic_df["spike"] == True
    ]

    plt.scatter(
        spike_df["second"],
        spike_df["total_bytes"],
        label="Traffic Spike"
    )

    plt.title(
        f"{device_name} Intensive Phase Traffic"
    )

    plt.xlabel("Timestamp")
    plt.ylabel("Bytes per Second")

    plt.legend()

    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR /
        f"{device_name}_traffic_graph.png"
    )

    plt.close()

    # PRINT SUMMARY
    print("\n--- RESULTS ---")

    print(f"Traffic spikes: {spike_count}")

    print("\nNew DNS queries:")
    for dns in new_dns:
        print(f"  - {dns}")

    print("\nNew endpoints:")
    for ep in new_endpoints:
        print(f"  - {ep}")

    print("\nNew protocols:")
    for proto in new_protocols:
        print(f"  - {proto}")

print("\n================================")
print("INTENSIVE ANALYSIS COMPLETE")
print("================================")