import json
import ipaddress
from pathlib import Path

from ipwhois import IPWhois

# PATHS
ROOT_DIR = Path(__file__).resolve().parent
INPUT_DIR = ROOT_DIR / "idle_results"

# GET JSON FILES
JSON_FILES = list(INPUT_DIR.glob("*.json"))

print(f"Found {len(JSON_FILES)} result files")


# STORE RESULTS
all_results = []

# PROCESS FILES
for json_file in JSON_FILES:

    with open(json_file, "r") as f:
        data = json.load(f)

    device_name = data.get("device", "Unknown")
    endpoints = data.get("endpoints", [])

    print("\n================================")
    print(f"Device: {device_name}")
    print("================================")

    for ip in endpoints:

        try:
            # Skip invalid/private IPs just in case
            if ipaddress.ip_address(ip).is_private:
                continue

            print(f"Looking up: {ip}")

            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)

            org = result.get("network", {}).get("name", "Unknown")
            country = result.get("network", {}).get("country", "Unknown")

            print(f"Organization: {org}")
            print(f"Country: {country}")

            all_results.append({
                "device": device_name,
                "ip": ip,
                "organization": org,
                "country": country
            })

        except Exception as e:

            print(f"Failed lookup for {ip}")
            print(e)

# SAVE RESULTS
output_file = ROOT_DIR / "endpoint_whois_results.json"

with open(output_file, "w") as f:
    json.dump(all_results, f, indent=4)

print("\n================================")
print("WHOIS Analysis Complete")
print("================================")
print(f"Saved to: {output_file}")