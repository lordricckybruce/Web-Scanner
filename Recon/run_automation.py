#!/usr/bin/env python3

import os
import subprocess
from datetime import datetime

# Set your target domain
target = input("Enter the target domain (e.g., example.com): ").strip()

# Create output directory
output_dir = f"Recon-{target}"
os.makedirs(output_dir, exist_ok=True)

def run_command(command, output_file):
    """Run a shell command and write output to a file."""
    print(f"Running: {command}")
    try:
        result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
        with open(os.path.join(output_dir, output_file), "w") as f:
            f.write(result)
    except subprocess.CalledProcessError:
        with open(os.path.join(output_dir, output_file), "w") as f:
            f.write(f"[ERROR] Command failed: {command}")

# 1. WHOIS
run_command(f"whois {target}", "whois.txt")

# 2. NSLOOKUP
run_command(f"nslookup {target}", "nslookup.txt")

# 3. NMAP (top 100 ports)
run_command(f"nmap -Pn --top-ports 100 -T4 {target}", "nmap.txt")

# 4. Sublist3r
run_command(f"sublist3r -d {target} -o {output_dir}/sublist3r.txt", "sublist3r.txt")

# 5. theHarvester using Bing
run_command(f"theHarvester -d {target} -b bing -f {output_dir}/theharvester", "theharvester.txt")

print(f"\nRecon complete. All outputs saved in: {output_dir}")
