#!/bin/bash

# CunningRecon - A Powerful Reconnaissance and Vulnerability Scanner
# Author: Alexander Chukwumebuka Ireka
# Version: 1.0

# Colors
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'

echo -e "${GREEN}===[ CunningRecon: Recon + Vuln Scanner ]===${NC}"
read -p "Enter the target domain (e.g., example.com): " target

# Create folder for output
mkdir -p $target/recon
cd $target/recon

# Subdomain Enumeration
echo -e "${GREEN}[+] Enumerating subdomains with subfinder...${NC}"
subfinder -d $target -silent | tee subdomains.txt

# Check alive domains
echo -e "${GREEN}[+] Checking for alive domains...${NC}"
cat subdomains.txt | httpx -silent | tee alive.txt

# Run Nuclei
echo -e "${GREEN}[+] Running nuclei on alive domains...${NC}"
nuclei -l alive.txt -o nuclei_results.txt

# Wayback URLs
echo -e "${GREEN}[+] Gathering Wayback URLs...${NC}"
cat subdomains.txt | waybackurls | tee wayback.txt

# SQLi Scanner - Simple payload test (GET param)
echo -e "${GREEN}[+] Testing for basic SQL Injection payloads...${NC}"
payload="' OR 1=1--"
while read url; do
  if curl -s "$url$payload" | grep -q "sql"; then
    echo "[!] Possible SQLi on: $url$payload" | tee -a sqli_results.txt
  fi
done < alive.txt

echo -e "${GREEN}[✓] Recon and scanning complete! Check the $target/recon/ folder.${NC}"
