"""Download and cache MITRE ATT&CK Enterprise framework data"""
import requests
import json
import os

MITRE_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTPUT_FILE = "data/mitre_enterprise.json"

def download_mitre_data():
    print("[*] Downloading MITRE ATT&CK Enterprise data...")
    
    os.makedirs('data', exist_ok=True)
    
    response = requests.get(MITRE_ENTERPRISE_URL, timeout=30)
    response.raise_for_status()
    
    data = response.json()
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"[+] Downloaded {len(data['objects'])} MITRE objects")
    print(f"[+] Saved to {OUTPUT_FILE}")
    
    # Print some stats
    techniques = [obj for obj in data['objects'] if obj['type'] == 'attack-pattern']
    tactics = [obj for obj in data['objects'] if obj['type'] == 'x-mitre-tactic']
    
    print(f"    - Techniques: {len(techniques)}")
    print(f"    - Tactics: {len(tactics)}")

if __name__ == '__main__':
    download_mitre_data()
