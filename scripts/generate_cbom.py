#!/usr/bin/env python3
import json
import sys
import os

def generate_cbom(input_path="sbom.json", output_path="cbom.json"):
    """
    Parses a CycloneDX SBOM JSON and filters for cryptographic libraries
    to produce a CBOM (Cryptography Bill of Materials).
    """
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found.")
        sys.exit(1)

    try:
        with open(input_path, "r") as f:
            sbom = json.load(f)
    except Exception as e:
        print(f"Error reading SBOM: {e}")
        sys.exit(1)

    # List of known crypto library patterns (normalized to lowercase)
    # This is a heuristic list and should be expanded.
    crypto_keywords = [
        "crypto", "openssl", "libssl", "ssl", "tls",
        "sodium", "bcrypt", "scrypt", "argon2",
        "gnupg", "gpg", "ssh", "pyca", "auth"
    ]

    cbom_components = []
    
    components = sbom.get("components", [])
    print(f"Scanning {len(components)} components for cryptographic assets...")

    for comp in components:
        name = comp.get("name", "").lower()
        description = comp.get("description", "").lower()
        
        # Check if any keyword maps to the component name or description
        if any(keyword in name for keyword in crypto_keywords):
            # It's a match!
            cbom_components.append(comp)
            continue
            
        # Optional: Deep check description if name didn't match
        # if any(keyword in description for keyword in crypto_keywords):
        #     cbom_components.append(comp)

    # Create CBOM structure (CycloneDX compliant subset)
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": sbom.get("specVersion", "1.4"),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "YADS Cryptography Bill of Materials",
                "version": "1.0.0"
            }
        },
        "components": cbom_components
    }

    try:
        with open(output_path, "w") as f:
            json.dump(cbom, f, indent=2)
        print(f"Successfully generated {output_path} with {len(cbom_components)} crypto components.")
    except Exception as e:
        print(f"Error writing CBOM: {e}")
        sys.exit(1)

if __name__ == "__main__":
    generate_cbom()
