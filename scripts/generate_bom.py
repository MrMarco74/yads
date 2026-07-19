#!/usr/bin/env python3
"""
YADS Bill of Materials Generator

Generates Software Bill of Materials (SBOM) and Cryptography Bill of Materials (CBOM)
in CycloneDX format for supply chain security and compliance.

Usage:
    python scripts/generate_bom.py
    python scripts/generate_bom.py --output-dir releases/
    python scripts/generate_bom.py --sbom-only
    python scripts/generate_bom.py --cbom-only
"""

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class SBOMGenerator:
    """Generate Software Bill of Materials using Syft or pip analysis."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.version = self._get_version()

    def _get_version(self) -> str:
        """Extract version from config.py."""
        config_file = self.project_root / "yads" / "config.py"
        if config_file.exists():
            content = config_file.read_text()
            match = re.search(r'VERSION:\s*str\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                return match.group(1)
        return "unknown"

    def generate(self, output_dir: Path) -> Dict[str, Path]:
        """
        Generate SBOM in JSON and XML formats.

        Args:
            output_dir: Directory to write output files

        Returns:
            Dict with paths to generated files
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Try Syft first (preferred), fallback to pip-based generation
        if self._syft_available():
            print("  Using Syft for SBOM generation...")
            sbom = self._generate_with_syft()
        else:
            print("  Syft not found, using pip-based SBOM generation...")
            sbom = self._generate_from_pip()

        # Write JSON
        json_path = output_dir / "sbom.json"
        with open(json_path, "w") as f:
            json.dump(sbom, f, indent=2)

        # Write XML
        xml_path = output_dir / "sbom.xml"
        xml_content = self._convert_to_xml(sbom)
        with open(xml_path, "w") as f:
            f.write(xml_content)

        return {"json": json_path, "xml": xml_path}

    def _syft_available(self) -> bool:
        """Check if Syft is installed."""
        try:
            subprocess.run(
                ["syft", "--version"],
                capture_output=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _generate_with_syft(self) -> Dict[str, Any]:
        """Generate SBOM using Syft."""
        result = subprocess.run(
            ["syft", ".", "-o", "cyclonedx-json"],
            cwd=self.project_root,
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)

    def _generate_from_pip(self) -> Dict[str, Any]:
        """Generate SBOM from pip packages (fallback method)."""
        # Get installed packages
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            check=True
        )
        packages = json.loads(result.stdout)

        # Read requirements.txt for direct dependencies
        requirements_file = self.project_root / "requirements.txt"
        direct_deps = set()
        if requirements_file.exists():
            for line in requirements_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    # Extract package name
                    match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                    if match:
                        direct_deps.add(match.group(1).lower())

        # Build CycloneDX structure
        components = []
        for pkg in packages:
            pkg_name = pkg["name"]
            pkg_version = pkg["version"]

            # Get license info
            license_info = self._get_package_license(pkg_name)

            component = {
                "type": "library",
                "bom-ref": f"pkg:pypi/{pkg_name}@{pkg_version}",
                "name": pkg_name,
                "version": pkg_version,
                "purl": f"pkg:pypi/{pkg_name}@{pkg_version}",
            }

            if license_info:
                component["licenses"] = [{"license": {"id": license_info}}]

            # Mark if direct dependency
            if pkg_name.lower() in direct_deps:
                component["scope"] = "required"
            else:
                component["scope"] = "optional"

            components.append(component)

        return {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "YADS",
                        "name": "YADS SBOM Generator",
                        "version": self.version
                    }
                ],
                "component": {
                    "type": "application",
                    "name": "YADS",
                    "version": self.version,
                    "description": "Yet Another Domain Scanner - Attack Surface Management",
                    "licenses": [{"license": {"id": "MIT"}}]
                }
            },
            "components": components
        }

    def _get_package_license(self, package_name: str) -> Optional[str]:
        """Get SPDX license identifier for a package."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "show", package_name],
                capture_output=True,
                text=True,
                check=True
            )
            for line in result.stdout.splitlines():
                if line.startswith("License:"):
                    license_text = line.split(":", 1)[1].strip()
                    # Map common licenses to SPDX IDs
                    license_map = {
                        "MIT": "MIT",
                        "Apache 2.0": "Apache-2.0",
                        "Apache-2.0": "Apache-2.0",
                        "BSD": "BSD-3-Clause",
                        "BSD-3-Clause": "BSD-3-Clause",
                        "BSD-2-Clause": "BSD-2-Clause",
                        "GPL": "GPL-3.0-only",
                        "LGPL": "LGPL-3.0-only",
                        "ISC": "ISC",
                        "MPL": "MPL-2.0",
                        "PSF": "PSF-2.0",
                    }
                    for key, spdx in license_map.items():
                        if key.lower() in license_text.lower():
                            return spdx
                    return None
        except subprocess.CalledProcessError:
            pass
        return None

    def _convert_to_xml(self, sbom: Dict[str, Any]) -> str:
        """Convert CycloneDX JSON to XML format."""
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"',
            f'     serialNumber="{sbom.get("serialNumber", "")}"',
            '     version="1">',
            '  <metadata>',
            f'    <timestamp>{sbom["metadata"]["timestamp"]}</timestamp>',
            '    <tools>',
        ]

        for tool in sbom["metadata"].get("tools", []):
            xml_lines.append('      <tool>')
            xml_lines.append(f'        <vendor>{tool.get("vendor", "")}</vendor>')
            xml_lines.append(f'        <name>{tool.get("name", "")}</name>')
            xml_lines.append(f'        <version>{tool.get("version", "")}</version>')
            xml_lines.append('      </tool>')

        xml_lines.append('    </tools>')

        # Main component
        comp = sbom["metadata"].get("component", {})
        xml_lines.append('    <component type="application">')
        xml_lines.append(f'      <name>{comp.get("name", "")}</name>')
        xml_lines.append(f'      <version>{comp.get("version", "")}</version>')
        if comp.get("description"):
            xml_lines.append(f'      <description>{comp.get("description", "")}</description>')
        xml_lines.append('    </component>')
        xml_lines.append('  </metadata>')

        # Components
        xml_lines.append('  <components>')
        for comp in sbom.get("components", []):
            xml_lines.append(f'    <component type="{comp.get("type", "library")}" bom-ref="{comp.get("bom-ref", "")}">')
            xml_lines.append(f'      <name>{comp.get("name", "")}</name>')
            xml_lines.append(f'      <version>{comp.get("version", "")}</version>')
            if comp.get("purl"):
                xml_lines.append(f'      <purl>{comp.get("purl")}</purl>')
            if comp.get("licenses"):
                xml_lines.append('      <licenses>')
                for lic in comp["licenses"]:
                    if lic.get("license", {}).get("id"):
                        xml_lines.append(f'        <license><id>{lic["license"]["id"]}</id></license>')
                xml_lines.append('      </licenses>')
            xml_lines.append('    </component>')
        xml_lines.append('  </components>')
        xml_lines.append('</bom>')

        return "\n".join(xml_lines)


class CBOMGenerator:
    """Generate Cryptography Bill of Materials by scanning the codebase."""

    # Patterns to detect cryptographic usage
    CRYPTO_PATTERNS = {
        "hash_algorithms": {
            "MD5": r'\b(?:md5|MD5)\b',
            "SHA-1": r'\b(?:sha1|SHA1|sha-1|SHA-1)\b',
            "SHA-256": r'\b(?:sha256|SHA256|sha-256|SHA-256)\b',
            "SHA-384": r'\b(?:sha384|SHA384|sha-384|SHA-384)\b',
            "SHA-512": r'\b(?:sha512|SHA512|sha-512|SHA-512)\b',
            "BLAKE2": r'\b(?:blake2b|blake2s|BLAKE2)\b',
            "SHA-3": r'\b(?:sha3|SHA3)\b',
        },
        "symmetric_ciphers": {
            "AES": r'\b(?:AES|aes)(?:-(?:128|192|256))?(?:-(?:CBC|GCM|CTR|ECB))?\b',
            "AES-GCM": r'\b(?:AES-GCM|aesgcm|AESGCM)\b',
            "ChaCha20": r'\b(?:ChaCha20|chacha20)\b',
            "ChaCha20-Poly1305": r'\b(?:ChaCha20-Poly1305|chacha20-poly1305)\b',
            "3DES": r'\b(?:3DES|TripleDES|DES3)\b',
            "Fernet": r'\b(?:Fernet|fernet)\b',
        },
        "asymmetric_algorithms": {
            "RSA": r'\b(?:RSA|rsa)(?:-(?:2048|3072|4096))?\b',
            "ECDSA": r'\b(?:ECDSA|ecdsa)\b',
            "Ed25519": r'\b(?:Ed25519|ed25519)\b',
            "ECDH": r'\b(?:ECDH|ecdh)\b',
            "X25519": r'\b(?:X25519|x25519)\b',
            "DSA": r'\b(?:DSA|dsa)\b',
        },
        "key_derivation": {
            "PBKDF2": r'\b(?:PBKDF2|pbkdf2)\b',
            "bcrypt": r'\b(?:bcrypt|Bcrypt|BCRYPT)\b',
            "scrypt": r'\b(?:scrypt|Scrypt)\b',
            "Argon2": r'\b(?:Argon2|argon2)\b',
            "HKDF": r'\b(?:HKDF|hkdf)\b',
        },
        "protocols": {
            "TLS 1.2": r'\b(?:TLSv1\.2|TLS_1_2|TLS1_2|tlsv1\.2)\b',
            "TLS 1.3": r'\b(?:TLSv1\.3|TLS_1_3|TLS1_3|tlsv1\.3)\b',
            "SSL": r'\b(?:SSLv3|SSL_CONTEXT|ssl\.create)\b',
            "HTTPS": r'\bhttps://\b',
        },
        "macs": {
            "HMAC": r'\b(?:HMAC|hmac)\b',
            "Poly1305": r'\b(?:Poly1305|poly1305)\b',
            "CMAC": r'\b(?:CMAC|cmac)\b',
        },
        "random": {
            "secrets": r'\bsecrets\.\b',
            "os.urandom": r'\bos\.urandom\b',
            "random.SystemRandom": r'\brandom\.SystemRandom\b',
        }
    }

    # Crypto library imports
    CRYPTO_IMPORTS = [
        ("cryptography", "Cryptographic primitives library"),
        ("pycryptodome", "PyCryptodome - cryptographic library"),
        ("pyotp", "One-time password library (TOTP/HOTP)"),
        ("passlib", "Password hashing library"),
        ("bcrypt", "bcrypt password hashing"),
        ("hashlib", "Python standard library hashing"),
        ("hmac", "Python HMAC implementation"),
        ("ssl", "Python SSL/TLS support"),
        ("secrets", "Cryptographically secure random numbers"),
        ("nacl", "PyNaCl - libsodium bindings"),
        ("jwt", "JSON Web Tokens"),
        ("pyjwt", "PyJWT - JSON Web Tokens"),
        ("jose", "python-jose - JavaScript Object Signing"),
        ("fernet", "Fernet symmetric encryption"),
    ]

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.version = self._get_version()

    def _get_version(self) -> str:
        """Extract version from config.py."""
        config_file = self.project_root / "yads" / "config.py"
        if config_file.exists():
            content = config_file.read_text()
            match = re.search(r'VERSION:\s*str\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                return match.group(1)
        return "unknown"

    def generate(self, output_dir: Path) -> Dict[str, Path]:
        """
        Generate CBOM in JSON and XML formats.

        Args:
            output_dir: Directory to write output files

        Returns:
            Dict with paths to generated files
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Scan codebase
        crypto_findings = self._scan_codebase()

        # Build CBOM
        cbom = self._build_cbom(crypto_findings)

        # Write JSON
        json_path = output_dir / "cbom.json"
        with open(json_path, "w") as f:
            json.dump(cbom, f, indent=2)

        # Write XML
        xml_path = output_dir / "cbom.xml"
        xml_content = self._convert_to_xml(cbom)
        with open(xml_path, "w") as f:
            f.write(xml_content)

        return {"json": json_path, "xml": xml_path}

    def _scan_codebase(self) -> Dict[str, List[Dict[str, Any]]]:
        """Scan Python files for cryptographic usage."""
        findings = {
            "algorithms": [],
            "libraries": [],
            "protocols": [],
        }

        # Directories to scan
        scan_dirs = [
            self.project_root / "yads",
            self.project_root / "scripts",
        ]

        # Track unique findings
        seen_algorithms = set()
        seen_libraries = set()
        seen_protocols = set()

        for scan_dir in scan_dirs:
            if not scan_dir.exists():
                continue

            for py_file in scan_dir.rglob("*.py"):
                try:
                    content = py_file.read_text(errors="ignore")
                    relative_path = str(py_file.relative_to(self.project_root))

                    # Check crypto imports
                    for lib_name, description in self.CRYPTO_IMPORTS:
                        pattern = rf'\bimport\s+{lib_name}\b|\bfrom\s+{lib_name}\b'
                        if re.search(pattern, content) and lib_name not in seen_libraries:
                            seen_libraries.add(lib_name)
                            findings["libraries"].append({
                                "name": lib_name,
                                "description": description,
                                "locations": [relative_path]
                            })

                    # Check crypto patterns
                    for category, patterns in self.CRYPTO_PATTERNS.items():
                        for algo_name, pattern in patterns.items():
                            if re.search(pattern, content):
                                if category == "protocols":
                                    if algo_name not in seen_protocols:
                                        seen_protocols.add(algo_name)
                                        findings["protocols"].append({
                                            "name": algo_name,
                                            "category": category,
                                            "locations": [relative_path]
                                        })
                                else:
                                    if algo_name not in seen_algorithms:
                                        seen_algorithms.add(algo_name)
                                        findings["algorithms"].append({
                                            "name": algo_name,
                                            "category": category,
                                            "locations": [relative_path]
                                        })

                except Exception as e:
                    print(f"    Warning: Could not scan {py_file}: {e}")

        return findings

    def _build_cbom(self, findings: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Build CycloneDX CBOM structure."""
        components = []

        # Add cryptographic algorithms
        for algo in findings["algorithms"]:
            component = {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto:{algo['name'].lower().replace(' ', '-')}",
                "name": algo["name"],
                "cryptoProperties": {
                    "assetType": self._get_asset_type(algo["category"]),
                    "algorithmProperties": {
                        "primitive": self._get_primitive(algo["category"]),
                    }
                }
            }

            # Add quantum-safe indicator
            quantum_safe = self._is_quantum_safe(algo["name"])
            if quantum_safe is not None:
                component["cryptoProperties"]["nistQuantumSecurityLevel"] = 0 if not quantum_safe else 1

            components.append(component)

        # Add crypto libraries as services
        services = []
        for lib in findings["libraries"]:
            services.append({
                "bom-ref": f"service:crypto-lib:{lib['name']}",
                "name": lib["name"],
                "description": lib["description"],
            })

        # Add protocols
        for proto in findings["protocols"]:
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": f"crypto:proto:{proto['name'].lower().replace(' ', '-').replace('.', '')}",
                "name": proto["name"],
                "cryptoProperties": {
                    "assetType": "protocol",
                }
            })

        return {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "YADS",
                        "name": "YADS CBOM Generator",
                        "version": self.version
                    }
                ],
                "component": {
                    "type": "application",
                    "name": "YADS",
                    "version": self.version,
                    "description": "Yet Another Domain Scanner - Enterprise Attack Surface Management"
                }
            },
            "components": components,
            "services": services,
        }

    def _get_asset_type(self, category: str) -> str:
        """Map category to CycloneDX asset type."""
        mapping = {
            "hash_algorithms": "algorithm",
            "symmetric_ciphers": "algorithm",
            "asymmetric_algorithms": "algorithm",
            "key_derivation": "algorithm",
            "macs": "algorithm",
            "random": "algorithm",
            "protocols": "protocol",
        }
        return mapping.get(category, "algorithm")

    def _get_primitive(self, category: str) -> str:
        """Map category to cryptographic primitive."""
        mapping = {
            "hash_algorithms": "hash",
            "symmetric_ciphers": "block-cipher",
            "asymmetric_algorithms": "public-key-encryption",
            "key_derivation": "key-derivation",
            "macs": "mac",
            "random": "random-number-generator",
        }
        return mapping.get(category, "unknown")

    def _is_quantum_safe(self, algo_name: str) -> Optional[bool]:
        """Check if algorithm is quantum-safe."""
        # Not quantum safe
        not_safe = ["RSA", "ECDSA", "ECDH", "DSA", "Ed25519", "X25519",
                    "SHA-1", "MD5", "3DES"]
        # Quantum safe (or not applicable)
        safe = ["AES-256", "SHA-256", "SHA-384", "SHA-512", "SHA-3",
                "BLAKE2", "ChaCha20-Poly1305"]

        for ns in not_safe:
            if ns.lower() in algo_name.lower():
                return False
        for s in safe:
            if s.lower() in algo_name.lower():
                return True
        return None

    def _convert_to_xml(self, cbom: Dict[str, Any]) -> str:
        """Convert CycloneDX JSON to XML format."""
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"',
            f'     serialNumber="{cbom.get("serialNumber", "")}"',
            '     version="1">',
            '  <metadata>',
            f'    <timestamp>{cbom["metadata"]["timestamp"]}</timestamp>',
            '    <tools>',
        ]

        for tool in cbom["metadata"].get("tools", []):
            xml_lines.append('      <tool>')
            xml_lines.append(f'        <vendor>{tool.get("vendor", "")}</vendor>')
            xml_lines.append(f'        <name>{tool.get("name", "")}</name>')
            xml_lines.append(f'        <version>{tool.get("version", "")}</version>')
            xml_lines.append('      </tool>')

        xml_lines.append('    </tools>')

        comp = cbom["metadata"].get("component", {})
        xml_lines.append('    <component type="application">')
        xml_lines.append(f'      <name>{comp.get("name", "")}</name>')
        xml_lines.append(f'      <version>{comp.get("version", "")}</version>')
        if comp.get("description"):
            xml_lines.append(f'      <description>{comp.get("description", "")}</description>')
        xml_lines.append('    </component>')
        xml_lines.append('  </metadata>')

        # Components (crypto assets)
        xml_lines.append('  <components>')
        for comp in cbom.get("components", []):
            comp_type = comp.get("type", "cryptographic-asset")
            xml_lines.append(f'    <component type="{comp_type}" bom-ref="{comp.get("bom-ref", "")}">')
            xml_lines.append(f'      <name>{comp.get("name", "")}</name>')
            if comp.get("cryptoProperties"):
                xml_lines.append('      <cryptoProperties>')
                props = comp["cryptoProperties"]
                if props.get("assetType"):
                    xml_lines.append(f'        <assetType>{props["assetType"]}</assetType>')
                if props.get("algorithmProperties"):
                    xml_lines.append('        <algorithmProperties>')
                    algo_props = props["algorithmProperties"]
                    if algo_props.get("primitive"):
                        xml_lines.append(f'          <primitive>{algo_props["primitive"]}</primitive>')
                    xml_lines.append('        </algorithmProperties>')
                if props.get("nistQuantumSecurityLevel") is not None:
                    xml_lines.append(f'        <nistQuantumSecurityLevel>{props["nistQuantumSecurityLevel"]}</nistQuantumSecurityLevel>')
                xml_lines.append('      </cryptoProperties>')
            xml_lines.append('    </component>')
        xml_lines.append('  </components>')

        # Services (crypto libraries)
        if cbom.get("services"):
            xml_lines.append('  <services>')
            for svc in cbom["services"]:
                xml_lines.append(f'    <service bom-ref="{svc.get("bom-ref", "")}">')
                xml_lines.append(f'      <name>{svc.get("name", "")}</name>')
                if svc.get("description"):
                    xml_lines.append(f'      <description>{svc.get("description", "")}</description>')
                xml_lines.append('    </service>')
            xml_lines.append('  </services>')

        xml_lines.append('</bom>')

        return "\n".join(xml_lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate SBOM and CBOM for YADS",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="releases",
        help="Output directory for BOM files (default: releases)"
    )
    parser.add_argument(
        "--sbom-only",
        action="store_true",
        help="Generate only SBOM"
    )
    parser.add_argument(
        "--cbom-only",
        action="store_true",
        help="Generate only CBOM"
    )

    args = parser.parse_args()

    # Determine project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    output_dir = project_root / args.output_dir

    print("\n" + "=" * 60)
    print("  YADS Bill of Materials Generator")
    print("=" * 60 + "\n")

    generated_files = []

    # Generate SBOM
    if not args.cbom_only:
        print("Generating Software Bill of Materials (SBOM)...")
        sbom_gen = SBOMGenerator(project_root)
        sbom_files = sbom_gen.generate(output_dir)
        generated_files.extend(sbom_files.values())
        print(f"  ✅ SBOM JSON: {sbom_files['json']}")
        print(f"  ✅ SBOM XML:  {sbom_files['xml']}")

    # Generate CBOM
    if not args.sbom_only:
        print("\nGenerating Cryptography Bill of Materials (CBOM)...")
        cbom_gen = CBOMGenerator(project_root)
        cbom_files = cbom_gen.generate(output_dir)
        generated_files.extend(cbom_files.values())
        print(f"  ✅ CBOM JSON: {cbom_files['json']}")
        print(f"  ✅ CBOM XML:  {cbom_files['xml']}")

    print("\n" + "=" * 60)
    print(f"  Generated {len(generated_files)} files in {output_dir}")
    print("=" * 60 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
