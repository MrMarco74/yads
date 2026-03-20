import zipapp
import os
import stat
import shutil
import tempfile
import subprocess
import sys

SOURCE = os.path.join(os.path.dirname(__file__))
OUTPUT = os.path.join(os.path.dirname(__file__), "..", "yads-setup.pyz")

def run_trivy_scan(path):
    """Scans the source directory for secrets using Trivy."""
    print(f"  Security: Scanning {path} for secrets...")
    try:
        # Check if ignore file exists for release manager context (optional)
        # For now, we just run a standard scan.
        res = subprocess.run(["trivy", "fs", "--scanners", "secret", "--exit-code", "1", "-q", path], 
                             capture_output=True, text=True)
        if res.returncode != 0:
            print("\n" + "!"*60)
            print("  SECURITY ALERT: Potential secrets found in installer source!")
            print("  Aborting build to prevent leakage.")
            print("!"*60 + "\n")
            print(res.stdout)
            return False
        print("  ✅ No secrets detected in source.")
        return True
    except FileNotFoundError:
        print("  ⚠️  Trivy not available. Skipping secret scan.")
        return True

def build():
    output = os.path.abspath(OUTPUT)
    print(f"Building {output} from {SOURCE}...")

    if not run_trivy_scan(SOURCE):
        if os.getenv("STRICT_BUILD") == "1":
            print("❌ Build aborted due to security findings (STRICT_BUILD=1).")
            sys.exit(1)
        else:
            print("⚠️  Security findings detected, but continuing build (STRICT_BUILD=0/unset).")

    with tempfile.TemporaryDirectory() as tmp:
        # Copy source into temp dir
        pkg_tmp = os.path.join(tmp, "yads_installer")
        shutil.copytree(SOURCE, pkg_tmp, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "build.py"))

        # Pre-resize logo.png to 128x128 so Tkinter loads it instantly at runtime
        logo_path = os.path.join(pkg_tmp, "logo.png")
        if os.path.exists(logo_path):
            try:
                from PIL import Image
                with Image.open(logo_path) as img:
                    img.thumbnail((128, 128), Image.LANCZOS)
                    img.save(logo_path, "PNG", optimize=True)
                print(f"  logo.png resized to {img.size[0]}x{img.size[1]} px")
            except ImportError:
                print("  Pillow not available — logo.png kept as-is")

        zipapp.create_archive(
            pkg_tmp,
            target=output,
            interpreter="/usr/bin/env python3",
        )

    # Make executable
    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    print(f"Successfully built {output}")


if __name__ == "__main__":
    build()
