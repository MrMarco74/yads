import sys
import os
import subprocess
import threading
from pathlib import Path

def check_dependencies():
    """Checks for PySide6 and QFluentWidgets, attempts install if missing."""
    try:
        import PySide6
        import qfluentwidgets
        return True
    except ImportError:
        print("Required dependencies (PySide6/qfluentwidgets) missing.")
        # Attempt to install for the user if they have pip
        try:
            print("Attempting to install missing components...")
            # Try normal install first
            res = subprocess.run([sys.executable, "-m", "pip", "install", "PySide6", "PySide6-Fluent-Widgets"], capture_output=True)
            if res.returncode != 0:
                print("Standard install blocked. Trying with --break-system-packages...")
                subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", "PySide6", "PySide6-Fluent-Widgets"], check=True)
            return True
        except Exception as e:
            print(f"Auto-install failed: {e}")
            return False

def _create_desktop_entry():
    """Create .desktop file and icon — called once in a background thread."""
    desktop_dir = Path.home() / ".local" / "share" / "applications"
    icon_dir = Path.home() / ".local" / "share" / "icons"
    pyz_path = Path(sys.argv[0]).resolve()

    icon_path = "yads-setup"
    try:
        icon_dir.mkdir(parents=True, exist_ok=True)
        dest_icon = icon_dir / "yads-setup.png"
        
        # In a .pyz we might need to extract the logo
        import zipfile
        with zipfile.ZipFile(pyz_path, 'r') as z:
            with z.open('logo.png') as src, open(dest_icon, 'wb') as f:
                f.write(src.read())
        icon_path = str(dest_icon)
    except Exception as e:
        print(f"[Desktop] Could not write icon: {e}", file=sys.stderr)

    try:
        desktop_dir.mkdir(parents=True, exist_ok=True)
        desktop_path = desktop_dir / "yads-setup.desktop"
        content = (
            "[Desktop Entry]\n"
            "Version=1.0\n"
            "Type=Application\n"
            "Name=YADS Setup\n"
            "Comment=YADS Installer & Update Tool\n"
            f"Exec=python3 {pyz_path}\n"
            f"Icon={icon_path}\n"
            "Terminal=false\n"
            "Categories=System;Settings;\n"
        )
        desktop_path.write_text(content)
        desktop_path.chmod(0o755)
        print(f"[Desktop] Entry created: {desktop_path}")
    except Exception as e:
        print(f"[Desktop] Could not create .desktop entry: {e}", file=sys.stderr)

def _extract_resources():
    """Extract all resources to temp directory for GUI use."""
    try:
        import tempfile
        import zipfile
        import shutil
        
        temp_dir = tempfile.mkdtemp(prefix="yads_setup_")
        os.environ["YADS_INSTALLER_RESOURCES"] = temp_dir
        
        pyz_path = sys.argv[0]
        resources = ['logo.png', 'docker-compose.customer.yml', 'nginx.conf.template']
        
        if zipfile.is_zipfile(pyz_path):
            with zipfile.ZipFile(pyz_path, 'r') as z:
                for res in resources:
                    if res in z.namelist():
                        dest = os.path.join(temp_dir, res)
                        with z.open(res) as src, open(dest, 'wb') as f:
                            f.write(src.read())
            # Compatibility with previous env var
            os.environ["YADS_INSTALLER_LOGO"] = os.path.join(temp_dir, "logo.png")
            return
        
        # Fallback for direct execution
        src_root = os.path.dirname(__file__)
        for res in resources:
            src = os.path.join(src_root, res)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(temp_dir, res))
        
        os.environ["YADS_INSTALLER_LOGO"] = os.path.join(temp_dir, "logo.png")
    except Exception as e:
        print(f"Resource extraction failed: {e}", file=sys.stderr)

def main():
    _extract_resources()
    
    # Only try to create desktop entry if not already present
    desktop_path = Path.home() / ".local" / "share" / "applications" / "yads-setup.desktop"
    if not desktop_path.exists() and not os.environ.get("YADS_INSTALLER_NO_DESKTOP"):
        threading.Thread(target=_create_desktop_entry, daemon=True).start()

    if not check_dependencies():
        print("Could not satisfy dependencies. Please install PySide6 and qfluentwidgets manually.")
        sys.exit(1)

    from PySide6.QtWidgets import QApplication
    from gui import GlassInstaller

    app = QApplication(sys.argv)
    
    # Check for dark mode to match theme
    from gui import detect_system_dark_mode
    from qfluentwidgets import setTheme, Theme
    if detect_system_dark_mode():
        setTheme(Theme.DARK)
    else:
        setTheme(Theme.LIGHT)

    window = GlassInstaller()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
