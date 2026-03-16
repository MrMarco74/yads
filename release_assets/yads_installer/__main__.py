import sys
import os
import pkgutil
from gui import YADSInstallerGUI
import tkinter as tk


def _create_desktop_entry():
    """Create a .desktop file so the installer appears in the app menu / taskbar."""
    desktop_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "applications")
    icon_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "icons")
    pyz_path = os.path.abspath(sys.argv[0])

    # Write icon PNG from bundled data
    try:
        os.makedirs(icon_dir, exist_ok=True)
        icon_path = os.path.join(icon_dir, "yads-setup.png")
        logo_data = pkgutil.get_data("yads_installer", "logo.png")
        if logo_data:
            with open(icon_path, "wb") as f:
                f.write(logo_data)
    except Exception as e:
        print(f"[Desktop] Could not write icon: {e}")
        icon_path = "yads-setup"

    # Write .desktop file
    try:
        os.makedirs(desktop_dir, exist_ok=True)
        desktop_path = os.path.join(desktop_dir, "yads-setup.desktop")
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
        with open(desktop_path, "w") as f:
            f.write(content)
        os.chmod(desktop_path, 0o755)
        print(f"[Desktop] Entry created: {desktop_path}")
    except Exception as e:
        print(f"[Desktop] Could not create .desktop entry: {e}")


def main():
    _create_desktop_entry()
    root = tk.Tk()
    app = YADSInstallerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
