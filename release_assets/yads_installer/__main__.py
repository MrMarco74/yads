import sys
import os
import pkgutil
import threading
import tkinter as tk


def _create_desktop_entry(logo_data: bytes):
    """Create .desktop file and icon — called once in a background thread."""
    desktop_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "applications")
    icon_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "icons")
    pyz_path = os.path.abspath(sys.argv[0])

    icon_path = "yads-setup"
    try:
        os.makedirs(icon_dir, exist_ok=True)
        icon_path = os.path.join(icon_dir, "yads-setup.png")
        if logo_data:
            with open(icon_path, "wb") as f:
                f.write(logo_data)
    except Exception as e:
        print(f"[Desktop] Could not write icon: {e}", file=sys.stderr)

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
        print(f"[Desktop] Could not create .desktop entry: {e}", file=sys.stderr)


def main():
    # Skip desktop-entry creation if the .desktop file already exists —
    # no need to rewrite it on every launch.
    # When it does need creating: read logo bytes here in the main thread
    # (avoids Python import-lock contention with the background thread that
    # would otherwise call pkgutil.get_data while gui.py is being imported).
    desktop_path = os.path.join(
        os.path.expanduser("~"), ".local", "share", "applications", "yads-setup.desktop"
    )
    if not os.path.exists(desktop_path):
        try:
            logo_data = pkgutil.get_data("yads_installer", "logo.png") or b""
        except Exception:
            logo_data = b""
        threading.Thread(target=_create_desktop_entry, args=(logo_data,), daemon=True).start()

    try:
        root = tk.Tk()
    except Exception as e:
        print(f"[Fatal] Cannot open display: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        from gui import YADSInstallerGUI
        app = YADSInstallerGUI(root)
    except Exception as e:
        import traceback
        traceback.print_exc()
        tk.messagebox.showerror("Startup Error", str(e))
        sys.exit(1)

    # Bring window to front
    root.lift()
    root.attributes("-topmost", True)
    root.after(200, lambda: root.attributes("-topmost", False))
    root.mainloop()


if __name__ == "__main__":
    main()
