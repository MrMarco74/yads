#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import sys
import os
import threading
import queue
import yaml
from pathlib import Path
from typing import Optional

# Add the tools directory to path to import release modules
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

try:
    from release import ReleaseOrchestrator
    from release_lib.config import ReleaseConfig
except ImportError as e:
    print(f"Error importing release modules: {e}")
    sys.exit(1)

class LogRedirector:
    """Redirects stdout/stderr to a queue for the GUI to consume"""
    def __init__(self, queue):
        self.queue = queue

    def write(self, string):
        self.queue.put(string)

    def flush(self):
        pass

class ReleaseGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("YADS Release Automation")
        self.root.geometry("850x850")
        self.root.minsize(800, 700)

        # Set window icon
        icon_path = script_dir / "release_icon.png"
        if icon_path.exists():
            try:
                self.icon = tk.PhotoImage(file=str(icon_path))
                self.root.iconphoto(True, self.icon)
            except Exception as e:
                print(f"Error loading icon: {e}")

        self.project_root = script_dir.parent
        self.config_dir = Path.home() / ".yads"
        self.config_file = self.config_dir / "release_gui.yaml"
        self.log_queue = queue.Queue()
        self.cancel_requested = False
        self.current_uploader = None

        self._setup_styles()
        self._create_widgets()
        self._load_config()

        # Start log consumer
        self.root.after(100, self._process_logs)

    def _setup_styles(self):
        style = ttk.Style()
        style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        style.configure("Status.TLabel", font=("Helvetica", 10, "italic"))
        # Match License Manager feel
        style.configure("TButton", padding=5)

    def _create_widgets(self):
        # Tab Setup (Same as License Manager)
        self.tab_control = ttk.Notebook(self.root)
        self.tab_release = ttk.Frame(self.tab_control)
        self.tab_settings = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab_release, text='Release Automation')
        self.tab_control.add(self.tab_settings, text='Configuration')
        self.tab_control.pack(expand=1, fill="both", padx=10, pady=10)

        self._setup_release_tab()
        self._setup_settings_tab()

    def _setup_release_tab(self):
        frame = ttk.Frame(self.tab_release, padding="10")
        frame.pack(fill="both", expand=True)

        # Header
        ttk.Label(frame, text="Execute Software Release", style="Header.TLabel").pack(anchor="w", pady=(0, 10))

        # Input Controls Row
        input_row = ttk.Frame(frame)
        input_row.pack(fill="x", pady=5)

        ttk.Label(input_row, text="Update Type (Bump):").pack(side=tk.LEFT, padx=5)
        self.bump_type = ttk.Combobox(input_row, values=["patch", "minor", "major"], width=15)
        self.bump_type.set("patch")
        self.bump_type.pack(side=tk.LEFT, padx=5)

        ttk.Label(input_row, text="or Version:").pack(side=tk.LEFT, padx=(15, 5))
        self.manual_version = ttk.Entry(input_row, width=12)
        self.manual_version.pack(side=tk.LEFT, padx=5)
        ttk.Label(input_row, text="(e.g. 1.2.3)", foreground="gray").pack(side=tk.LEFT)

        self.dry_run_var = tk.BooleanVar(value=True)
        self.dry_run_check = ttk.Checkbutton(input_row, text="Dry Run (Preview Only)", variable=self.dry_run_var)
        self.dry_run_check.pack(side=tk.LEFT, padx=15)

        # Buttons Row
        btn_row = ttk.Frame(frame)
        btn_row.pack(fill="x", pady=(10, 5))

        self.start_btn = ttk.Button(btn_row, text="Run Release Process", command=self._run_release_thread)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.retry_btn = ttk.Button(btn_row, text="Retry Upload", command=self._retry_upload_thread)
        self.retry_btn.pack(side=tk.LEFT, padx=5)

        ttk.Label(btn_row, text="Version:").pack(side=tk.LEFT, padx=(10, 5))
        self.upload_version = ttk.Combobox(btn_row, values=[], width=10, state="readonly")
        self.upload_version.pack(side=tk.LEFT, padx=2)
        self.refresh_versions_btn = ttk.Button(btn_row, text="↻", width=2, command=self._refresh_versions)
        self.refresh_versions_btn.pack(side=tk.LEFT, padx=2)
        self._refresh_versions()

        self.upload_dry_run_var = tk.BooleanVar(value=True)
        self.upload_dry_run_check = ttk.Checkbutton(btn_row, text="Dry Run", variable=self.upload_dry_run_var)
        self.upload_dry_run_check.pack(side=tk.LEFT, padx=(10, 5))

        self.download_btn = ttk.Button(btn_row, text="Download Release Files", command=self._download_release_files)
        self.download_btn.pack(side=tk.LEFT, padx=5)

        self.cancel_btn = ttk.Button(btn_row, text="Cancel", command=self._cancel_operation, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.RIGHT, padx=5)

        # Log Section
        log_frame = ttk.LabelFrame(frame, text=" Execution Logs ", padding="5")
        log_frame.pack(fill="both", expand=True, pady=(10, 0))

        self.log_view = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("Courier New", 10), state=tk.DISABLED, bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
        self.log_view.pack(fill="both", expand=True)
        
        # Tags for colored logging
        self.log_view.tag_configure("error", foreground="#ff6b6b")
        self.log_view.tag_configure("success", foreground="#51cf66")
        self.log_view.tag_configure("info", foreground="#339af0")

    def _setup_settings_tab(self):
        frame = ttk.Frame(self.tab_settings, padding="10")
        frame.pack(fill="both", expand=True)

        # SSH Section
        ssh_frame = ttk.LabelFrame(frame, text=" SSH Deployment Settings ", padding="10")
        ssh_frame.pack(fill="x", pady=5)

        ttk.Label(ssh_frame, text="SSH Server:").grid(row=0, column=0, sticky="w", pady=2)
        self.ssh_host = ttk.Entry(ssh_frame, width=30)
        self.ssh_host.grid(row=0, column=1, sticky="w", pady=2, padx=10)

        ttk.Label(ssh_frame, text="Port:").grid(row=0, column=2, sticky="w", pady=2, padx=(10, 0))
        self.ssh_port = ttk.Entry(ssh_frame, width=6)
        self.ssh_port.grid(row=0, column=3, sticky="w", pady=2, padx=5)
        self.ssh_port.insert(0, "22")

        ttk.Label(ssh_frame, text="SSH User:").grid(row=1, column=0, sticky="w", pady=2)
        self.ssh_user = ttk.Entry(ssh_frame, width=40)
        self.ssh_user.grid(row=1, column=1, sticky="w", pady=2, padx=10)

        ttk.Label(ssh_frame, text="SSH Password:").grid(row=2, column=0, sticky="w", pady=2)
        self.ssh_pass = ttk.Entry(ssh_frame, width=40, show="*")
        self.ssh_pass.grid(row=2, column=1, sticky="w", pady=2, padx=10)
        ttk.Label(ssh_frame, text="(or use key file)", foreground="gray").grid(row=2, column=2, sticky="w")

        ttk.Label(ssh_frame, text="SSH Key File:").grid(row=3, column=0, sticky="w", pady=2)
        self.ssh_key = ttk.Entry(ssh_frame, width=40)
        self.ssh_key.grid(row=3, column=1, sticky="w", pady=2, padx=10)
        ttk.Label(ssh_frame, text="(e.g. ~/.ssh/id_rsa)", foreground="gray").grid(row=3, column=2, sticky="w")

        # SSH Paths
        ttk.Label(ssh_frame, text="Releases Path:").grid(row=4, column=0, sticky="w", pady=2)
        self.ssh_path_releases = ttk.Entry(ssh_frame, width=40)
        self.ssh_path_releases.grid(row=4, column=1, sticky="w", pady=2, padx=10)
        ttk.Label(ssh_frame, text="(zip + version.json)", foreground="gray").grid(row=4, column=2, sticky="w")

        ttk.Label(ssh_frame, text="Homepage EN:").grid(row=5, column=0, sticky="w", pady=2)
        self.ssh_path_en = ttk.Entry(ssh_frame, width=40)
        self.ssh_path_en.grid(row=5, column=1, sticky="w", pady=2, padx=10)

        ttk.Label(ssh_frame, text="Homepage DE:").grid(row=6, column=0, sticky="w", pady=2)
        self.ssh_path_de = ttk.Entry(ssh_frame, width=40)
        self.ssh_path_de.grid(row=6, column=1, sticky="w", pady=2, padx=10)

        # FTP Section
        ftp_frame = ttk.LabelFrame(frame, text=" FTP Deployment Settings ", padding="10")
        ftp_frame.pack(fill="x", pady=5)

        ttk.Label(ftp_frame, text="FTP Server:").grid(row=0, column=0, sticky="w", pady=2)
        self.ftp_host = ttk.Entry(ftp_frame, width=40)
        self.ftp_host.grid(row=0, column=1, sticky="w", pady=2, padx=10)
        ttk.Label(ftp_frame, text="(e.g. ftp.example.com)", foreground="gray").grid(row=0, column=2, sticky="w")

        ttk.Label(ftp_frame, text="FTP User:").grid(row=1, column=0, sticky="w", pady=2)
        self.ftp_user = ttk.Entry(ftp_frame, width=40)
        self.ftp_user.grid(row=1, column=1, sticky="w", pady=2, padx=10)

        ttk.Label(ftp_frame, text="FTP Password:").grid(row=2, column=0, sticky="w", pady=2)
        self.ftp_pass = ttk.Entry(ftp_frame, width=40, show="*")
        self.ftp_pass.grid(row=2, column=1, sticky="w", pady=2, padx=10)

        # FTP Paths
        ttk.Label(ftp_frame, text="Releases Path:").grid(row=3, column=0, sticky="w", pady=2)
        self.ftp_path_releases = ttk.Entry(ftp_frame, width=40)
        self.ftp_path_releases.grid(row=3, column=1, sticky="w", pady=2, padx=10)
        ttk.Label(ftp_frame, text="(zip + version.json)", foreground="gray").grid(row=3, column=2, sticky="w")

        ttk.Label(ftp_frame, text="Homepage EN:").grid(row=4, column=0, sticky="w", pady=2)
        self.ftp_path_en = ttk.Entry(ftp_frame, width=40)
        self.ftp_path_en.grid(row=4, column=1, sticky="w", pady=2, padx=10)

        ttk.Label(ftp_frame, text="Homepage DE:").grid(row=5, column=0, sticky="w", pady=2)
        self.ftp_path_de = ttk.Entry(ftp_frame, width=40)
        self.ftp_path_de.grid(row=5, column=1, sticky="w", pady=2, padx=10)

        # AI/Translation Section
        gcp_frame = ttk.LabelFrame(frame, text=" Translation Settings (Google Cloud / AI Studio) ", padding="10")
        gcp_frame.pack(fill="x", pady=10)

        ttk.Label(gcp_frame, text="Service:").grid(row=0, column=0, sticky="w", pady=2)
        self.ai_service = ttk.Combobox(gcp_frame, values=["gemini", "vertexai", "manual"], width=15)
        self.ai_service.set("gemini")
        self.ai_service.grid(row=0, column=1, sticky="w", pady=2, padx=10)

        ttk.Label(gcp_frame, text="Gemini API Key:").grid(row=1, column=0, sticky="w", pady=2)
        self.gemini_key = ttk.Entry(gcp_frame, width=40, show="*")
        self.gemini_key.grid(row=1, column=1, sticky="w", pady=2, padx=10)

        ttk.Label(gcp_frame, text="GCP Project ID:").grid(row=2, column=0, sticky="w", pady=2)
        self.gcp_project = ttk.Entry(gcp_frame, width=40)
        self.gcp_project.grid(row=2, column=1, sticky="w", pady=2, padx=10)
        ttk.Label(gcp_frame, text="(For Vertex AI only)", foreground="gray").grid(row=2, column=2, sticky="w")

        ttk.Label(gcp_frame, text="GCP Location:").grid(row=3, column=0, sticky="w", pady=2)
        self.gcp_location = ttk.Entry(gcp_frame, width=40)
        self.gcp_location.grid(row=3, column=1, sticky="w", pady=2, padx=10)
        self.gcp_location.insert(0, "us-central1")

        ttk.Label(gcp_frame, text="AI Model:").grid(row=4, column=0, sticky="w", pady=2)
        self.ai_model = ttk.Combobox(gcp_frame, values=[
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
            "gemini-1.5-flash",
            "gemini-1.5-flash-latest",
            "gemini-1.5-pro",
            "gemini-1.5-pro-latest"
        ], width=30)
        self.ai_model.set("gemini-2.0-flash")
        self.ai_model.grid(row=4, column=1, sticky="w", pady=2, padx=10)
        ttk.Label(gcp_frame, text="(Used for changelog & translation)", foreground="gray").grid(row=4, column=2, sticky="w")

        save_btn = ttk.Button(frame, text="💾 Save Configuration", command=self._save_config)
        save_btn.pack(pady=20)

    def _load_config(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = yaml.safe_load(f) or {}
                    self.ssh_host.insert(0, data.get('ssh_host', ''))
                    self.ssh_port.delete(0, tk.END)
                    self.ssh_port.insert(0, data.get('ssh_port', '22'))
                    self.ssh_user.insert(0, data.get('ssh_user', ''))
                    self.ssh_pass.insert(0, data.get('ssh_pass', ''))
                    self.ssh_key.insert(0, data.get('ssh_key', ''))
                    self.ssh_path_releases.insert(0, data.get('ssh_path_releases', '/en/releases/'))
                    self.ssh_path_en.insert(0, data.get('ssh_path_en', '/en/'))
                    self.ssh_path_de.insert(0, data.get('ssh_path_de', '/de/'))
                    self.ftp_host.insert(0, data.get('ftp_host', ''))
                    self.ftp_user.insert(0, data.get('ftp_user', ''))
                    self.ftp_pass.insert(0, data.get('ftp_pass', ''))
                    self.ftp_path_releases.insert(0, data.get('ftp_path_releases', '/en/releases/'))
                    self.ftp_path_en.insert(0, data.get('ftp_path_en', '/en/'))
                    self.ftp_path_de.insert(0, data.get('ftp_path_de', '/de/'))
                    self.ai_service.set(data.get('ai_service', 'gemini'))
                    self.gemini_key.insert(0, data.get('gemini_key', ''))
                    self.gcp_location.delete(0, tk.END)
                    self.gcp_location.insert(0, data.get('gcp_location', 'us-central1'))
                    self.ai_model.set(data.get('ai_model', 'gemini-2.0-flash'))
            except Exception as e:
                self._log(f"Error loading config: {e}\n", "error")

    def _save_config(self):
        self.config_dir.mkdir(parents=True, exist_ok=True)
        data = {
            'ssh_host': self.ssh_host.get(),
            'ssh_port': self.ssh_port.get(),
            'ssh_user': self.ssh_user.get(),
            'ssh_pass': self.ssh_pass.get(),
            'ssh_key': self.ssh_key.get(),
            'ssh_path_releases': self.ssh_path_releases.get(),
            'ssh_path_en': self.ssh_path_en.get(),
            'ssh_path_de': self.ssh_path_de.get(),
            'ftp_host': self.ftp_host.get(),
            'ftp_user': self.ftp_user.get(),
            'ftp_pass': self.ftp_pass.get(),
            'ftp_path_releases': self.ftp_path_releases.get(),
            'ftp_path_en': self.ftp_path_en.get(),
            'ftp_path_de': self.ftp_path_de.get(),
            'ai_service': self.ai_service.get(),
            'gemini_key': self.gemini_key.get(),
            'gcp_project': self.gcp_project.get(),
            'gcp_location': self.gcp_location.get(),
            'ai_model': self.ai_model.get()
        }
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(data, f)
            messagebox.showinfo("Success", "Settings saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save settings: {e}")

    def _log(self, message, tag=None):
        self.log_view.config(state=tk.NORMAL)
        if tag:
            self.log_view.insert(tk.END, message, tag)
        else:
            self.log_view.insert(tk.END, message)
        self.log_view.see(tk.END)
        self.log_view.config(state=tk.DISABLED)

    def _process_logs(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self._log(msg)
        except queue.Empty:
            pass
        self.root.after(100, self._process_logs)

    def _download_release_files(self):
        """Download/save release files locally before uploading"""
        import shutil

        # Ask user for destination folder
        dest_dir = filedialog.askdirectory(
            title="Select folder to save release files",
            initialdir=str(Path.home() / "Downloads")
        )

        if not dest_dir:
            return  # User cancelled

        dest_path = Path(dest_dir)

        # Get current version from config.py
        try:
            from yads.config import settings
            version = settings.VERSION
        except:
            # Fallback: read from version.json
            version_file = self.project_root / "releases" / "version.json"
            if version_file.exists():
                import json
                with open(version_file) as f:
                    version = json.load(f).get("version", "unknown")
            else:
                version = "unknown"

        # List of files to download
        files_to_copy = [
            f"releases/yads_v{version}_customer_pkg.zip",
            "releases/version.json",
            "releases/version_de.json",
            "yads-homepage/en/support.html",
            "yads-homepage/en/changes.html",
            "yads-homepage/en/docs.html",
            "yads-homepage/de/support.html",
            "yads-homepage/de/changes.html",
            "yads-homepage/de/docs.html",
        ]

        copied = []
        missing = []

        for file_path in files_to_copy:
            src = self.project_root / file_path
            if src.exists():
                # Preserve directory structure or flatten?
                # Let's create subdirs to keep it organized
                rel_dest = dest_path / file_path
                rel_dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, rel_dest)
                copied.append(file_path)
            else:
                missing.append(file_path)

        # Show result
        msg = f"Downloaded {len(copied)} files to:\n{dest_dir}\n"
        if missing:
            msg += f"\nMissing files ({len(missing)}):\n" + "\n".join(f"  - {f}" for f in missing)

        if copied:
            messagebox.showinfo("Download Complete", msg)
            self._log(f"\n📥 Downloaded {len(copied)} release files to {dest_dir}\n", "success")
        else:
            messagebox.showwarning("No Files", "No release files found to download.\nRun the release process first.")

    def _refresh_versions(self):
        """Scan releases folder for available versions"""
        import re
        releases_dir = self.project_root / "releases"
        versions = []

        if releases_dir.exists():
            for f in releases_dir.iterdir():
                if f.is_file() and f.name.endswith("_customer_pkg.zip"):
                    # Extract version from filename like yads_v1.13.5_customer_pkg.zip
                    match = re.search(r'_v(\d+\.\d+\.\d+)_customer_pkg\.zip$', f.name)
                    if match:
                        versions.append(match.group(1))

        # Sort versions descending (newest first)
        versions.sort(key=lambda v: [int(x) for x in v.split('.')], reverse=True)

        self.upload_version['values'] = versions
        if versions:
            self.upload_version.set(versions[0])

    def _cancel_operation(self):
        """Cancel the current operation"""
        self.cancel_requested = True
        self._log("\n⚠️  Cancel requested... terminating upload process.\n", "error")

        # Try to terminate uploader's current process
        if hasattr(self, 'current_uploader') and self.current_uploader:
            if self.current_uploader.current_process:
                try:
                    self.current_uploader.current_process.terminate()
                    self._log("   Upload process terminated.\n", "error")
                except:
                    pass

    def _retry_upload_thread(self):
        """Start retry upload in a separate thread"""
        self.cancel_requested = False
        self.log_view.config(state=tk.NORMAL)
        self.log_view.delete(1.0, tk.END)
        self.log_view.config(state=tk.DISABLED)

        self.start_btn.config(state=tk.DISABLED)
        self.retry_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        thread = threading.Thread(target=self._retry_upload, daemon=True)
        thread.start()

    def _retry_upload(self):
        """Retry uploading release files"""
        # Redirect stdout
        old_stdout = sys.stdout
        sys.stdout = LogRedirector(self.log_queue)

        dry_run = self.upload_dry_run_var.get()

        try:
            # Get selected version from dropdown
            version = self.upload_version.get()
            if not version:
                print("❌ No version selected. Please select a version from the dropdown.")
                return

            if dry_run:
                print(f"--- DRY RUN: Upload Preview for v{version} ---\n")
            else:
                print(f"--- Retrying Upload for v{version} ---\n")

            # Set environment variables
            os.environ['YADS_FTP_PASSWORD'] = self.ftp_pass.get()

            # Create orchestrator and load config
            orchestrator = ReleaseOrchestrator(str(self.project_root))

            try:
                orchestrator.load_config()
            except Exception as e:
                print(f"ℹ️  Note: {e}")
                if not hasattr(orchestrator, 'config') or orchestrator.config is None:
                    from release_lib.config import ReleaseConfig
                    orchestrator.config = ReleaseConfig("/dev/nonexistent")
                    orchestrator.config.config = {}

            # Apply GUI settings (same as in _execute_release)
            config = orchestrator.config.config

            if 'upload' not in config: config['upload'] = {}
            if 'ssh' not in config['upload']: config['upload']['ssh'] = {}
            if 'ftp' not in config['upload']: config['upload']['ftp'] = {}
            if 'paths' not in config['upload']: config['upload']['paths'] = {}

            # SSH settings
            ssh_host = self.ssh_host.get()
            ssh_user = self.ssh_user.get()
            if ssh_host and ssh_user:
                config['upload']['method'] = 'ssh'
                config['upload']['ssh']['host'] = ssh_host
                config['upload']['ssh']['user'] = ssh_user
                config['upload']['ssh']['password'] = self.ssh_pass.get()
                # Only set key_file if specified; empty means use password auth
                ssh_key = self.ssh_key.get().strip()
                config['upload']['ssh']['key_file'] = ssh_key if ssh_key else ''
                try:
                    config['upload']['ssh']['port'] = int(self.ssh_port.get())
                except ValueError:
                    config['upload']['ssh']['port'] = 22
            else:
                config['upload']['method'] = 'ftp'

            # FTP settings
            ftp_host = self.ftp_host.get()
            if ftp_host:
                config['upload']['ftp']['host'] = ftp_host
            config['upload']['ftp']['user'] = self.ftp_user.get()
            config['upload']['ftp']['password'] = self.ftp_pass.get()
            if 'port' not in config['upload']['ftp']:
                config['upload']['ftp']['port'] = 21

            # Upload paths - use SSH or FTP paths based on method
            if config['upload']['method'] == 'ssh':
                path_releases = self.ssh_path_releases.get().strip()
                path_homepage_en = self.ssh_path_en.get().strip()
                path_homepage_de = self.ssh_path_de.get().strip()
            else:
                path_releases = self.ftp_path_releases.get().strip()
                path_homepage_en = self.ftp_path_en.get().strip()
                path_homepage_de = self.ftp_path_de.get().strip()

            if path_releases:
                if not path_releases.endswith('/'): path_releases += '/'
                config['upload']['paths']['releases'] = path_releases
            if path_homepage_en:
                if not path_homepage_en.endswith('/'): path_homepage_en += '/'
                config['upload']['paths']['homepage_en'] = path_homepage_en
            if path_homepage_de:
                if not path_homepage_de.endswith('/'): path_homepage_de += '/'
                config['upload']['paths']['homepage_de'] = path_homepage_de

            # Re-initialize uploader
            from release_lib.uploader import ReleaseUploader
            orchestrator.uploader = ReleaseUploader(config, str(self.project_root))
            self.current_uploader = orchestrator.uploader  # For cancellation

            # Retry upload
            success = orchestrator.retry_upload(version, dry_run=dry_run)

            if dry_run:
                print("\n✅ Dry run complete - no files were uploaded")
            elif success:
                print("\n✅ Upload completed successfully")
            else:
                print("\n❌ Upload failed")

        except Exception as e:
            print(f"\nCRITICAL ERROR: {e}")
        finally:
            sys.stdout = old_stdout
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.retry_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.cancel_btn.config(state=tk.DISABLED))

    def _run_release_thread(self):
        # Safety prompt when not in dry-run mode
        if not self.dry_run_var.get():
            result = messagebox.askyesnocancel(
                "Upload Confirmation",
                "You are about to upload files to the server.\n\n"
                "Have you downloaded a local backup first?\n\n"
                "Yes = Continue with upload\n"
                "No = Download files first\n"
                "Cancel = Abort"
            )
            if result is None:  # Cancel
                return
            elif result is False:  # No - download first
                self._download_release_files()
                return

        self.cancel_requested = False
        self.log_view.config(state=tk.NORMAL)
        self.log_view.delete(1.0, tk.END)
        self.log_view.config(state=tk.DISABLED)

        self.start_btn.config(state=tk.DISABLED)
        self.retry_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        thread = threading.Thread(target=self._execute_release, daemon=True)
        thread.start()

    def _execute_release(self):
        bump = self.bump_type.get()
        dry_run = self.dry_run_var.get()
        manual_version = self.manual_version.get().strip()

        # Redirect stdout
        old_stdout = sys.stdout
        sys.stdout = LogRedirector(self.log_queue)

        try:
            if manual_version:
                print(f"--- Starting Release (Version: {manual_version}, Dry Run: {dry_run}) ---\n")
            else:
                print(f"--- Starting Release (Bump: {bump}, Dry Run: {dry_run}) ---\n")
            
            # Patch environment EARLY so that expansion in load_config can pick it up
            # if the variables are defined in the YAML file.
            os.environ['YADS_FTP_PASSWORD'] = self.ftp_pass.get()
            os.environ['GEMINI_API_KEY'] = os.getenv('GEMINI_API_KEY', '') # Preserve if set
            
            # Note: Orchestrator requires a project root string
            orchestrator = ReleaseOrchestrator(str(self.project_root))
            
            try:
                orchestrator.load_config()
            except Exception as e:
                print(f"ℹ️  Note: Configuration file loading/validation message: {e}")
                print("   Continuing with GUI-only settings...")
                # Ensure we have a config object even if loading failed
                if not hasattr(orchestrator, 'config') or orchestrator.config is None:
                    from release_lib.config import ReleaseConfig
                    # Create empty config
                    orchestrator.config = ReleaseConfig("/dev/nonexistent") 
                    orchestrator.config.config = {}

            # --- Apply GUI Overrides ---
            config = orchestrator.config.config

            # Ensure required structures exist
            if 'upload' not in config: config['upload'] = {}
            if 'ssh' not in config['upload']: config['upload']['ssh'] = {}
            if 'ftp' not in config['upload']: config['upload']['ftp'] = {}
            if 'paths' not in config['upload']: config['upload']['paths'] = {}

            # Apply SSH GUI settings
            ssh_host = self.ssh_host.get()
            ssh_user = self.ssh_user.get()
            if ssh_host and ssh_user:
                config['upload']['method'] = 'ssh'
                config['upload']['ssh']['host'] = ssh_host
                config['upload']['ssh']['user'] = ssh_user
                config['upload']['ssh']['password'] = self.ssh_pass.get()
                # Only set key_file if specified; empty means use password auth
                ssh_key = self.ssh_key.get().strip()
                config['upload']['ssh']['key_file'] = ssh_key if ssh_key else ''
                try:
                    config['upload']['ssh']['port'] = int(self.ssh_port.get())
                except ValueError:
                    config['upload']['ssh']['port'] = 22
            else:
                config['upload']['method'] = 'ftp'

            # Apply FTP GUI settings
            ftp_host = self.ftp_host.get()
            if ftp_host:
                config['upload']['ftp']['host'] = ftp_host
            elif 'host' not in config['upload']['ftp']:
                config['upload']['ftp']['host'] = 'yads-security.com'
            config['upload']['ftp']['user'] = self.ftp_user.get()
            config['upload']['ftp']['password'] = self.ftp_pass.get()
            if 'port' not in config['upload']['ftp']:
                config['upload']['ftp']['port'] = 21

            # Upload paths - use SSH or FTP paths based on method
            if config['upload']['method'] == 'ssh':
                path_releases = self.ssh_path_releases.get().strip()
                path_homepage_en = self.ssh_path_en.get().strip()
                path_homepage_de = self.ssh_path_de.get().strip()
            else:
                path_releases = self.ftp_path_releases.get().strip()
                path_homepage_en = self.ftp_path_en.get().strip()
                path_homepage_de = self.ftp_path_de.get().strip()

            if path_releases:
                if not path_releases.endswith('/'): path_releases += '/'
                config['upload']['paths']['releases'] = path_releases
            if path_homepage_en:
                if not path_homepage_en.endswith('/'): path_homepage_en += '/'
                config['upload']['paths']['homepage_en'] = path_homepage_en
            if path_homepage_de:
                if not path_homepage_de.endswith('/'): path_homepage_de += '/'
                config['upload']['paths']['homepage_de'] = path_homepage_de
            
            # Translation Overrides
            service = self.ai_service.get()
            if 'translation' not in config: config['translation'] = {}
            config['translation']['service'] = service
            
            if service == 'gemini':
                config['translation']['api_key'] = self.gemini_key.get()
            elif service == 'vertexai':
                config['translation']['project_id'] = self.gcp_project.get()
                config['translation']['location'] = self.gcp_location.get()

            # Re-initialize translator with GUI settings
            from release_lib.translator import ChangelogTranslator
            orchestrator.translator = ChangelogTranslator(
                api_key=self.gemini_key.get() if service == 'gemini' else None,
                service=service,
                project_id=self.gcp_project.get() if service == 'vertexai' else None,
                location=self.gcp_location.get() if service == 'vertexai' else 'us-central1',
                model_name=self.ai_model.get()
            )

            # Share AI model with changelog manager for AI-powered changelog generation
            if orchestrator.translator.model:
                orchestrator.changelog_manager.set_ai_model(
                    orchestrator.translator.model,
                    orchestrator.translator.service
                )
                print(f"  ✅ AI changelog generation enabled ({orchestrator.translator.service})")

            # Re-initialize uploader with the final overridden configuration
            from release_lib.uploader import ReleaseUploader
            orchestrator.uploader = ReleaseUploader(config, str(self.project_root))
            self.current_uploader = orchestrator.uploader  # For cancellation

            # Run release
            success = orchestrator.execute_release(
                bump_type=bump,
                dry_run=dry_run,
                use_editor=False,
                interactive=False,
                target_version=manual_version if manual_version else None
            )
            
            if success:
                print("\n✅ Release Process Finished")
            else:
                print("\n❌ Release Process Failed")
                
        except Exception as e:
            print(f"\nCRITICAL ERROR: {e}")
        finally:
            sys.stdout = old_stdout
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.retry_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.cancel_btn.config(state=tk.DISABLED))

if __name__ == "__main__":
    root = tk.Tk(className="yads-release-manager")
    app = ReleaseGUI(root)
    root.mainloop()
