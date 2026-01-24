#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
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

        self.project_root = script_dir.parent
        self.config_dir = Path.home() / ".yads"
        self.config_file = self.config_dir / "release_gui.yaml"
        self.log_queue = queue.Queue()
        
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

        # Controls Row
        ctrl_row = ttk.Frame(frame)
        ctrl_row.pack(fill="x", pady=5)

        ttk.Label(ctrl_row, text="Update Type (Bump):").pack(side=tk.LEFT, padx=5)
        self.bump_type = ttk.Combobox(ctrl_row, values=["patch", "minor", "major"], width=15)
        self.bump_type.set("patch")
        self.bump_type.pack(side=tk.LEFT, padx=5)

        self.dry_run_var = tk.BooleanVar(value=True)
        self.dry_run_check = ttk.Checkbutton(ctrl_row, text="Dry Run (Preview Only)", variable=self.dry_run_var)
        self.dry_run_check.pack(side=tk.LEFT, padx=15)

        self.start_btn = ttk.Button(ctrl_row, text="🚀 Run Release Process", command=self._run_release_thread)
        self.start_btn.pack(side=tk.RIGHT, padx=5)

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

        # FTP Section
        ftp_frame = ttk.LabelFrame(frame, text=" FTP Deployment Settings ", padding="10")
        ftp_frame.pack(fill="x", pady=5)

        ttk.Label(ftp_frame, text="FTP User:").grid(row=0, column=0, sticky="w", pady=2)
        self.ftp_user = ttk.Entry(ftp_frame, width=40)
        self.ftp_user.grid(row=0, column=1, sticky="w", pady=2, padx=10)

        ttk.Label(ftp_frame, text="FTP Password:").grid(row=1, column=0, sticky="w", pady=2)
        self.ftp_pass = ttk.Entry(ftp_frame, width=40, show="*")
        self.ftp_pass.grid(row=1, column=1, sticky="w", pady=2, padx=10)

        ttk.Label(ftp_frame, text="Target Folder:").grid(row=2, column=0, sticky="w", pady=2)
        self.ftp_path = ttk.Entry(ftp_frame, width=60)
        self.ftp_path.grid(row=2, column=1, sticky="w", pady=2, padx=10)
        ttk.Label(ftp_frame, text="(e.g. /var/www/html/)", foreground="gray").grid(row=2, column=2, sticky="w")

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

        save_btn = ttk.Button(frame, text="💾 Save Configuration", command=self._save_config)
        save_btn.pack(pady=20)

    def _load_config(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = yaml.safe_load(f) or {}
                    self.ftp_user.insert(0, data.get('ftp_user', ''))
                    self.ftp_pass.insert(0, data.get('ftp_pass', ''))
                    self.ftp_path.insert(0, data.get('ftp_path', '/var/www/'))
                    self.ai_service.set(data.get('ai_service', 'gemini'))
                    self.gemini_key.insert(0, data.get('gemini_key', ''))
                    self.gcp_project.insert(0, data.get('gcp_project', ''))
                    self.gcp_location.delete(0, tk.END)
                    self.gcp_location.insert(0, data.get('gcp_location', 'us-central1'))
            except Exception as e:
                self._log(f"Error loading config: {e}\n", "error")

    def _save_config(self):
        self.config_dir.mkdir(parents=True, exist_ok=True)
        data = {
            'ftp_user': self.ftp_user.get(),
            'ftp_pass': self.ftp_pass.get(),
            'ftp_path': self.ftp_path.get(),
            'ai_service': self.ai_service.get(),
            'gemini_key': self.gemini_key.get(),
            'gcp_project': self.gcp_project.get(),
            'gcp_location': self.gcp_location.get()
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

    def _run_release_thread(self):
        self.log_view.config(state=tk.NORMAL)
        self.log_view.delete(1.0, tk.END)
        self.log_view.config(state=tk.DISABLED)
        
        self.start_btn.config(state=tk.DISABLED)
        thread = threading.Thread(target=self._execute_release, daemon=True)
        thread.start()

    def _execute_release(self):
        bump = self.bump_type.get()
        dry_run = self.dry_run_var.get()
        
        # Redirect stdout
        old_stdout = sys.stdout
        sys.stdout = LogRedirector(self.log_queue)
        
        try:
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
            if 'method' not in config['upload']: config['upload']['method'] = 'ftp'
            if 'ftp' not in config['upload']: config['upload']['ftp'] = {}
            if 'paths' not in config['upload']: config['upload']['paths'] = {}
            
            # Apply FTP GUI settings
            config['upload']['ftp']['user'] = self.ftp_user.get()
            config['upload']['ftp']['password'] = self.ftp_pass.get()
            
            # Default FTP host/port if not present in YAML
            if 'host' not in config['upload']['ftp']:
                config['upload']['ftp']['host'] = 'yads-security.com'
            if 'port' not in config['upload']['ftp']:
                config['upload']['ftp']['port'] = 21

            # Target folder override
            target_path = self.ftp_path.get()
            if target_path:
                if not target_path.endswith('/'): target_path += '/'
                config['upload']['paths']['releases'] = target_path
            
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
                location=self.gcp_location.get() if service == 'vertexai' else 'us-central1'
            )

            # Re-initialize uploader with the final overridden configuration
            from release_lib.uploader import ReleaseUploader
            orchestrator.uploader = ReleaseUploader(config, str(self.project_root))
            
            # Run release
            success = orchestrator.execute_release(
                bump_type=bump,
                dry_run=dry_run,
                use_editor=False,
                interactive=False
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

if __name__ == "__main__":
    root = tk.Tk()
    app = ReleaseGUI(root)
    root.mainloop()
