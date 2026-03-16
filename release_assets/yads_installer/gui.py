import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import os
import pkgutil
import socket
import threading
import time
import webbrowser
from installer import DependencyChecker, NetworkTools

# Constants
STYLE_HEADER = "Header.TLabel"
STYLE_ACTION_BTN = "Action.TButton"

class YADSInstallerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("YADS — Setup Wizard")
        self.root.geometry("600x500")
        
        self.current_step = 0
        _real_ip = NetworkTools._real_ip() or ""
        try:
            _real_hostname = socket.gethostname()
        except Exception:
            _real_hostname = _real_ip or "localhost"
        _default_host = _real_hostname or _real_ip or "localhost"
        self.data = {
            "api_port": "80",
            "host": _default_host,
            "use_nginx": True,
            "use_ssl": False,
            "ssl_choice": "1", # 1: self-signed, 2: custom
            "ssl_cn": _default_host,
            "auth_mode": "local", # local, oidc
            "kc_choice": "1",    # 1: Local, 2: Bundled, 3: External
            "kc_port": "8080",
            "yads_host": _default_host,
            "license_key": "",
            "admin_user": "admin",
            "admin_pass": "",
            "admin_pass2": "",
            "db_init_action": "upgrade",
            "mon_choice": "1",   # 1: None, 2: Bundled, 3: External
            "grafana_port": "3000",
            "admin_email": "admin@example.com",
            # Secrets will be generated at the end
        }
        
        # Detect Theme
        self.dark_mode = self.detect_dark_mode()
        self.setup_styles()
        self.load_logo()
        # Set window icon (taskbar + title bar)
        if self.logo_img:
            try:
                root.iconphoto(True, self.logo_img)
            except Exception:
                pass
        
        self.main_container = tk.Frame(root, bg=self.colors['bg'])
        self.main_container.pack(fill="both", expand=True)
        
        # Pack footer FIRST to ensure it stays at the bottom and isn't clipped
        self.nav_frame = tk.Frame(self.main_container, bg=self.colors['bg_alt'])
        self.nav_frame.pack(fill="x", side="bottom", ipady=10)
        
        self.content_frame = tk.Frame(self.main_container, bg=self.colors['bg'], padx=20, pady=20)
        self.content_frame.pack(fill="both", expand=True)
        
        self.btn_prev = ttk.Button(self.nav_frame, text="Back", command=self.prev_step)
        self.btn_prev.pack(side="left", padx=40, pady=10)
        
        self.btn_next = ttk.Button(self.nav_frame, text="Next", command=self.next_step, style=STYLE_ACTION_BTN)
        self.btn_next.pack(side="right", padx=40, pady=10)
        
        # Detection of existing installation
        self.is_upgrade = os.path.exists(".env")
        self.install_mode_var = tk.StringVar(value="update")  # "update" or "reinstall"
        
        self.steps = [
            self.step_welcome,
            self.step_dependencies,
        ]

        if self.is_upgrade:
            self.steps.append(self.step_upgrade_backup)

        self.steps.extend([
            self.step_license,
            self.step_network_ssl,
            self.step_idp,
            self.step_monitoring,
            self.step_remote_workers,
            self.step_admin,
            self.step_telemetry,
            self.step_summary
        ])
        
        # Performance/Secret data
        self.secrets = {}
        self.backup_var = tk.StringVar(value="sql")  # Backup always enforced
        self.backup_password = tk.StringVar()
        self.data['remote_workers'] = []
        
        self.show_step()

    def detect_dark_mode(self):
        # 1. Check for GTK_THEME environment variable
        env_theme = os.environ.get("GTK_THEME", "").lower()
        if "dark" in env_theme:
            return True

        # 2. Check gsettings (GNOME, Cinnamon, etc.)
        try:
            # Try newer color-scheme preference
            out = subprocess.check_output(
                ["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"],
                stderr=subprocess.DEVNULL, text=True, timeout=2
            ).strip().lower()
            if "dark" in out:
                return True

            # Fallback to checking the actual theme name (Common on Mint/Cinnamon)
            out = subprocess.check_output(
                ["gsettings", "get", "org.gnome.desktop.interface", "gtk-theme"],
                stderr=subprocess.DEVNULL, text=True, timeout=2
            ).strip().lower()
            if "dark" in out:
                return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 3. Check for specific Mint 'Mint-Y-Dark' or similar
        try:
            out = subprocess.check_output(
                ["xfconf-query", "-c", "xsettings", "-p", "/Net/ThemeName"],
                stderr=subprocess.DEVNULL, text=True, timeout=2
            ).strip().lower()
            if "dark" in out:
                return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return False

    def setup_styles(self):
        self.colors = {
            'bg': "#1e1e1e" if self.dark_mode else "#ffffff",
            'fg': "#e0e0e0" if self.dark_mode else "#212121",
            'fg_sub': "#a0a0a0" if self.dark_mode else "#666666",
            'bg_alt': "#2d2d2d" if self.dark_mode else "#f5f5f5",
            'accent': "#007acc" if self.dark_mode else "#005a9e",
            'success': "#4caf50",
            'error': "#f44336"
        }
        
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure("TFrame", background=self.colors['bg'])
        style.configure("TLabel", background=self.colors['bg'], foreground=self.colors['fg'], font=("sans-serif", 10))
        style.configure(STYLE_HEADER, font=("sans-serif", 16, "bold"))
        
        # Selection Elements - Fix white boxes in Dark Mode
        style.configure("TRadiobutton", background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure("TCheckbutton", background=self.colors['bg'], foreground=self.colors['fg'])
        
        # Modern & Large Button Styling - Balanced padding and explicit centering
        style.configure("TButton", padding=(25, 12), font=("TkDefaultFont", 11, "bold"), 
                        background=self.colors['bg_alt'], anchor="center")
        style.configure(STYLE_ACTION_BTN, background=self.colors['accent'], foreground="white")
        
        # Explicit foregrounds for all states to ensure visibility
        style.map("TButton",
            foreground=[('active', self.colors['fg']), ('!active', self.colors['fg'])],
            background=[('active', self.colors['bg_alt'])]
        )
        style.map(STYLE_ACTION_BTN,
            background=[('active', self.colors['accent']), ('pressed', self.colors['accent'])],
            foreground=[('active', 'white'), ('!active', 'white')]
        )
        # Fix selection colors too
        style.map("TRadiobutton", background=[('active', self.colors['bg'])])
        style.map("TCheckbutton", background=[('active', self.colors['bg'])])
        
        self.root.configure(bg=self.colors['bg'])

    def load_logo(self):
        try:
            import base64, io
            logo_data = pkgutil.get_data(__name__, "logo.png")
            if not logo_data:
                self.logo_img = None
                return
            # Use Pillow to resize before handing to Tk — avoids hanging on large PNGs
            try:
                from PIL import Image, ImageTk
                img = Image.open(io.BytesIO(logo_data))
                img.thumbnail((128, 128), Image.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(img)
            except ImportError:
                # Pillow not available — fall back to tk.PhotoImage with base64
                b64 = base64.b64encode(logo_data).decode("ascii")
                full_img = tk.PhotoImage(data=b64)
                w = full_img.width()
                factor = max(1, w // 128)
                self.logo_img = full_img.subsample(factor, factor)
        except Exception as e:
            print(f"Logo could not be loaded: {e}")
            self.logo_img = None

    def show_step(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        self.steps[self.current_step]()
        
        if self.current_step > 0:
            self.btn_prev.pack(side="left", padx=40, pady=10)
            self.btn_prev.configure(state="normal")
        else:
            self.btn_prev.pack_forget()
        self.btn_next.configure(text="Finish" if self.current_step == len(self.steps)-1 else "Next")

    def next_step(self):
        # Save current step data — use step function identity, not index,
        # so new steps don't break existing logic.
        current_fn = self.steps[self.current_step]
        if current_fn == self.step_license:
            if hasattr(self, 'ent_license'):
                self.data['license_key'] = self.ent_license.get("1.0", "end").strip()
        elif current_fn == self.step_network_ssl:
            if hasattr(self, 'ent_port'):
                self.data['api_port'] = self.ent_port.get()
            if hasattr(self, 'ssl_var'):
                self.data['use_ssl'] = self.ssl_var.get()
            if hasattr(self, 'ssl_choice_var'):
                self.data['ssl_choice'] = self.ssl_choice_var.get()
            if hasattr(self, 'ent_host'):
                self.data['host'] = self.ent_host.get()
        elif current_fn == self.step_idp:
            if hasattr(self, 'idp_var'):
                self.data['kc_choice'] = self.idp_var.get()
                self.data['auth_mode'] = "oidc" if self.idp_var.get() in ["2", "3"] else "local"
        elif current_fn == self.step_monitoring:
            if hasattr(self, 'mon_var'):
                self.data['mon_choice'] = self.mon_var.get()
            if hasattr(self, 'ent_grafana_port'):
                self.data['grafana_port'] = self.ent_grafana_port.get()
        elif current_fn == self.step_admin:
            if hasattr(self, 'ent_admin_user'):
                self.data['admin_user'] = self.ent_admin_user.get().strip()
            if hasattr(self, 'ent_admin_pass'):
                self.data['admin_pass'] = self.ent_admin_pass.get()
            if hasattr(self, 'ent_admin_pass2'):
                self.data['admin_pass2'] = self.ent_admin_pass2.get()
            # Validate before proceeding
            if current_fn == self.step_admin and self.current_step < len(self.steps) - 1:
                err = self._validate_admin()
                if err:
                    messagebox.showerror("Eingabefehler", err)
                    return
        elif current_fn == self.step_telemetry:
            if hasattr(self, 'telemetry_var'):
                self.data['send_telemetry'] = self.telemetry_var.get()
        elif current_fn == self.step_upgrade_backup:
            # Decide db_init_action for REINSTALL
            if hasattr(self, 'db_init_var'):
                self.data['db_init_action'] = self.db_init_var.get()

        if self.current_step < len(self.steps) - 1:
            # UPDATE mode: after backup step jump straight to summary (skip config steps)
            if (current_fn == self.step_upgrade_backup
                    and self.install_mode_var.get() == "update"):
                self.current_step = len(self.steps) - 1
            else:
                self.current_step += 1
                # Reinstall+Upgrade: skip step_admin (admin stays in DB, no new credentials needed)
                if (self.steps[self.current_step] == self.step_admin
                        and self.is_upgrade
                        and self.data.get('db_init_action', 'upgrade') != 'purge'):
                    self.current_step += 1
            self.show_step()
        else:
            self.finish_setup()

    def _validate_admin(self):
        import re
        user = self.data.get('admin_user', '').strip()
        pw = self.data.get('admin_pass', '')
        pw2 = self.data.get('admin_pass2', '')
        if not user:
            return "Benutzername darf nicht leer sein."
        if len(pw) < 12:
            return f"Passwort zu kurz ({len(pw)}/12 Zeichen). BSI TR-02102 erfordert mind. 12 Zeichen."
        cats = sum([
            bool(re.search(r'[A-Z]', pw)),
            bool(re.search(r'[a-z]', pw)),
            bool(re.search(r'[0-9]', pw)),
            bool(re.search(r'[^A-Za-z0-9]', pw)),
        ])
        if cats < 3:
            return "Passwort muss mind. 3 Zeichenklassen enthalten (Großbuchstaben, Kleinbuchstaben, Ziffern, Sonderzeichen)."
        if pw != pw2:
            return "Passwörter stimmen nicht überein."
        return None

    def step_remote_workers(self):
        ttk.Label(self.content_frame, text="Remote Worker konfigurieren", style=STYLE_HEADER).pack(pady=(0, 10))
        ttk.Label(self.content_frame, text="Sie können zusätzliche dedizierte Worker auf anderen Maschinen hinzufügen, um die Last zu verteilen.", 
                  wraplength=500).pack(pady=5)
        
        # Scrollable frame for workers
        list_container = ttk.Frame(self.content_frame)
        list_container.pack(fill="both", expand=True, pady=10)
        
        self.workers_list_frame = ttk.Frame(list_container)
        self.workers_list_frame.pack(fill="both", expand=True)
        
        self.render_workers_list()
        
        btn_add = ttk.Button(self.content_frame, text="+ Worker hinzufügen", command=self.add_worker_dialog)
        btn_add.pack(pady=10)

    def render_workers_list(self):
        for widget in self.workers_list_frame.winfo_children():
            widget.destroy()
            
        if not self.data['remote_workers']:
            ttk.Label(self.workers_list_frame, text="Keine remote Worker konfiguriert.", foreground=self.colors['fg_sub']).pack(pady=20)
            return

        for i, worker in enumerate(self.data['remote_workers']):
            f = ttk.Frame(self.workers_list_frame, style="Card.TFrame" if hasattr(self, 'card_style') else "TFrame")
            f.pack(fill="x", pady=2)
            ttk.Label(f, text=f"{worker['user']}@{worker['host']}", width=30).pack(side="left", padx=5)
            ttk.Label(f, text=f"[{worker['method'].upper()}]", foreground=self.colors['fg_sub']).pack(side="left", padx=5)
            
            btn_del = ttk.Button(f, text="Entfernen", command=lambda idx=i: self.remove_worker(idx), width=10)
            btn_del.pack(side="right", padx=5)
            
            btn_test = ttk.Button(f, text="Test", command=lambda idx=i: self.test_worker_connection(idx), width=8)
            btn_test.pack(side="right", padx=5)
            
            if worker['method'] == "manual":
                btn_cmd = ttk.Button(f, text="Befehl", command=self.show_worker_command, width=8)
                btn_cmd.pack(side="right", padx=5)
            else:
                btn_deploy = ttk.Button(f, text="Deploy", command=lambda idx=i: self.deploy_worker_ssh(idx), width=8)
                btn_deploy.pack(side="right", padx=5)

    def show_worker_command(self):
        cmd = self.get_worker_docker_command()
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Setup Befehl")
        dialog.geometry("600x350")
        dialog.configure(bg=self.colors['bg'])
        
        ttk.Label(dialog, text="Kopieren Sie diesen Befehl auf den Remote Worker:", wraplength=550).pack(pady=10)
        
        txt = tk.Text(dialog, bg=self.colors['bg_alt'], fg=self.colors['fg'], padx=10, pady=10, height=10)
        txt.pack(fill="both", expand=True, padx=20)
        txt.insert("1.0", cmd)
        txt.config(state="disabled")
        
        ttk.Button(dialog, text="Schließen", command=dialog.destroy).pack(pady=15)

    def add_worker_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Remote Worker hinzufügen")
        dialog.geometry("400x350")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Worker Details", style=STYLE_HEADER).pack(pady=10)
        
        content = ttk.Frame(dialog)
        content.pack(fill="both", expand=True, padx=20)
        
        content.columnconfigure(1, weight=1)
        ttk.Label(content, text="Host / IP:").grid(row=0, column=0, sticky="w", pady=5)
        ent_host = ttk.Entry(content)
        ent_host.grid(row=0, column=1, sticky="ew", pady=5)

        ttk.Label(content, text="SSH User:").grid(row=1, column=0, sticky="w", pady=5)
        ent_user = ttk.Entry(content)
        ent_user.insert(0, "root")
        ent_user.grid(row=1, column=1, sticky="ew", pady=5)
        
        ttk.Label(content, text="Methode:").grid(row=2, column=0, sticky="w", pady=5)
        method_var = tk.StringVar(value="ssh")
        ttk.Radiobutton(content, text="SSH Automatik", variable=method_var, value="ssh").grid(row=2, column=1, sticky="w")
        ttk.Radiobutton(content, text="Manuell (Befehle)", variable=method_var, value="manual").grid(row=3, column=1, sticky="w")
        
        ttk.Label(content, text="SSH Passwort:").grid(row=4, column=0, sticky="w", pady=5)
        ent_pw = ttk.Entry(content, show="*")
        ent_pw.grid(row=4, column=1, sticky="ew", pady=5)
        
        def save():
            host = ent_host.get().strip()
            user = ent_user.get().strip()
            pw = ent_pw.get()
            if not host: 
                messagebox.showerror("Fehler", "Host ist erforderlich")
                return
            
            self.data['remote_workers'].append({
                "host": host,
                "user": user,
                "password": pw,
                "method": method_var.get(),
                "status": "new"
            })
            self.render_workers_list()
            dialog.destroy()
            
        ttk.Button(dialog, text="Speichern", command=save, style=STYLE_ACTION_BTN).pack(pady=20)

    def remove_worker(self, index):
        self.data['remote_workers'].pop(index)
        self.render_workers_list()

    def get_worker_docker_command(self):
        if not self.secrets:
            self.generate_secrets()
            
        token = self.secrets.get('WORKER_REGISTRATION_TOKEN', 'YOUR_TOKEN')
        manager_url = f"http://{self.data['host']}:{self.data['api_port']}"
        db_url = f"postgresql://yads:{self.secrets.get('POSTGRES_PASSWORD')}@{self.data['host']}:5432/yads"
        redis_url = f"redis://{self.data['host']}:6379/0"
        
        return f"docker run -d --name yads-remote-worker \\\n" \
               f"  -e MANAGER_URL={manager_url} \\\n" \
               f"  -e WORKER_REGISTRATION_TOKEN={token} \\\n" \
               f"  -e DATABASE_URL={db_url} \\\n" \
               f"  -e REDIS_URL={redis_url} \\\n" \
               f"  registry.yads-security.com/yads/yads-worker:latest"

    def deploy_worker_ssh(self, index):
        worker = self.data['remote_workers'][index]
        host = worker['host']
        user = worker['user']
        pw = worker.get('password', '')
        cmd = self.get_worker_docker_command()
        
        def _deploy():
            try:
                # We try to use ssh with password passing via stdin if possible,
                # or just recommend sshpass if available.
                # For a professional result, we'll try a combination.
                import pexpect # Might not be available in standard lib
                
                # Fallback: simple subprocess with environment or similar
                # Since we don't have pexpect for sure, we'll use a script approach.
                ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", f"{user}@{host}", cmd]
                
                # Check if sshpass is installed
                has_sshpass = subprocess.run(["which", "sshpass"], capture_output=True).returncode == 0
                
                if has_sshpass and pw:
                    full_cmd = ["sshpass", "-p", pw] + ssh_cmd
                    res = subprocess.run(full_cmd, capture_output=True, text=True)
                else:
                    # Try without sshpass (might require key)
                    res = subprocess.run(ssh_cmd, capture_output=True, text=True)
                
                if res.returncode == 0:
                    self.root.after(0, lambda: messagebox.showinfo("Deployment", f"Worker auf {host} erfolgreich gestartet!"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Deployment Fehlgeschlagen", res.stderr))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                
        threading.Thread(target=_deploy, daemon=True).start()

    def test_worker_connection(self, index):
        worker = self.data['remote_workers'][index]
        host = worker['host']
        method = worker['method']
        
        def _test():
            results = []
            results.append(self._ping_host(host))
            if method == "ssh":
                results.append(self._check_ssh_port(host))
            
            msg = "\n".join(results)
            if "✗" in msg:
                self.root.after(0, lambda: messagebox.showwarning("Connection Test", msg))
            else:
                self.root.after(0, lambda: messagebox.showinfo("Connection Test", msg))
        
        threading.Thread(target=_test, daemon=True).start()

    def _ping_host(self, host):
        try:
            res = subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True)
            return "✓ Ping erfolgreich" if res.returncode == 0 else "✗ Ping fehlgeschlagen"
        except Exception:
            return "? Ping Fehler"

    def _check_ssh_port(self, host):
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                return "✓ SSH Port (22) offen" if s.connect_ex((host, 22)) == 0 else "✗ SSH Port (22) geschlossen"
        except Exception:
            return "? SSH Port Fehler"

    def finish_setup(self):
        mode = self.install_mode_var.get() if self.is_upgrade else "reinstall"
        mode_label = "Update" if mode == "update" else "Neuinstallation"
        if not messagebox.askyesno("Bestätigen", f"{mode_label} jetzt durchführen?"):
            return
        try:
            # Backup always enforced for existing installations
            if self.is_upgrade:
                self.execute_backup()

            if self.is_upgrade and mode == "update":
                # UPDATE: pull new images, restart — preserve all config
                print("Pulling latest images...")
                subprocess.run(["docker", "compose", "pull"], check=True)
                print("Restarting services...")
                subprocess.run(["docker", "compose", "up", "-d", "--remove-orphans"], check=True)
                messagebox.showinfo("Update abgeschlossen",
                                    "YADS wurde erfolgreich aktualisiert.\n\n"
                                    "Die neuen Images sind aktiv.")
                self.root.quit()
                return

            # REINSTALL or fresh install
            if self.is_upgrade:
                print("Stopping existing containers for reinstall...")
                subprocess.run(["docker", "compose", "down"], capture_output=True, timeout=60)

                db_action = self.data.get('db_init_action', 'upgrade')
                if db_action == "purge":
                    # Purge: drop the postgres volume so new password works cleanly
                    subprocess.run(["docker", "volume", "rm", "-f", "yads_postgres_data"],
                                   capture_output=True, timeout=30)

            self.generate_secrets()

            # For reinstall with data preservation: keep existing POSTGRES_PASSWORD
            # so the running volume isn't locked out by a new credential
            if self.is_upgrade and self.data.get('db_init_action', 'upgrade') == "upgrade":
                if os.path.exists(".env"):
                    with open(".env") as f:
                        for line in f:
                            if line.startswith("POSTGRES_PASSWORD="):
                                old_pw = line.split("=", 1)[1].strip()
                                if old_pw:
                                    self.secrets["POSTGRES_PASSWORD"] = old_pw
                                break
            self.write_env_file()
            self.write_nginx_config()
            self.authenticate_registry()

            msg = "Configuration applied successfully!\n\nSoll YADS jetzt gestartet und der Browser (in 5s) geöffnet werden?"
            if messagebox.askyesno("Start YADS?", msg):
                # Show progress in UI
                self.show_startup_progress()
                self.start_yads_and_open_browser()
            else:
                messagebox.showinfo("Success", "Setup complete. Start YADS manually with 'docker compose up -d'.")
                self.root.quit()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to complete setup: {e}")

    def show_startup_progress(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        ttk.Label(self.content_frame, text="YADS wird gestartet...", style=STYLE_HEADER).pack(pady=40)
        self.lbl_progress = ttk.Label(self.content_frame,
                                       text="Docker-Container werden initialisiert...",
                                       wraplength=500, justify="center")
        self.lbl_progress.pack(pady=10)

        self.btn_prev.configure(state="disabled")
        self.btn_next.configure(state="disabled")
        self.root.update()

    def _check_port_free(self, port):
        """Returns the name of the process blocking the port, or None if free."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", int(port)))
            return None
        except OSError:
            return f"Port {port} bereits belegt"

    def start_yads_and_open_browser(self):
        def _target():
            try:
                # Pre-flight: check if the configured port is free
                port = int(self.data.get('api_port', 80))
                conflict = self._check_port_free(port)
                if conflict:
                    msg = (f"Port {port}/TCP ist bereits belegt.\n\n"
                           f"Bitte beende den anderen Dienst (z.B. Apache, Nginx) "
                           f"oder wähle einen anderen Port in der Konfiguration.")
                    self.root.after(0, lambda m=msg: messagebox.showerror("Port-Konflikt", m))
                    self.root.after(0, lambda: self.btn_next.configure(state="normal"))
                    return

                result = subprocess.run(
                    ["docker", "compose", "up", "-d", "--force-recreate"],
                    capture_output=True, text=True
                )
                if result.returncode != 0:
                    # Filter out Docker Compose warnings — show only actual errors
                    lines = (result.stderr + result.stdout).splitlines()
                    errors = [l for l in lines if "level=warning" not in l and l.strip()]
                    raise RuntimeError("\n".join(errors) or result.stderr.strip())

                # Sync DB password: set it via Unix socket (no password needed from inside container)
                # This fixes mismatches between .env and an existing postgres volume
                self.root.after(0, lambda: self._set_progress("Datenbank-Passwort synchronisieren..."))
                pg_password = self.secrets.get("POSTGRES_PASSWORD", "")
                if pg_password:
                    for _ in range(15):  # wait up to 30s for DB to be ready
                        sync = subprocess.run(
                            ["docker", "exec", "yads-db", "psql", "-U", "yads", "-d", "yads",
                             "-c", f"ALTER USER yads WITH PASSWORD '{pg_password}';"],
                            capture_output=True, text=True, timeout=10
                        )
                        if sync.returncode == 0:
                            break
                        time.sleep(2)

                proto = "https" if self.data['use_ssl'] else "http"
                port = self.data['api_port']
                base_url = f"{proto}://{self.data['host']}:{port}"
                # Health check goes directly to yads-api (bypassing nginx which may still be starting)
                # With nginx: yads-api is on YADS_DIRECT_PORT=8000
                # Without nginx: yads-api is on API_PORT (e.g. 8085)
                direct_port = 8000 if self.data.get('use_nginx') else int(port)
                health_url = f"{proto}://localhost:{direct_port}/health"

                # Wait until YADS API is reachable (max 90s)
                import urllib.request
                import urllib.error
                api_ready = False
                for i in range(45):
                    self.root.after(0, lambda i=i: self._set_progress(
                        f"Warte auf YADS-Start... ({i*2}s) — {health_url}"))
                    try:
                        urllib.request.urlopen(health_url, timeout=2)
                        api_ready = True
                        break
                    except Exception:
                        time.sleep(2)

                if not api_ready:
                    # Show docker logs for diagnosis
                    logs = subprocess.run(
                        ["docker", "logs", "--tail", "20", "yads-api"],
                        capture_output=True, text=True
                    )
                    raise RuntimeError(
                        f"YADS-API nicht erreichbar nach 90s.\n\n"
                        f"Getestete URL: {health_url}\n\n"
                        f"Letzte Container-Logs:\n{logs.stdout or logs.stderr}"
                    )

                # Post-start setup via API
                self._run_post_start_setup(base_url)

                self.root.after(0, lambda: self._set_progress("Fertig! Browser wird geöffnet..."))
                time.sleep(1)
                webbrowser.open(base_url)
                time.sleep(1)
                self.root.after(100, self.root.destroy)
            except Exception as e:
                err_msg = str(e)
                print(f"Error starting YADS: {err_msg}")
                def _show_err(m=err_msg):
                    try:
                        if self.root.winfo_exists():
                            messagebox.showerror("Startup Error", f"Could not start YADS:\n\n{m}")
                    except Exception:
                        pass
                self.root.after(100, _show_err)

        threading.Thread(target=_target, daemon=False).start()

    def _set_progress(self, msg):
        """Update the startup progress label if it exists."""
        if hasattr(self, 'lbl_progress'):
            self.lbl_progress.configure(text=msg)

    def _run_post_start_setup(self, base_url):
        """Call /setup/* API endpoints after YADS is up to configure license + admin."""
        import urllib.request
        import urllib.error
        import json

        def _post(path, payload):
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                f"{base_url}{path}",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="replace")
                return e.code, body
            except Exception as ex:
                return None, str(ex)

        errors = []

        # 1. License key
        license_key = self.data.get('license_key', '').strip()
        if license_key:
            self.root.after(0, lambda: self._set_progress("Lizenz aktivieren..."))
            status, body = _post("/setup/check-license", {"license_key": license_key})
            if status is None:
                errors.append(f"Lizenz: Verbindungsfehler — {body}")
            elif status not in (200, 201):
                errors.append(f"Lizenz ungültig ({status}): {body}")

        # 2. Create admin — only for fresh install or purge reinstall
        # For update or upgrade reinstall the admin already exists in the DB
        is_fresh = not self.is_upgrade
        is_purge = self.data.get('db_init_action') == 'purge'
        if is_fresh or is_purge:
            admin_user = self.data.get('admin_user', '').strip()
            admin_pass = self.data.get('admin_pass', '')
            if admin_user and admin_pass:
                self.root.after(0, lambda: self._set_progress("Admin-Konto anlegen..."))
                status, body = _post("/setup/create-admin", {"username": admin_user, "password": admin_pass})
                if status is None:
                    errors.append(f"Admin: Verbindungsfehler — {body}")
                elif status not in (200, 201):
                    errors.append(f"Admin-Erstellung fehlgeschlagen ({status}): {body}")

        # 3. DB init (purge) if REINSTALL + purge chosen — before finish
        if self.data.get('db_init_action') == 'purge':
            self.root.after(0, lambda: self._set_progress("Datenbank zurücksetzen..."))
            status, body = _post("/setup/init-data", {"action": "purge"})
            if status is None or status not in (200, 201):
                errors.append(f"DB-Reset fehlgeschlagen ({status}): {body}")

        # 4. Mark setup complete
        self.root.after(0, lambda: self._set_progress("Setup abschließen..."))
        status, body = _post("/setup/finish", {})
        if status is None or status not in (200, 201):
            errors.append(f"Setup-Abschluss fehlgeschlagen ({status}): {body}")
        else:
            # Retrieve the stable instance_uuid from the API response (may override local one)
            if isinstance(body, dict) and body.get("instance_uuid"):
                self.data['instance_uuid'] = body["instance_uuid"]

        # 5. Send installation report — only if user opted in
        if self.data.get('send_telemetry'):
            self.root.after(0, lambda: self._set_progress("Installationsmeldung senden..."))
            self._send_installation_report()

        if errors:
            msg = "Setup mit Warnungen abgeschlossen:\n\n" + "\n\n".join(errors)
            def _show_warnings(m=msg):
                try:
                    if self.root.winfo_exists():
                        messagebox.showwarning("Setup-Warnungen", m)
                except Exception:
                    pass
            self.root.after(0, _show_warnings)

    def _build_report_payload(self):
        """Build the installation report payload dict."""
        import json as _json, base64 as _b64
        from datetime import datetime, timezone
        import urllib.request

        instance_uuid = self.data.get('instance_uuid', '')

        # Extract customer_id from license key payload (base64 JSON, no crypto needed)
        customer_id = ""
        license_key = self.data.get('license_key', '').strip()
        if license_key and '.' in license_key:
            try:
                p_b64 = license_key.split('.')[0]
                p_b64 += '=' * ((4 - len(p_b64) % 4) % 4)
                lic_data = _json.loads(_b64.urlsafe_b64decode(p_b64))
                customer_id = lic_data.get('customer_id', '')
            except Exception:
                pass

        # Try to get the real version from the running YADS API
        version = self.data.get('yads_version', 'latest')
        try:
            v_req = urllib.request.urlopen(
                f"{self._base_url_for_api()}/api/updates/version", timeout=5
            )
            version = _json.loads(v_req.read()).get("version", version)
        except Exception:
            pass

        return {
            "instance_uuid": instance_uuid,
            "version": version,
            "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "install_type": "installer",
            "customer_id": customer_id,
        }

    def _is_business_license(self):
        """Return True if the license contains a customer_id (= commercial/business)."""
        payload = self._build_report_payload()
        return bool(payload.get('customer_id'))

    def _send_installation_report(self):
        """
        Send installation report. Behaviour depends on license tier:

        Community Edition (no customer_id):
            Try online → if offline: save JSON + queue in YADS for auto-retry.
            Transparent info dialog on failure.

        Business (customer_id present):
            Try online → if offline: show Activation Request Code (Option B)
            so the customer can contact YADS team directly.
            Additionally queue in YADS for auto-retry once internet is available.
            The YADS team retains full control — no silent self-activation.
        """
        import json as _json, urllib.request, os as _os, base64 as _b64

        payload = self._build_report_payload()
        customer_id = payload.get('customer_id', '')
        is_business = bool(customer_id)

        # --- Try online send ---
        sent = False
        send_error = None
        try:
            data = _json.dumps(payload).encode()
            req = urllib.request.Request(
                "https://support.yads-security.com/api/installation",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10):
                sent = True
        except Exception as exc:
            send_error = str(exc)

        if sent:
            return  # Done — nothing more to do

        # --- Offline: queue in YADS API for auto-retry (both tiers) ---
        try:
            q_data = _json.dumps(payload).encode()
            q_req = urllib.request.Request(
                f"{self._base_url_for_api()}/setup/queue-report",
                data=q_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(q_req, timeout=5)
        except Exception:
            pass

        if is_business:
            # === Option B — Business: Activation Request Code ===
            # Encode payload as compact base64 string for manual handoff
            act_code = _b64.urlsafe_b64encode(
                _json.dumps(payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')

            # Save JSON file for email attachment
            report_path = _os.path.expanduser("~/yads-activation-request.json")
            try:
                with open(report_path, "w") as f:
                    _json.dump(payload, f, indent=2)
            except Exception:
                report_path = None

            lines = [
                "┌─────────────────────────────────────────────────────┐",
                "│         AKTIVIERUNGSANFRAGE ERFORDERLICH            │",
                "└─────────────────────────────────────────────────────┘",
                "",
                "Diese Installation konnte nicht automatisch registriert",
                "werden (kein Internetzugang zum YADS-Aktivierungsserver).",
                "",
                "Was Sie jetzt tun müssen:",
                "  1. Senden Sie den folgenden Aktivierungscode per E-Mail",
                "     an: aktivierung@yads-security.com",
                "  2. Das YADS-Team bestätigt Ihre Installation.",
                "  3. YADS versucht außerdem beim nächsten Start mit",
                "     Internetzugang die Registrierung automatisch.",
                "",
                "─── Ihr Aktivierungscode (bitte vollständig kopieren) ───",
                "",
                act_code,
                "",
                "─────────────────────────────────────────────────────────",
            ]
            if report_path:
                lines += [
                    f"Eine Kopie wurde gespeichert unter: {report_path}",
                ]
            lines += [
                "",
                "Enthaltene Daten (nur diese werden übertragen):",
                f"  instance_uuid : {payload['instance_uuid']}",
                f"  customer_id   : {customer_id}",
                f"  version       : {payload['version']}",
                f"  install_type  : installer",
                "",
                "Keine Domainnamen, IPs oder Scan-Daten werden übertragen.",
                "YADS läuft normal weiter — die Registrierung ist separat.",
            ]

        else:
            # === Community Edition: einfaches Offline-Reporting ===
            report_path = _os.path.expanduser("~/yads-installation-report.json")
            try:
                with open(report_path, "w") as f:
                    _json.dump(payload, f, indent=2)
            except Exception:
                report_path = None

            lines = [
                "Installationsmeldung konnte nicht gesendet werden.",
                f"(Ursache: {send_error})",
                "",
                "YADS sendet die Meldung automatisch beim nächsten Start,",
                "sobald eine Internetverbindung verfügbar ist.",
            ]
            if report_path:
                lines += [
                    f"Lokale Kopie gespeichert: {report_path}",
                ]
            lines += [
                "",
                "Gesendete Daten:",
                f"  instance_uuid : {payload['instance_uuid']}",
                f"  version       : {payload['version']}",
                f"  install_type  : installer",
                "",
                "Dies ist ein anonymes Community-Edition-Reporting.",
                "Keine Domainnamen oder Scan-Daten werden übertragen.",
            ]

        title = ("Aktivierungsanfrage" if is_business
                 else "Installationsmeldung — Offline")
        msg = "\n".join(lines)

        def _show(m=msg, t=title):
            try:
                if self.root.winfo_exists():
                    messagebox.showinfo(t, m)
            except Exception:
                pass
        self.root.after(0, _show)

    def _base_url_for_api(self):
        """Return the direct YADS API base URL (bypasses nginx if active)."""
        proto = "https" if self.data.get('use_ssl') else "http"
        direct_port = 8000 if self.data.get('use_nginx') else int(self.data.get('api_port', 80))
        return f"{proto}://localhost:{direct_port}"

    def authenticate_registry(self):
        # Read-only credentials for YADS registry
        reg_user = "yads-readonly"
        reg_token = "REDACTED"
        reg_url = "registry.yads-security.com"
        
        try:
            # Note: In a production environment, we might want to mask the token 
            # but for this installer it mirrors the original setup.sh logic.
            cmd = ["docker", "login", reg_url, "-u", reg_user, "--password-stdin"]
            subprocess.run(cmd, input=reg_token, text=True, check=True, capture_output=True, timeout=30)
            print("Successfully authenticated with YADS registry.")
        except subprocess.CalledProcessError as e:
            print(f"Registry login failed: {e.stderr}")
            # We don't necessarily want to crash here, maybe the user is already logged in 
            # or has their own credentials.

    def generate_secrets(self):
        import secrets
        import string
        def rand_str(length=24):
            alphabet = string.ascii_letters + string.digits
            return ''.join(secrets.choice(alphabet) for _ in range(length))
        
        self.secrets = {
            "POSTGRES_PASSWORD": rand_str(32),
            "SECRET_KEY": secrets.token_hex(32),
            "WORKER_REGISTRATION_TOKEN": secrets.token_hex(20),
            "SUPPORT_ADMIN_TOKEN": secrets.token_hex(24)
        }

    def write_env_file(self):
        use_nginx = self.data['use_nginx']
        # Build COMPOSE_PROFILES: activate nginx profile when chosen,
        # add keycloak/monitoring profiles as needed below
        profiles = []
        if use_nginx:
            profiles.append("nginx")

        env_content = f"""# Generated by YADS GUI Setup
POSTGRES_PASSWORD={self.secrets['POSTGRES_PASSWORD']}
SECRET_KEY={self.secrets['SECRET_KEY']}
WORKER_REGISTRATION_TOKEN={self.secrets['WORKER_REGISTRATION_TOKEN']}
SUPPORT_ADMIN_TOKEN={self.secrets['SUPPORT_ADMIN_TOKEN']}
YADS_VERSION=latest
API_PORT={self.data['api_port']}
AUTH_MODE={self.data['auth_mode']}
HAS_NGINX={'true' if use_nginx else 'false'}
"""
        if self.data['auth_mode'] == "oidc" and self.data['kc_choice'] == "2": # Bundled
            profiles.append("keycloak")
            env_content += f"""
KC_PORT={self.data['kc_port']}
KC_ADMIN=admin
KC_ADMIN_PASSWORD={secrets.token_urlsafe(16)}
KC_DB_PASSWORD={secrets.token_urlsafe(16)}
OIDC_SERVER_URL=http://keycloak:8080
OIDC_PUBLIC_URL=http://{self.data['yads_host']}:{self.data['kc_port']}
OIDC_REALM=yads
OIDC_CLIENT_ID=yads
OIDC_CLIENT_SECRET={secrets.token_hex(24)}
OIDC_REDIRECT_URI=http://{self.data['yads_host']}:{self.data['api_port']}/auth/oidc/callback
"""

        if self.data['mon_choice'] == "2": # Bundled
            profiles.append("monitoring")
            env_content += f"""
METRICS_ENABLED=true
METRICS_AUTH_MODE=token
METRICS_TOKEN={secrets.token_hex(24)}
GRAFANA_PORT={self.data['grafana_port']}
GRAFANA_ADMIN_PASSWORD={secrets.token_urlsafe(16)}
"""

        if profiles:
            env_content += f"COMPOSE_PROFILES={','.join(profiles)}\n"

        # When nginx is active: yads-api uses YADS_DIRECT_PORT (8000) internally,
        # nginx handles the external API_PORT — prevents port conflict
        # When no nginx: YADS_DIRECT_PORT = API_PORT so yads-api is directly reachable
        if use_nginx:
            env_content += "YADS_DIRECT_PORT=8000\n"
        else:
            env_content += f"YADS_DIRECT_PORT={self.data['api_port']}\n"

        license_key = self.data.get('license_key', '').strip()
        if license_key:
            env_content += f"LICENSE_KEY={license_key}\n"

        with open(".env", "w") as f:
            f.write(env_content)

    def write_nginx_config(self):
        if not self.data['use_nginx']:
            return
        
        template_path = "nginx.conf.template"
        # Since we are in a pyz, we might need to find where the template is.
        # But usually the installer is run in a directory that HAS the template.
        if os.path.exists(template_path):
            with open(template_path, "r") as f:
                content = f.read()
            
            content = content.replace("{{PORT}}", self.data['api_port'])
            if self.data['use_ssl']:
                content = content.replace(f"listen {self.data['api_port']};", f"listen {self.data['api_port']} ssl;")
            
            os.makedirs("nginx", exist_ok=True)
            # Docker may have created nginx/nginx.conf as a directory on a previous
            # failed start (bind-mount with missing file) — remove it before writing
            nginx_conf = "nginx/nginx.conf"
            if os.path.isdir(nginx_conf):
                import shutil
                shutil.rmtree(nginx_conf)
            with open(nginx_conf, "w") as f:
                f.write(content)

    def prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.show_step()

    # --- Step 0: Welcome ---
    def step_upgrade_backup(self):
        ttk.Label(self.content_frame, text="Vorhandene Installation erkannt", style=STYLE_HEADER).pack(pady=(0, 10))

        # ── Mode selection ────────────────────────────────────────────────────
        mode_frame = tk.LabelFrame(self.content_frame, text="Installationsmodus",
                                   bg=self.colors['bg'], fg=self.colors['fg'])
        mode_frame.pack(fill="x", pady=(0, 12))

        mode_desc = tk.StringVar()

        def _update_desc(*_):
            if self.install_mode_var.get() == "update":
                mode_desc.set("Zieht die neuesten Docker-Images und startet die Dienste neu.\n"
                              "Konfiguration und Daten bleiben vollständig erhalten.")
            else:
                mode_desc.set("Führt eine vollständige Neuinstallation durch.\n"
                              "Alle Konfigurationsschritte werden erneut durchlaufen.")

        ttk.Radiobutton(mode_frame, text="Update  — Images aktualisieren, Konfig beibehalten",
                        variable=self.install_mode_var, value="update",
                        command=_update_desc).pack(anchor="w", padx=10, pady=(8, 2))
        ttk.Radiobutton(mode_frame, text="Reinstall  — Neuinstallation (Konfig neu konfigurieren)",
                        variable=self.install_mode_var, value="reinstall",
                        command=_update_desc).pack(anchor="w", padx=10, pady=(2, 8))

        desc_lbl = ttk.Label(mode_frame, textvariable=mode_desc, foreground=self.colors['fg_sub'],
                             wraplength=480, justify="left")
        desc_lbl.pack(anchor="w", padx=10, pady=(0, 8))
        _update_desc()

        # ── Backup (always enforced) ──────────────────────────────────────────
        bk_frame = tk.LabelFrame(self.content_frame, text="Backup (verpflichtend)",
                                 bg=self.colors['bg'], fg=self.colors['fg'])
        bk_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(bk_frame,
                  text="Ein Backup wird vor jeder Änderung automatisch erstellt.",
                  foreground=self.colors['fg_sub'], wraplength=480).pack(anchor="w", padx=10, pady=(8, 4))

        # Check if yads-api is running
        api_running = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", "yads-api"],
            capture_output=True, text=True, timeout=10
        ).stdout.strip() == "true"

        ttk.Radiobutton(bk_frame, text="Unverschlüsselt  (SQL Dump via pg_dump)",
                        variable=self.backup_var, value="sql").pack(anchor="w", padx=10, pady=3)

        enc_rb = ttk.Radiobutton(bk_frame, text="Verschlüsselt  (YADS interner Mechanismus)",
                                 variable=self.backup_var, value="encrypted")
        enc_rb.pack(anchor="w", padx=10, pady=3)

        if not api_running:
            enc_rb.configure(state="disabled")
            if self.backup_var.get() == "encrypted":
                self.backup_var.set("sql")
            ttk.Label(bk_frame,
                      text="⚠ YADS-API läuft nicht — verschlüsseltes Backup nicht verfügbar.",
                      foreground="#f0a500", wraplength=480,
                      font=("sans-serif", 9, "italic")).pack(anchor="w", padx=28, pady=(0, 6))

        # Password entry (shown only for encrypted)
        self.pw_frame = ttk.Frame(bk_frame)
        ttk.Label(self.pw_frame, text="Backup-Passwort:").pack(side="left", padx=(10, 5))
        self.ent_backup_pw = ttk.Entry(self.pw_frame, textvariable=self.backup_password, show="*")
        self.ent_backup_pw.pack(side="left", fill="x", expand=True, padx=5)

        def toggle_pw(*_):
            try:
                if self.backup_var.get() == "encrypted":
                    self.pw_frame.pack(fill="x", pady=(4, 8))
                else:
                    self.pw_frame.pack_forget()
            except Exception:
                return

        self.backup_var.trace_add("write", toggle_pw)
        toggle_pw()

        # ── DB Init (shown only for REINSTALL mode) ───────────────────────────
        self.db_init_var = tk.StringVar(value=self.data.get('db_init_action', 'upgrade'))
        self.db_init_frame = tk.LabelFrame(self.content_frame, text="Datenbankinitialisierung (nur bei Reinstall)",
                                           bg=self.colors['bg'], fg=self.colors['fg'])
        self.db_init_frame.pack(fill="x", pady=(8, 0))

        ttk.Radiobutton(self.db_init_frame,
                        text="Upgrade  — Daten behalten, Schema migrieren",
                        variable=self.db_init_var, value="upgrade").pack(anchor="w", padx=10, pady=(8, 2))
        ttk.Radiobutton(self.db_init_frame,
                        text="Factory Reset  — ALLE Daten löschen (Neuanfang)",
                        variable=self.db_init_var, value="purge").pack(anchor="w", padx=10, pady=(2, 8))

        def _toggle_db_init(*_):
            if self.install_mode_var.get() == "reinstall":
                self.db_init_frame.pack(fill="x", pady=(8, 0))
            else:
                self.db_init_frame.pack_forget()

        self.install_mode_var.trace_add("write", _toggle_db_init)
        _toggle_db_init()

    def execute_backup(self):
        b_type = self.backup_var.get()
        if b_type == "encrypted":
            self.run_encrypted_backup()
        else:
            self.run_sql_backup()  # Default: sql (backup always enforced)

    def run_sql_backup(self):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"yads_backup_{timestamp}.sql.gz"
        try:
            # Read password from .env
            pg_password = ""
            if os.path.exists(".env"):
                with open(".env", "r") as f:
                    for line in f:
                        if line.startswith("POSTGRES_PASSWORD="):
                            pg_password = line.split("=", 1)[1].strip().strip('"').strip("'")
                            break
            env = os.environ.copy()
            if pg_password:
                env["PGPASSWORD"] = pg_password

            # Check that yads-db container is running (use container name, not compose service,
            # to work regardless of which directory/project started the stack)
            check = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", "yads-db"],
                capture_output=True, text=True, timeout=10
            )
            if check.stdout.strip() != "true":
                raise RuntimeError("Container yads-db läuft nicht. Starte YADS zuerst oder backup manuell.")

            sql_file = filename.replace(".gz", "")
            cmd = ["docker", "exec", "-i", "yads-db", "pg_dump", "-U", "yads", "yads"]
            with open(sql_file, "w") as f_out:
                subprocess.run(cmd, check=True, stdout=f_out, env=env)

            subprocess.run(["gzip", sql_file], check=True)
            messagebox.showinfo("Backup", f"Backup erstellt: {os.path.abspath(filename)}")
        except Exception as e:
            messagebox.showerror("Backup Error", f"SQL Backup fehlgeschlagen:\n{e}")
            raise

    def run_encrypted_backup(self):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"yads_backup_encrypted_{timestamp}.enc"
        pw = self.backup_password.get()
        if not pw: raise ValueError("Passwort erforderlich!")
        
        try:
            script = f"""
from yads.core.backup import create_backup_zip
from yads.database import SessionLocal
import io
with SessionLocal() as session:
    buf = create_backup_zip(session, password='{pw}')
    with open('/tmp/backup.enc', 'wb') as f:
        f.write(buf.getbuffer())
"""
            # Check container is running before exec
            check = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", "yads-api"],
                capture_output=True, text=True, timeout=10
            )
            if check.stdout.strip() != "true":
                raise RuntimeError("Container yads-api läuft nicht. Encrypted Backup nicht möglich.\n"
                                   "Wähle 'Unverschlüsselt' oder starte YADS zuerst.")
            subprocess.run(["docker", "exec", "-i", "yads-api", "python3", "-c", script], check=True)
            subprocess.run(["docker", "cp", "yads-api:/tmp/backup.enc", filename], check=True)
            subprocess.run(["docker", "exec", "-i", "yads-api", "rm", "/tmp/backup.enc"], check=True)
            messagebox.showinfo("Backup", f"Verschlüsseltes Backup erstellt: {filename}")
        except Exception as e:
            messagebox.showerror("Backup Error", f"Verschlüsseltes Backup fehlgeschlagen: {e}")
            raise

    def step_welcome(self):
        if self.logo_img:
            tk.Label(self.content_frame, image=self.logo_img, bg=self.colors['bg']).pack(pady=(0, 10))
            
        ttk.Label(self.content_frame, text="Welcome to YADS!", style=STYLE_HEADER).pack(pady=(0, 10))
        
        explanation = (
            "This setup wizard will guide you through the installation and configuration "
            "of Yet Another Domain Scanner (YADS).\n\n"
            "We will check your system for required dependencies, configure your "
            "network settings, and prepare the environment for deployment."
        )
        ttk.Label(self.content_frame, text=explanation, wraplength=500, justify="center").pack(pady=10)
        
        # Disclaimer from homepage
        disclaimer = (
            "⚠️ HINWEIS: Dieses Projekt ist das Ergebnis von 'Vibe-Coding' (KI-gestützte Entwicklung).\n"
            "Trotz umfangreicher Tests erfolgt die Nutzung auf eigene Gefahr (Use at your own risk)!"
        )
        ttk.Label(self.content_frame, text=disclaimer, wraplength=500, justify="center", 
                  font=("sans-serif", 8, "italic"), foreground=self.colors['fg_sub']).pack(pady=10)
        
        ttk.Label(self.content_frame, text="Click 'Next' to begin the setup process.", font=("sans-serif", 9, "bold")).pack(pady=15)

    # --- Step 1: Dependencies ---
    def step_dependencies(self):
        ttk.Label(self.content_frame, text="Checking Dependencies", style=STYLE_HEADER).pack(pady=(0, 20))
        
        self.dep_list = tk.Frame(self.content_frame, bg=self.colors['bg'])
        self.dep_list.pack(fill="x")
        
        self.add_dep_status("Docker CLI", DependencyChecker.check_docker())
        self.add_dep_status("Docker Compose (v2+)", DependencyChecker.check_docker_compose())
        self.add_dep_status("OpenSSL", DependencyChecker.check_openssl())
        
        btn_fix = ttk.Button(self.content_frame, text="Install Missing Dependencies", command=self.fix_dependencies)
        btn_fix.pack(pady=20)

    def add_dep_status(self, name, ok):
        color = self.colors['success'] if ok else self.colors['error']
        icon = "✓" if ok else "✗"
        frame = tk.Frame(self.dep_list, bg=self.colors['bg'])
        frame.pack(fill="x", pady=2)
        ttk.Label(frame, text=f"{icon} {name}", foreground=color).pack(side="left")

    def fix_dependencies(self):
        ok, msg = DependencyChecker.install_dependencies()
        if ok:
            messagebox.showinfo("Success", msg)
            self.show_step()
        else:
            messagebox.showerror("Error", msg)

    # --- Step 2: Network & SSL ---
    def step_network_ssl(self):
        ttk.Label(self.content_frame, text="Network & SSL Configuration", style=STYLE_HEADER).pack(pady=(0, 20))
        
        # Port
        port_frame = tk.Frame(self.content_frame, bg=self.colors['bg'])
        port_frame.pack(fill="x", pady=5)
        ttk.Label(port_frame, text="API Port:").pack(side="left")
        self.ent_port = ttk.Entry(port_frame, width=10)
        self.ent_port.insert(0, self.data['api_port'])
        self.ent_port.pack(side="left", padx=10)
        
        # SSL Checkbox
        self.ssl_var = tk.BooleanVar(value=self.data['use_ssl'])
        cb_ssl = ttk.Checkbutton(self.content_frame, text="Enable SSL / HTTPS", 
                                variable=self.ssl_var, command=self.toggle_ssl_options)
        cb_ssl.pack(anchor="w", pady=10)
        
        # SSL Certificate Options
        self.ssl_options_frame = tk.Frame(self.content_frame, bg=self.colors['bg'])
        self.ssl_options_frame.pack(fill="x", padx=20)
        
        self.ssl_choice_var = tk.StringVar(value=self.data['ssl_choice'])
        ttk.Radiobutton(self.ssl_options_frame, text="Generate self-signed certificate", 
                        variable=self.ssl_choice_var, value="1").pack(anchor="w")
        ttk.Radiobutton(self.ssl_options_frame, text="Use custom certificates (provide paths later)", 
                        variable=self.ssl_choice_var, value="2").pack(anchor="w")
        
        self.toggle_ssl_options()
        
        # Host & Ping
        ttk.Label(self.content_frame, text="API Host / Server Address:").pack(anchor="w", pady=(20, 0))
        host_frame = tk.Frame(self.content_frame, bg=self.colors['bg'])
        host_frame.pack(fill="x", pady=5)
        self.ent_host = ttk.Entry(host_frame)
        self.ent_host.insert(0, self.data['host'])
        self.ent_host.pack(side="left", fill="x", expand=True, padx=(0, 5))
        btn_ping = ttk.Button(host_frame, text="Ping", command=self.run_ping)
        btn_ping.pack(side="right")
        
        self.lbl_resolution = ttk.Label(self.content_frame, text="IP: unknown | Hostname: unknown", font=("Courier", 9))
        self.lbl_resolution.pack(anchor="w")
        self.update_resolution()

    def toggle_ssl_options(self):
        if self.ssl_var.get():
            self.ssl_options_frame.pack(fill="x", padx=20)
        else:
            self.ssl_options_frame.pack_forget()

    # --- Step 3: Identity Provider ---
    def step_idp(self):
        ttk.Label(self.content_frame, text="Identity Provider (Auth)", style=STYLE_HEADER).pack(pady=(0, 10))
        
        ttk.Label(self.content_frame, text="Choose how users should authenticate:", wraplength=500).pack(anchor="w", pady=10)
        
        self.idp_var = tk.StringVar(value=self.data['kc_choice'])
        
        ttk.Radiobutton(self.content_frame, text="Local accounts only (simple)", 
                        variable=self.idp_var, value="1").pack(anchor="w", pady=5)
        ttk.Radiobutton(self.content_frame, text="Bundled Keycloak (complete stack)", 
                        variable=self.idp_var, value="2").pack(anchor="w", pady=5)
        ttk.Radiobutton(self.content_frame, text="External OIDC Provider (Keycloak, Auth0, etc.)", 
                        variable=self.idp_var, value="3").pack(anchor="w", pady=5)
        
        idp_desc = (
            "Local auth is sufficient for small teams. Keycloak adds SSO capability "
            "but requires more system resources."
        )
        ttk.Label(self.content_frame, text=idp_desc, font=("sans-serif", 9, "italic"), 
                  foreground=self.colors['fg_sub'], wraplength=500).pack(pady=10)

    def update_resolution(self, event=None):
        host = getattr(self, 'ent_host', None)
        if not host: return
        host_val = host.get()
        ip, hostname = NetworkTools.resolve(host_val)
        if ip:
            self.lbl_resolution.configure(text=f"IP: {ip} | Hostname: {hostname}")
            self.data['host'] = host_val
        else:
            self.lbl_resolution.configure(text="DNS: Could not resolve")

    def run_ping(self):
        host = self.ent_host.get() if hasattr(self, 'ent_host') else self.data.get('host', '')
        ok, output = NetworkTools.ping(host)
        if ok:
            messagebox.showinfo("Ping Success", f"Host {host} is reachable.")
        else:
            messagebox.showerror("Ping Failed", f"Could not reach {host}.\n\n{output}")

    # --- Step 4: Monitoring ---
    def step_monitoring(self):
        ttk.Label(self.content_frame, text="Observability & Monitoring", style=STYLE_HEADER).pack(pady=(0, 10))
        
        ttk.Label(self.content_frame, text="YADS exposes Prometheus metrics at /metrics.", wraplength=500).pack(anchor="w", pady=10)
        
        self.mon_var = tk.StringVar(value=self.data['mon_choice'])
        
        ttk.Radiobutton(self.content_frame, text="None (no monitoring stack)", 
                        variable=self.mon_var, value="1").pack(anchor="w", pady=5)
        ttk.Radiobutton(self.content_frame, text="Bundled stack (Prometheus + Grafana + Loki)", 
                        variable=self.mon_var, value="2").pack(anchor="w", pady=5)
        ttk.Radiobutton(self.content_frame, text="External (connect your own Prometheus)", 
                        variable=self.mon_var, value="3").pack(anchor="w", pady=5)
        
        # Grafana Port (only for bundled)
        self.mon_options_frame = tk.Frame(self.content_frame, bg=self.colors['bg'])
        self.mon_options_frame.pack(fill="x", pady=10)
        
        ttk.Label(self.mon_options_frame, text="Grafana Port:").pack(side="left")
        self.ent_grafana_port = ttk.Entry(self.mon_options_frame, width=10)
        self.ent_grafana_port.insert(0, self.data['grafana_port'])
        self.ent_grafana_port.pack(side="left", padx=10)

    # --- Step 5: Admin Account ---
    def step_license(self):
        ttk.Label(self.content_frame, text="Lizenzschlüssel", style=STYLE_HEADER).pack(pady=(0, 10))
        ttk.Label(self.content_frame,
                  text="Gib deinen YADS-Lizenzschlüssel ein. Er wird in die .env-Datei geschrieben\n"
                       "und beim ersten Start automatisch aktiviert.",
                  wraplength=500, foreground=self.colors['fg_sub']).pack(anchor="w", pady=(0, 10))

        self.ent_license = tk.Text(self.content_frame, height=5,
                                   bg=self.colors['bg_alt'], fg=self.colors['fg'],
                                   insertbackground=self.colors['fg'], font=("monospace", 9))
        self.ent_license.pack(fill="x", pady=5)
        if self.data.get('license_key'):
            self.ent_license.insert("1.0", self.data['license_key'])

        ttk.Label(self.content_frame,
                  text="Ohne gültigen Schlüssel können keine Scans ausgeführt werden.\n"
                       "Der Schritt kann übersprungen werden — Schlüssel später in den Einstellungen eintragen.",
                  wraplength=500, foreground=self.colors['fg_sub'],
                  font=("sans-serif", 9, "italic")).pack(anchor="w", pady=(8, 0))

    def step_admin(self):
        ttk.Label(self.content_frame, text="Admin-Konto einrichten", style=STYLE_HEADER).pack(pady=(0, 6))
        ttk.Label(self.content_frame,
                  text="Dieses Konto wird nach dem Start automatisch über die Setup-API angelegt.",
                  wraplength=500, foreground=self.colors['fg_sub']).pack(anchor="w", pady=(0, 8))

        # Grid must be in its own frame — cannot mix pack+grid in content_frame
        grid = tk.Frame(self.content_frame, bg=self.colors['bg'])
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)

        ttk.Label(grid, text="Benutzername:").grid(row=0, column=0, sticky="w", pady=4)
        self.ent_admin_user = ttk.Entry(grid)
        self.ent_admin_user.insert(0, self.data.get('admin_user', 'admin'))
        self.ent_admin_user.grid(row=0, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Label(grid, text="Passwort:").grid(row=1, column=0, sticky="w", pady=4)
        self.ent_admin_pass = ttk.Entry(grid, show="*")
        self.ent_admin_pass.grid(row=1, column=1, sticky="ew", pady=4, padx=(8, 0))

        ttk.Label(grid, text="Passwort bestätigen:").grid(row=2, column=0, sticky="w", pady=4)
        self.ent_admin_pass2 = ttk.Entry(grid, show="*")
        self.ent_admin_pass2.grid(row=2, column=1, sticky="ew", pady=4, padx=(8, 0))

        # Password strength indicator
        self.lbl_pw_strength = ttk.Label(self.content_frame, text="", wraplength=500, font=("sans-serif", 9))
        self.lbl_pw_strength.pack(anchor="w", pady=(6, 0))

        ttk.Label(self.content_frame,
                  text="BSI TR-02102: mind. 12 Zeichen, Groß-/Kleinbuchstaben, Ziffern und Sonderzeichen.",
                  wraplength=500, foreground=self.colors['fg_sub'],
                  font=("sans-serif", 9, "italic")).pack(anchor="w", pady=(4, 0))

        self.ent_admin_pass.bind("<KeyRelease>", lambda e: self._update_pw_strength())
        self.ent_admin_pass2.bind("<KeyRelease>", lambda e: self._update_pw_strength())

    def _update_pw_strength(self):
        import re
        if not hasattr(self, 'ent_admin_pass'):
            return
        pw = self.ent_admin_pass.get()
        pw2 = self.ent_admin_pass2.get() if hasattr(self, 'ent_admin_pass2') else ""
        issues = []
        if len(pw) < 12:
            issues.append(f"zu kurz ({len(pw)}/12 Zeichen)")
        cats = sum([
            bool(re.search(r'[A-Z]', pw)),
            bool(re.search(r'[a-z]', pw)),
            bool(re.search(r'[0-9]', pw)),
            bool(re.search(r'[^A-Za-z0-9]', pw)),
        ])
        if cats < 3:
            issues.append("mind. 3 Zeichenklassen (Groß, Klein, Ziffern, Sonderzeichen)")
        if pw2 and pw != pw2:
            issues.append("Passwörter stimmen nicht überein")
        if not hasattr(self, 'lbl_pw_strength'):
            return
        if not pw:
            self.lbl_pw_strength.configure(text="", foreground=self.colors['fg_sub'])
        elif issues:
            self.lbl_pw_strength.configure(
                text="✗ " + " · ".join(issues),
                foreground=self.colors['error'])
        else:
            self.lbl_pw_strength.configure(
                text="✓ Passwort erfüllt BSI-Anforderungen" + (" · stimmt überein" if pw2 else ""),
                foreground=self.colors['success'])
    def step_telemetry(self):
        import uuid as _uuid
        ttk.Label(self.content_frame, text="Installationsmeldung", style=STYLE_HEADER).pack(pady=(0, 10))

        info = (
            "Möchten Sie eine anonyme Installationsmeldung an das YADS-Team senden?\n\n"
            "Dies hilft uns, die Anzahl aktiver Installationen und die verwendeten "
            "Versionen im Überblick zu behalten. Es werden keine persönlichen Daten, "
            "keine Domainnamen und keine Scan-Ergebnisse übertragen."
        )
        ttk.Label(self.content_frame, text=info, wraplength=520, justify="left").pack(anchor="w", pady=(0, 12))

        # Generate/reuse instance UUID so the preview is stable
        if not self.data.get('instance_uuid'):
            self.data['instance_uuid'] = str(_uuid.uuid4())

        # Try to extract customer_id from license for preview
        preview_customer_id = ""
        lic_key = self.data.get('license_key', '').strip()
        if lic_key and '.' in lic_key:
            try:
                import base64 as _b64, json as _json
                p_b64 = lic_key.split('.')[0]
                p_b64 += '=' * ((4 - len(p_b64) % 4) % 4)
                preview_customer_id = _json.loads(_b64.urlsafe_b64decode(p_b64)).get('customer_id', '')
            except Exception:
                pass

        # Resolve real version from running YADS API for the preview
        import json as _json2
        preview_version = self.data.get('yads_version', '')
        try:
            v_req = urllib.request.urlopen(
                f"{self._base_url_for_api()}/api/updates/version", timeout=4
            )
            preview_version = _json2.loads(v_req.read()).get("version", preview_version) or preview_version
        except Exception:
            pass
        if not preview_version:
            preview_version = "unbekannt"

        preview = (
            "Folgende Daten würden gesendet:\n"
            f"  • instance_uuid : {self.data['instance_uuid']}\n"
            f"  • version       : {preview_version}\n"
            f"  • install_type  : installer\n"
        )
        if preview_customer_id:
            preview += f"  • customer_id   : {preview_customer_id}\n"
        preview += "  • submitted_at  : <Zeitstempel beim Senden>"
        preview_frame = tk.Frame(self.content_frame, bg=self.colors['bg_alt'],
                                  bd=1, relief="solid")
        preview_frame.pack(fill="x", pady=(0, 14))
        tk.Label(preview_frame, text=preview, bg=self.colors['bg_alt'], fg=self.colors['fg'],
                 font=("Monospace", 9), justify="left", anchor="w",
                 padx=12, pady=10).pack(fill="x")

        if not hasattr(self, 'telemetry_var'):
            self.telemetry_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            self.content_frame,
            text="Ja, ich sende eine anonyme Installationsmeldung an das YADS-Team.",
            variable=self.telemetry_var,
            bg=self.colors['bg'], fg=self.colors['fg'],
            selectcolor=self.colors['bg_alt'],
            activebackground=self.colors['bg'],
            activeforeground=self.colors['fg'],
        ).pack(anchor="w", pady=(0, 4))

        ttk.Label(
            self.content_frame,
            text="Die Meldung ist optional. Sie können diesen Schritt auch überspringen.",
            foreground=self.colors['fg_sub'],
        ).pack(anchor="w")

    def step_summary(self):
        mode = self.install_mode_var.get() if self.is_upgrade else "reinstall"
        if self.is_upgrade and mode == "update":
            ttk.Label(self.content_frame, text="Bereit zum Update", style=STYLE_HEADER).pack(pady=(0, 10))
            ttk.Label(self.content_frame,
                      text="YADS wird auf die neueste Version aktualisiert.\n"
                           "Konfiguration und Daten bleiben unverändert.",
                      wraplength=500, justify="center").pack(pady=10)
            summary_txt = f"Modus: Update (Images aktualisieren)\n"
            summary_txt += f"Backup: {self.backup_var.get()}\n\n"
            summary_txt += "Ablauf:\n"
            summary_txt += "  1. Backup erstellen\n"
            summary_txt += "  2. docker compose pull\n"
            summary_txt += "  3. docker compose up -d --remove-orphans\n"
        else:
            ttk.Label(self.content_frame, text="Bereit zur Installation", style=STYLE_HEADER).pack(pady=(0, 10))
            ttk.Label(self.content_frame, text="Zusammenfassung der Konfiguration:").pack(anchor="w")
            summary_txt = f"Modus: {'Reinstall' if self.is_upgrade else 'Neuinstallation'}\n"
            summary_txt += f"Host: {self.data['host']}\n"
            summary_txt += f"Port: {self.data['api_port']}\n"
            summary_txt += f"SSL: {'Aktiviert' if self.data['use_ssl'] else 'Deaktiviert'}\n"
            summary_txt += f"Auth: {self.data['auth_mode']}\n"
            summary_txt += f"Monitoring: {'Aktiviert' if self.data['mon_choice'] != '1' else 'Deaktiviert'}\n"
            if self.is_upgrade:
                summary_txt += f"Backup: {self.backup_var.get()}\n"
            summary_txt += "\nPasswörter und Tokens werden beim Klick auf Finish generiert und in .env gespeichert."
        
        self.text_area = tk.Text(self.content_frame, height=10, bg=self.colors['bg_alt'], fg=self.colors['fg'])
        self.text_area.insert("1.0", summary_txt)
        self.text_area.configure(state="disabled")
        self.text_area.pack(fill="both", pady=10)
        
        btn_frame = tk.Frame(self.content_frame, bg=self.colors['bg'])
        btn_frame.pack(fill="x")
        
        ttk.Button(btn_frame, text="Save to Disk", command=self.save_to_disk).pack(side="right")

    def save_to_disk(self):
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Configuration Summary"
        )
        if file_path:
            try:
                content = self.text_area.get("1.0", tk.END)
                with open(file_path, "w") as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Configuration saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = YADSInstallerGUI(root)
    root.mainloop()
