#!/usr/bin/env python3
import sys
import os
import subprocess
import threading
import time
import socket
import json
import webbrowser
import secrets
from pathlib import Path
from datetime import datetime

from PySide6.QtCore import Qt, QSize, Signal, QObject, QThread, Slot, QTimer
from PySide6.QtGui import QIcon, QFont, QColor, QPalette, QBrush, QLinearGradient
from PySide6.QtWidgets import (QApplication, QFrame, QVBoxLayout, QHBoxLayout, 
                             QLabel, QStackedWidget, QSpacerItem, QSizePolicy)

try:
    from qfluentwidgets import (FluentWindow, SubtitleLabel, 
                                 FluentIcon as FIF, PrimaryPushButton, TransparentPushButton,
                                 LineEdit, CheckBox, RadioButton, BodyLabel, 
                                 InfoBar, InfoBarPosition, AcrylicWindow, 
                                 FramelessWindow, setTheme, Theme, ProgressBar, 
                                 TextEdit, CaptionLabel, ScrollArea)
except ImportError:
    from qfluentwidgets import (FluentWindow, SubtitleLabel, 
                                 FluentIcon as FIF, PrimaryPushButton, TransparentPushButton,
                                 LineEdit, CheckBox, RadioButton, BodyLabel, 
                                 InfoBar, InfoBarPosition, setTheme, Theme, ProgressBar, 
                                 TextEdit, CaptionLabel, ScrollArea)
    AcrylicWindow = FluentWindow
    FramelessWindow = FluentWindow
from qfluentwidgets import FluentIcon as FIF

# Import shared utilities from yads-common if available
try:
    from yads_common.gui import detect_system_dark_mode, get_log_stylesheet
except ImportError:
    # Fallback if not installed yet
    def detect_system_dark_mode(): return True
    def get_log_stylesheet(dark=True): 
        # dark parameter is used to determine theme
        return "TextEdit { background: #1e1e1e; border-radius: 8px; }"

# --- Constants & Configuration ---
REGISTRY_URL = "registry.yads-security.com"
REGISTRY_USER = "yads-push"
REGISTRY_TOKEN = "REDACTED"
VERSION = "1.1.2"
COMPOSE_FILE = "docker-compose.yml"
NGINX_TEMPLATE = "nginx.conf.template"
JSON_CONTENT = "application/json"

import re

def validate_bsi_password(password: str) -> (bool, str):
    """
    Validates password based on BSI CS 050 recommendations.
    Returns (is_valid, error_message).
    """
    if len(password) < 12:
        return False, "Passwort muss mindestens 12 Zeichen lang sein (BSI Empfehlung)."
    
    # Check for categories (at least 3 of 4)
    categories = 0
    if re.search(r"[a-z]", password): categories += 1
    if re.search(r"[A-Z]", password): categories += 1
    if re.search(r"[0-9]", password): categories += 1
    if re.search(r"[^a-zA-Z0-9]", password): categories += 1
    
    if categories < 3:
        return False, "Passwort muss Zeichen aus mindestens 3 Kategorien enthalten (Groß, Klein, Zahlen, Sonderzeichen)."
    
    # Basic check against common patterns
    if password.lower() in ["password12345", "yadsadmin2026", "administrator"]:
        return False, "Passwort ist zu einfach oder ein bekanntes Muster."
        
    return True, ""

class Style:
    ACCENT = "#FF8C00"  # Vibrant Orange
    ACCENT_LIGHT = "#FFA500"
    BG_DARK = "#121212"
    GLASS_OPACITY = 180  # 0-255
    BORDER_GLOW = "1px solid rgba(255, 140, 0, 0.3)"

# --- Helper Classes (Ported from tkinter version) ---

class DependencyChecker:
    @staticmethod
    def check_docker():
        try:
            return subprocess.run(["docker", "--version"], capture_output=True).returncode == 0
        except Exception: return False

    @staticmethod
    def check_docker_compose():
        try:
            res = subprocess.run(["docker", "compose", "version"], capture_output=True)
            return res.returncode == 0
        except Exception: return False

    @staticmethod
    def check_docker_daemon():
        try:
            res = subprocess.run(["docker", "info"], capture_output=True)
            if res.returncode == 0: return True, "ok"
            err_msg = res.stderr.decode().lower()
            if "permission denied" in err_msg or "connect" in err_msg:
                return False, "permission_denied"
            return False, "error"
        except Exception: 
            return False, "error"

class NetworkTools:
    @staticmethod
    def resolve(host):
        try:
            ip = socket.gethostbyname(host)
            hostname = socket.getfqdn(host)
            return ip, hostname
        except Exception:
            return None, None

    @staticmethod
    def ping(host):
        try:
            res = subprocess.run(["ping", "-c", "1", "-W", "1", host], capture_output=True)
            return res.returncode == 0, res.stdout.decode()
        except Exception:
            return False, "Ping-Fehler"

class InstallationManager(QObject):
    """Handles the heavy lifting in a separate thread"""
    log_signal = Signal(str, str) # message, level
    progress_signal = Signal(int, str) # percent, text
    finished_signal = Signal(bool, str) # success, msg

    def __init__(self, data):
        super().__init__()
        self.data = data
        self.secrets = {}
        self.project_name = self._get_project_name()
    
    def _get_project_name(self):
        """Discover the current docker compose project name."""
        try:
            res = subprocess.run(["docker", "compose", "project-name"], capture_output=True, text=True)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except:
            pass
        # Fallback to directory name
        return os.path.basename(os.getcwd()).lower().replace("-", "").replace("_", "")

    def run_install(self):
        """Main installation sequence — data driven to reduce complexity."""
        steps = [
            (10, "Stoppe bestehende Dienste (falls vorhanden)...", self.shutdown_existing),
            (20, "Authentifiziere bei Registry...", self.login_registry),
            (30, "Generiere kryptografische Schlüssel...", self.generate_secrets),
            (35, "Bereite Konfigurationsdateien vor...", self.prepare_installation_files),
            (40, "Schreibe Umgebungsvariablen...", self.write_env),
            (50, "Downloade Docker Images (Dies kann dauern)...", 
             lambda: self.run_docker(["compose", "pull"])),
            (80, "Starte Container...", 
             lambda: self.run_docker(["compose", "up", "-d"])),
        ]

        try:
            self.progress_signal.emit(5, "Initialisiere...")
            
            # Optional Backup
            if self.data.get('do_backup', True):
                self.progress_signal.emit(8, "Erstelle Backup...")
                self.create_backup()

            for progress_val, label, func in steps:
                self.progress_signal.emit(progress_val, label)
                func()
            
            # 8. Post-Install Health Check
            self.progress_signal.emit(90, "Warte auf Systemstart (Health Check)...")
            if self.verify_health():
                self.progress_signal.emit(100, "Fertig!")
                self.finished_signal.emit(True, "YADS wurde erfolgreich installiert und ist bereit!")
            else:
                self.log_container_errors()
                self.finished_signal.emit(False, "Das System wurde gestartet, antwortet aber nicht auf den Health Check. Die Fehlerlogs wurden oben ausgegeben.")
        except Exception as e:
            self.log_signal.emit(f"FEHLER: {str(e)}", "error")
            self.finished_signal.emit(False, str(e))

    def shutdown_existing(self):
        """Shutdown existing containers to free up ports."""
        self.log_signal.emit("Suche nach laufenden Diensten...", "info")
        
        # 1. Try compose down first
        if os.path.exists(COMPOSE_FILE):
            self.log_signal.emit("Bestehende Konf gefunden. Stoppe Compose-Stack...", "info")
            if self.data.get('install_mode') == 'reinstall':
                self.run_docker(["compose", "down", "-v", "--remove-orphans"])
            else:
                self.run_docker(["compose", "down", "--remove-orphans"])
        
        # 2. Aggressive fallback: Force kill by names
        self.log_signal.emit(f"Bereinige restliche Container für Projekt '{self.project_name}'...", "info")
        # In Docker Compose, the default container name is {project}-{service}-1
        # but our customer.yml has hardcoded container_names (yads-api, etc.)
        # so we try both for maximum safety.
        services = ["proxy", "api", "worker", "db", "redis"]
        for s in services:
            # Try hardcoded names first (as defined in our yaml)
            subprocess.run(["docker", "rm", "-f", f"yads-{s}"], capture_output=True)
            # Then try project-prefixed names
            subprocess.run(["docker", "rm", "-f", f"{self.project_name}-{s}-1"], capture_output=True)
        
        # 3. Final check: port cleanup (optional but good)
        self.log_signal.emit("Dienste gestoppt.", "info")

    def create_backup(self):
        """Simple data backup for volumes."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_root = os.path.expanduser("~/yads_backups")
        os.makedirs(backup_root, exist_ok=True)
        backup_path = os.path.join(backup_root, f"yads_backup_{ts}")
        
        self.log_signal.emit(f"Sichere Volumes nach {backup_path}...", "info")
        # Discover actual volumes for this project
        volumes = [f"{self.project_name}_postgres_data", f"{self.project_name}_redis_data"]
        os.makedirs(backup_path, exist_ok=True)
        
        # We use docker run to copy data out of volumes
        for vol in volumes:
            cmd = ["docker", "run", "--rm", "-v", f"{vol}:/data", "-v", f"{backup_path}:/backup", "busybox", "sh", "-c", f"cp -a /data /backup/{vol}"]
            res = subprocess.run(cmd, capture_output=True)
            if res.returncode == 0:
                self.log_signal.emit(f"Volume {vol} gesichert.", "info")

    def login_registry(self):
        # Use --password-stdin to avoid insecurity warning and be more robust
        login_process = subprocess.Popen(
            ["docker", "login", REGISTRY_URL, "-u", REGISTRY_USER, "--password-stdin"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = login_process.communicate(input=REGISTRY_TOKEN)
        
        if login_process.returncode != 0:
            raise RuntimeError(f"Registry Login fehlgeschlagen: {stderr.strip()}")
        self.log_signal.emit("Registry Login erfolgreich.", "info")

    def generate_secrets(self):
        """Generates new secrets or reuses existing ones if upgrading."""
        existing = {}
        is_upgrade = self.data.get('install_mode') == 'upgrade'
        env_path = ".env"
        
        if is_upgrade:
            if not os.path.exists(env_path):
                self.log_signal.emit(f"FEHLER: .env nicht gefunden! Für ein Update muss der Installer im Verzeichnis der bestehenden Installation ausgeführt werden.", "error")
                raise RuntimeError("Konfigurationsdatei (.env) fehlt für Update.")
            
            self.log_signal.emit("Lese bestehende Geheimnisse aus .env...", "info")
            try:
                with open(env_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if "=" in line and not line.startswith("#"):
                            # Remove 'export ' if present
                            if line.startswith("export "):
                                line = line[7:].strip()
                                
                            parts = line.split("=", 1)
                            if len(parts) == 2:
                                k = parts[0].strip()
                                v = parts[1].strip().strip('"').strip("'")
                                
                                # Canonicalize keys
                                if k in ['POSTGRES_PASSWORD', 'DB_PASSWORD', 'DATABASE_PASSWORD']:
                                    existing['POSTGRES_PASSWORD'] = v
                                elif k in ['REDIS_PASSWORD', 'REDIS_PASS']:
                                    existing['REDIS_PASSWORD'] = v
                                elif k in ['SECRET_KEY']:
                                    existing['SECRET_KEY'] = v
                                elif k in ['SIGNING_KEY']:
                                    existing['SIGNING_KEY'] = v
                                elif k in ['REFRESH_SECRET']:
                                    existing['REFRESH_SECRET'] = v
            except Exception as e:
                self.log_signal.emit(f"Warnung beim Lesen der .env: {e}", "warning")

        # Fallback for missing critical keys during upgrade
        if is_upgrade and 'POSTGRES_PASSWORD' not in existing:
            self.log_signal.emit("WARNUNG: POSTGRES_PASSWORD wurde in der .env nicht gefunden!", "warning")

        # Prioritize manual user entries if provided
        db_pass = self.data.get('db_pass', '').strip()
        if db_pass:
            existing['POSTGRES_PASSWORD'] = db_pass

        self.secrets = {
            'POSTGRES_PASSWORD': existing.get('POSTGRES_PASSWORD', secrets.token_urlsafe(16)),
            'REDIS_PASSWORD': existing.get('REDIS_PASSWORD', secrets.token_urlsafe(16)),
            'SECRET_KEY': existing.get('SECRET_KEY', secrets.token_urlsafe(32)),
            'SIGNING_KEY': existing.get('SIGNING_KEY', secrets.token_urlsafe(32)),
            'REFRESH_SECRET': existing.get('REFRESH_SECRET', secrets.token_urlsafe(32)),
        }

    def prepare_installation_files(self):
        """Copy templates from temp resources to current dir."""
        resource_dir = os.environ.get("YADS_INSTALLER_RESOURCES")
        if not resource_dir or not os.path.exists(resource_dir):
            # Fallback for direct execution without pyz extraction
            resource_dir = os.path.dirname(__file__)
        
        # 1. Compose File
        src_compose = os.path.join(resource_dir, "docker-compose.customer.yml")
        if os.path.exists(src_compose):
            with open(src_compose, "r") as f:
                content = f.read()
            
            # Make DB user dynamic in connection string and DB service
            db_user = self.data.get('db_user', 'yads')
            content = content.replace("postgresql://yads:", f"postgresql://${{POSTGRES_USER:-{db_user}}}:")
            content = content.replace("POSTGRES_USER=yads", f"POSTGRES_USER=${{POSTGRES_USER:-{db_user}}}")
            
            with open(COMPOSE_FILE, "w") as f:
                f.write(content)
            self.log_signal.emit(f"{COMPOSE_FILE} erstellt.", "info")
        else:
            raise RuntimeError(f"Datei nicht gefunden: {src_compose}")
            
        # 2. Nginx Template -> nginx/nginx.conf
        src_nginx = os.path.join(resource_dir, NGINX_TEMPLATE)
        if os.path.exists(src_nginx):
            dest_dir = os.path.join(os.getcwd(), "nginx")
            os.makedirs(dest_dir, exist_ok=True)
            with open(src_nginx, "r") as f:
                content = f.read()
            
            # Simple template replacement
            content = content.replace("{{PORT}}", str(self.data.get('api_port', 8085)))
            content = content.replace("{{SERVER_NAME}}", self.data.get('host', 'localhost'))
            content = content.replace("{{CLIENT_MAX_BODY_SIZE}}", "100M")
            content = content.replace("{{PROXY_READ_TIMEOUT}}", "300s")
            
            with open(os.path.join(dest_dir, "nginx.conf"), "w") as f:
                f.write(content)
            self.log_signal.emit("nginx/nginx.conf erstellt.", "info")

    def write_env(self):
        lines = [
            f"COMPOSE_PROJECT_NAME={self.project_name}",
            f"YADS_HOST={self.data['host']}",
            f"API_PORT=80",
            f"YADS_DIRECT_PORT={self.data['api_port']}",
            f"YADS_LICENSE={self.data.get('license_key', '')}",
            f"POSTGRES_USER={self.data.get('db_user', 'yads')}",
            f"YADS_ADMIN_USER={self.data.get('admin_user', 'admin')}",
            f"YADS_ADMIN_PASS={self.data.get('admin_pass', 'admin')}",
            f"SETUP_COMPLETE=true",
        ]
        for k, v in self.secrets.items():
            lines.append(f"{k}={v}")
        
        with open(".env", "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log_signal.emit(".env-Datei geschrieben.", "info")

    def run_docker(self, args):
        cmd = ["docker"] + args
        self.log_signal.emit(f"Running: {' '.join(cmd)}", "info")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            self.log_signal.emit(line.strip(), "info")
        process.wait()
        if process.returncode != 0:
            self.log_container_errors()
            raise RuntimeError(f"Docker Kommando fehlgeschlagen mit Code {process.returncode}")

    def log_container_errors(self):
        """Fetch and display logs from yads-api if startup fails."""
        self.log_signal.emit("\n--- ERROR LOGS (yads-api) ---", "error")
        try:
            # Try to get logs from yads-api
            res = subprocess.run(["docker", "compose", "logs", "--tail=50", "yads-api"], 
                                 capture_output=True, text=True)
            if res.stdout:
                for line in res.stdout.splitlines():
                    self.log_signal.emit(line, "error")
            else:
                self.log_signal.emit("Keine Logs in yads-api gefunden.", "warning")
        except Exception as e:
            self.log_signal.emit(f"Fehler beim Abrufen der Logs: {e}", "warning")
        self.log_signal.emit("-----------------------------\n", "error")

    def verify_health(self, timeout_sec=60):
        """Wait for the API to respond with status: ok."""
        port = self.data.get('api_port', 8085)
        host = self.data.get('host', 'localhost')
        url = f"http://{host}:{port}/health"
        
        self.log_signal.emit(f"Prüfe System-Gesundheit unter {url}...", "info")
        
        start_time = time.time()
        while time.time() - start_time < timeout_sec:
            try:
                # Use curl as a simple available client
                res = subprocess.run(["curl", "-s", "-k", url], capture_output=True, text=True)
                if res.returncode == 0 and '"status":"ok"' in res.stdout:
                    self.log_signal.emit("System ist gesund und erreichbar.", "info")
                    return True
            except Exception:
                pass
            time.sleep(2)
        return False

# --- UI Components ---

class GlassInstaller(AcrylicWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"YADS Setup Wizard v{VERSION}")
        self.setWindowIcon(QIcon()) # Remove icon
        # Hide the title bar icon if it exists (for AcrylicWindow/FluentWindow)
        if hasattr(self, 'titleBar'): 
            self.titleBar.iconLabel.hide()
        
        self.resize(1000, 700)
        
        # Configure Glass effects
        self.windowEffect.setMicaEffect(self.winId(), isDarkMode=True)
        # For Linux/Mac, we use transparency if mica isn't available
        if sys.platform != "win32":
            self.setWindowOpacity(0.95)
            self.setStyleSheet(f"background-color: rgba(18, 18, 18, {Style.GLASS_OPACITY});")

        self.data = {
            'api_port': '8085',
            'host': 'localhost',
            'use_ssl': False,
            'use_nginx': True,
            'auth_mode': 'simple',
            'mon_choice': '1',
            'license_key': '',
            'install_mode': 'upgrade'
        }

        self.setup_ui()
        self.show_step(0)

    def setup_ui(self):
        # AcrylicWindow/FluentWindow already has hBoxLayout and stackedWidget
        # We try to use them if they exist, otherwise fallback.
        if hasattr(self, 'hBoxLayout') and hasattr(self, 'stackedWidget'):
            self.main_layout = self.hBoxLayout
            self.content_stack = self.stackedWidget
        else:
            self.main_layout = QHBoxLayout(self)
            self.content_stack = QStackedWidget(self)
        
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # 1. Sidebar (Custom Robust Design)
        self.sidebar_frame = QFrame(self)
        self.sidebar_frame.setFixedWidth(240)
        self.sidebar_frame.setStyleSheet("background: rgba(0,0,0,80); border-right: 1px solid rgba(255,255,255,10);")
        
        self.sidebar_layout = QVBoxLayout(self.sidebar_frame)
        self.sidebar_layout.setContentsMargins(10, 40, 10, 10)
        self.sidebar_layout.setSpacing(5)

        self.nav_buttons = []
        steps = [
            (FIF.HOME, "Willkommen"),
            (FIF.DEVELOPER_TOOLS, "System-Check"),
            (FIF.GLOBE, "Netzwerk"),
            (FIF.TILES, "Datenbank"),
            (FIF.PEOPLE, "Identität"),
            (FIF.PIE_SINGLE, "Monitoring"),
            (FIF.CERTIFICATE, "Lizenz"),
            (FIF.SETTING, "Admin"),
            (FIF.TILES, "Modus"),
            (FIF.DOWNLOAD, "Installation")
        ]

        from PySide6.QtWidgets import QPushButton
        for i, (icon, text) in enumerate(steps):
            btn = QPushButton(self.sidebar_frame)
            btn.setFixedHeight(50)
            btn.setFlat(True)
            btn.setCursor(Qt.PointingHandCursor)
            
            # Custom layout for icon + text
            btn_layout = QHBoxLayout(btn)
            btn_layout.setContentsMargins(15, 0, 10, 0)
            btn_layout.setSpacing(12)
            
            icon_label = QLabel()
            icon_label.setPixmap(icon.icon().pixmap(QSize(20, 20)))
            icon_label.setStyleSheet("background: transparent;")
            
            text_label = QLabel(text)
            text_label.setStyleSheet("background: transparent; color: white; font-size: 13px;")
            
            btn_layout.addWidget(icon_label)
            btn_layout.addWidget(text_label)
            btn_layout.addStretch(1)
            
            # Use a lambda to pass the index
            btn.clicked.connect(lambda checked=False, idx=i: self.show_step(idx))
            self.sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)
        
        self.sidebar_layout.addStretch(1)
        
        # 2. Content Area - only if we had to create it
        if not hasattr(self, 'stackedWidget'):
            self.content_stack.setStyleSheet("background: transparent;")
        
        # Add steps
        self.content_stack.addWidget(self.create_welcome_step())
        self.content_stack.addWidget(self.create_dependency_step())
        self.content_stack.addWidget(self.create_network_step())
        self.content_stack.addWidget(self.create_database_step())
        self.content_stack.addWidget(self.create_idp_step())
        self.content_stack.addWidget(self.create_monitoring_step())
        self.content_stack.addWidget(self.create_license_step())
        self.content_stack.addWidget(self.create_admin_step())
        self.content_stack.addWidget(self.create_mode_step())
        self.content_stack.addWidget(self.create_install_step())

        # 3. Bottom Navigation Bar
        self.bottom_bar = QFrame(self)
        self.bottom_bar.setFixedHeight(80)
        self.bottom_bar.setStyleSheet(f"border-top: {Style.BORDER_GLOW}; background: rgba(0,0,0,40);")
        
        bottom_layout = QHBoxLayout(self.bottom_bar)
        bottom_layout.setContentsMargins(30, 0, 30, 0)
        
        self.btn_back = TransparentPushButton("Zurück", self)
        self.btn_next = PrimaryPushButton("Weiter", self)
        self.btn_next.setFixedWidth(120)
        self.btn_next.clicked.connect(self.next_step)
        self.btn_back.clicked.connect(self.prev_step)

        bottom_layout.addWidget(self.btn_back)
        bottom_layout.addStretch(1)
        bottom_layout.addWidget(self.btn_next)

        # Assemble
        right_panel = QVBoxLayout()
        right_panel.setContentsMargins(0, 40, 0, 0) # Leave space for title bar
        right_panel.addWidget(self.content_stack)
        right_panel.addWidget(self.bottom_bar)
        
        # If we are using the internal layout, sidebar and right_panel are added differently
        if hasattr(self, 'hBoxLayout'):
            self.main_layout.insertWidget(0, self.sidebar_frame)
            self.main_layout.addLayout(right_panel)
        else:
            self.main_layout.addWidget(self.sidebar_frame)
            self.main_layout.addLayout(right_panel)

    def create_welcome_step(self) -> QFrame:
        page = QFrame()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(60, 40, 60, 40)
        layout.setAlignment(Qt.AlignCenter)

        title = SubtitleLabel("YADS Setup Wizard", page)
        title.setStyleSheet("font-size: 32px; font-weight: bold; color: white;")
        layout.addWidget(title)

        desc = BodyLabel("Dieser Assistent führt Sie durch die Installation und Konfiguration von YADS (Yet Another Domain Scanner).", page)
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet("color: #d4d4d4; margin-top: 20px;")
        layout.addWidget(desc)

        layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        disclaimer = CaptionLabel("⚠️ HINWEIS: Dieses Projekt ist das Ergebnis von 'Vibe-Coding' (KI-gestützt). Nutzung auf eigene Gefahr.", page)
        disclaimer.setStyleSheet("color: rgba(255,140,0,0.7); font-style: italic;")
        layout.addWidget(disclaimer)
        
        return page

    def create_dependency_step(self) -> QFrame:
        page = QFrame()
        self.dep_layout = QVBoxLayout(page)
        self.dep_layout.setContentsMargins(60, 40, 60, 40)
        
        self.dep_layout.addWidget(SubtitleLabel("Dependency Check", page))
        self.dep_layout.addWidget(BodyLabel("Wir prüfen nun, ob Ihr System alle Voraussetzungen erfüllt.", page))
        
        self.dep_list_widget = QFrame(page)
        self.dep_list_layout = QVBoxLayout(self.dep_list_widget)
        self.dep_list_layout.setSpacing(10)
        self.dep_list_layout.setContentsMargins(0, 20, 0, 20)
        self.dep_layout.addWidget(self.dep_list_widget)
        
        self.dep_layout.addStretch(1)
        return page

    def create_network_step(self) -> QFrame:
        page = QFrame()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(60, 40, 60, 40)
        layout.addWidget(SubtitleLabel("Netzwerk & Host", page))
        
        form = QVBoxLayout()
        form.setSpacing(15)
        
        self.input_host = LineEdit(page)
        self.input_host.setText(self.data.get('host', 'localhost'))
        form.addWidget(BodyLabel("Domain / IP (für externe Erreichbarkeit):"))
        form.addWidget(self.input_host)
        
        self.input_port = LineEdit(page)
        self.input_port.setText(self.data.get('api_port', '8085'))
        form.addWidget(BodyLabel("API Port:"))
        form.addWidget(self.input_port)
        
        layout.addLayout(form)
        layout.addStretch(1)
        return page

    def refresh_dependencies(self):
        # Clear previous items
        for i in reversed(range(self.dep_list_layout.count())): 
            self.dep_list_layout.itemAt(i).widget().setParent(None)
            
        checks = [
            ("Docker CLI", DependencyChecker.check_docker()),
            ("Docker Compose", DependencyChecker.check_docker_compose()),
        ]
        daemon_ok, daemon_status = DependencyChecker.check_docker_daemon()
        checks.append(("Docker Daemon", daemon_ok))
        
        for name, ok in checks:
            color = "#34d399" if ok else "#f87171"
            icon = "✓" if ok else "✗"
            lbl = BodyLabel(f"{icon} {name}", self.dep_list_widget)
            lbl.setStyleSheet(f"color: {color}; font-weight: bold;")
            self.dep_list_layout.addWidget(lbl)
            
        if not daemon_ok and daemon_status == "permission_denied":
            hint = CaptionLabel("HINWEIS: Docker-Berechtigung fehlt. Bitte füge deinen User zur 'docker'-Gruppe hinzu oder starte den Installer mit sudo.")
            hint.setStyleSheet("color: #fbbf24; font-style: italic;")
            hint.setWordWrap(True)
            self.dep_list_layout.addWidget(hint)

    def create_database_step(self) -> QFrame:
        page = QFrame()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(60, 40, 60, 40)
        layout.addWidget(SubtitleLabel("Datenbank-Konfiguration", page))
        layout.addWidget(BodyLabel("Konfigurieren Sie die Zugangsdaten für die interne PostreSQL Datenbank.", page))
        
        form = QVBoxLayout()
        form.setSpacing(15)
        
        self.input_db_user = LineEdit(page)
        self.input_db_user.setText("yads")
        form.addWidget(BodyLabel("Datenbank-Benutzer:"))
        form.addWidget(self.input_db_user)
        
        self.input_db_pass = LineEdit(page)
        self.input_db_pass.setEchoMode(LineEdit.Password)
        self.input_db_pass.setPlaceholderText("Leer lassen für Zufallsgenerierung")
        form.addWidget(BodyLabel("Datenbank-Passwort:"))
        form.addWidget(self.input_db_pass)
        
        layout.addLayout(form)
        layout.addStretch(1)
        return page

    def create_idp_step(self) -> QFrame:
        page = QFrame()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(60, 40, 60, 40)
        layout.addWidget(SubtitleLabel("Identity Provider (Auth)", page))
        
        self.idp_group = QFrame(page)
        idp_layout = QVBoxLayout(self.idp_group)
        
        self.rb_local = RadioButton("Lokale Konten (einfach)", self.idp_group)
        self.rb_keycloak = RadioButton("Bundled Keycloak (kompletter Stack)", self.idp_group)
        self.rb_oidc = RadioButton("Externer OIDC Provider (Keycloak, Auth0, etc.)", self.idp_group)
        
        self.rb_local.setChecked(True)
        idp_layout.addWidget(self.rb_local)
        idp_layout.addWidget(self.rb_keycloak)
        idp_layout.addWidget(self.rb_oidc)
        
        layout.addWidget(self.idp_group)
        layout.addStretch(1)
        return page

    def create_monitoring_step(self) -> QFrame:
        page = QFrame()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(60, 40, 60, 40)
        layout.addWidget(SubtitleLabel("Observability & Monitoring", page))
        
        self.mon_group = QFrame(page)
        mon_layout = QVBoxLayout(self.mon_group)
        
        self.rb_mon_none = RadioButton("Kein Monitoring-Stack", self.mon_group)
        self.rb_mon_bundled = RadioButton("Bundled Stack (Prometheus + Grafana + Loki)", self.mon_group)
        self.rb_mon_external = RadioButton("Extern (Eigener Prometheus)", self.mon_group)
        
        self.rb_mon_none.setChecked(True)
        mon_layout.addWidget(self.rb_mon_none)
        mon_layout.addWidget(self.rb_mon_bundled)
        mon_layout.addWidget(self.rb_mon_external)
        
        layout.addWidget(self.mon_group)
        layout.addStretch(1)
        return page

    def create_license_step(self) -> QFrame:
        page = QFrame()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(60, 40, 60, 40)
        layout.addWidget(SubtitleLabel("Lizenzschlüssel", page))
        
        self.input_license = TextEdit(page)
        self.input_license.setPlaceholderText("Dein YADS-Lizenzschlüssel hier einfügen...")
        self.input_license.setFixedHeight(150)
        layout.addWidget(self.input_license)
        
        layout.addStretch(1)
        return page

    def create_admin_step(self) -> QFrame:
        page = QFrame()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(60, 40, 60, 40)
        layout.addWidget(SubtitleLabel("Admin-Konto einrichten", page))
        
        form = QVBoxLayout()
        form.setSpacing(10)

        self.input_admin_user = LineEdit(page)
        self.input_admin_user.setText("admin")
        form.addWidget(BodyLabel("Benutzername:"))
        form.addWidget(self.input_admin_user)
        
        self.input_admin_pass = LineEdit(page)
        self.input_admin_pass.setEchoMode(LineEdit.Password)
        self.input_admin_pass.setPlaceholderText("Passwort (BSI: min 12 Zeichen, Mix)")
        self.input_admin_pass.textChanged.connect(self._update_password_status)
        form.addWidget(BodyLabel("Passwort:"))
        form.addWidget(self.input_admin_pass)

        self.input_admin_pass_confirm = LineEdit(page)
        self.input_admin_pass_confirm.setEchoMode(LineEdit.Password)
        self.input_admin_pass_confirm.setPlaceholderText("Passwort wiederholen")
        self.input_admin_pass_confirm.textChanged.connect(self._update_password_status)
        form.addWidget(BodyLabel("Passwort bestätigen:"))
        form.addWidget(self.input_admin_pass_confirm)

        self.password_status_label = CaptionLabel("", page)
        self.password_status_label.setWordWrap(True)
        form.addWidget(self.password_status_label)
        
        layout.addLayout(form)
        layout.addStretch(1)
        return page

    def _update_password_status(self):
        """Real-time BSI and match feedback"""
        pw = self.input_admin_pass.text()
        conf = self.input_admin_pass_confirm.text()
        
        if not pw:
            self.password_status_label.setText("")
            return

        is_valid, err = validate_bsi_password(pw)
        if not is_valid:
            self.password_status_label.setText(f"❌ {err}")
            self.password_status_label.setStyleSheet("color: #f87171;")
        elif pw != conf:
            self.password_status_label.setText("⚠️ Passwörter stimmen nicht überein.")
            self.password_status_label.setStyleSheet("color: #fbbf24;")
        else:
            self.password_status_label.setText("✅ Passwort erfüllt BSI Vorgaben und ist identisch.")
            self.password_status_label.setStyleSheet("color: #34d399;")

    def create_mode_step(self) -> QFrame:
        page = QFrame()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(60, 40, 60, 40)
        layout.addWidget(SubtitleLabel("Installations-Modus", page))
        
        self.mode_group = QFrame(page)
        mode_layout = QVBoxLayout(self.mode_group)
        mode_layout.setSpacing(20)
        
        self.rb_upgrade = RadioButton("Upgrade (Bestehendes Setup aktualisieren, Daten bleiben erhalten)", self.mode_group)
        self.rb_reinstall = RadioButton("Neuinstallation (Kompletter Reset, Volumes werden gelöscht)", self.mode_group)
        
        self.rb_upgrade.setChecked(True)
        mode_layout.addWidget(self.rb_upgrade)
        mode_layout.addWidget(self.rb_reinstall)
        
        layout.addWidget(self.mode_group)
        
        # Backup Option
        self.cb_backup = CheckBox("Backup vor der Durchführung erstellen (empfohlen)", page)
        self.cb_backup.setChecked(True)
        layout.addWidget(self.cb_backup)
        
        layout.addStretch(1)
        return page

    def create_install_step(self) -> QFrame:
        page = QFrame()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(60, 40, 60, 40)
        layout.addWidget(SubtitleLabel("Bereit zur Installation", page))
        
        self.progress_bar = ProgressBar(page)
        self.progress_bar.setValue(0)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)
        
        self.log_view = TextEdit(page)
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background: #000; color: #0f0; font-family: monospace;")
        layout.addWidget(self.log_view)
        
        return page

    def show_step(self, index: int):
        # Validate current step before leaving
        curr = self.content_stack.currentIndex()
        if not self._validate_and_save_data(curr):
            return
            
        self.content_stack.setCurrentIndex(index)
        self.btn_back.setEnabled(index > 0)
        
        # Highlight current button
        for i, btn in enumerate(self.nav_buttons):
            # Find labels inside the button
            labels = btn.findChildren(QLabel)
            if i == index:
                btn.setStyleSheet(f"background: rgba(255,255,255,25); border-left: 4px solid {Style.ACCENT}; border-top: none; border-right: none; border-bottom: none;")
                for lbl in labels:
                    if lbl.text(): # text label
                        lbl.setStyleSheet("color: white; font-weight: bold; background: transparent; border: none;")
                    else: # icon label
                        lbl.setStyleSheet("background: transparent; border: none;")
            else:
                btn.setStyleSheet("background: transparent; border: none;")
                for lbl in labels:
                    if lbl.text(): # text label
                        lbl.setStyleSheet("color: rgba(255,255,255,160); font-weight: normal; background: transparent; border: none;")
                    else: # icon label
                        lbl.setStyleSheet("background: transparent; border: none;")

        # Trigger page-specific logic
        if index == 1: # Dependencies
            self.refresh_dependencies()
            
        if index == self.content_stack.count() - 1:
            self.btn_next.setText("Installieren")
        else:
            self.btn_next.setText("Weiter")

    def next_step(self):
        idx = self.content_stack.currentIndex()
        if not self._validate_and_save_data(idx):
            return

        if idx < self.content_stack.count() - 1:
            self.show_step(idx + 1)
        else:
            self.finish_setup()

    def _validate_and_save_data(self, idx: int) -> bool:
        if idx == 2: # Network
            self.data['host'] = self.input_host.text()
            self.data['api_port'] = self.input_port.text()
            if not self.data['host'] or not self.data['api_port']:
                InfoBar.warning("Eingabe fehlt", "Bitte Host und Port angeben.", parent=self)
                return False
        
        elif idx == 3: # Database
            self.data['db_user'] = self.input_db_user.text()
            self.data['db_pass'] = self.input_db_pass.text()
            if not self.data['db_user']:
                InfoBar.warning("Eingabe fehlt", "Datenbank-Benutzer ist erforderlich.", parent=self)
                return False
                
        elif idx == 4: # IDP
            if self.rb_local.isChecked():
                self.data['auth_mode'] = 'simple'
            elif self.rb_keycloak.isChecked():
                self.data['auth_mode'] = 'keycloak'
            else:
                self.data['auth_mode'] = 'oidc'
            
        elif idx == 5: # Monitoring
            if self.rb_mon_none.isChecked():
                self.data['mon_choice'] = '1'
            elif self.rb_mon_bundled.isChecked():
                self.data['mon_choice'] = '2'
            else:
                self.data['mon_choice'] = '3'
            
        elif idx == 6: # License
            self.data['license_key'] = self.input_license.toPlainText().strip()
            
        elif idx == 7: # Admin
            if not self.input_admin_user.text() or not self.input_admin_pass.text():
                InfoBar.warning("Eingabe fehlt", "Benutzername und Passwort erforderlich.", parent=self)
                return False
            
            # BSI Validation
            is_valid, err_msg = validate_bsi_password(self.input_admin_pass.text())
            if not is_valid:
                InfoBar.warning("Passwort-Sicherheit (BSI)", err_msg, duration=5000, parent=self)
                return False
            
            if self.input_admin_pass.text() != self.input_admin_pass_confirm.text():
                InfoBar.warning("Passwort-Fehler", "Passwörter stimmen nicht überein.", duration=5000, parent=self)
                return False

            self.data['admin_user'] = self.input_admin_user.text()
            self.data['admin_pass'] = self.input_admin_pass.text()
            
        elif idx == 8: # Mode
            self.data['install_mode'] = 'upgrade' if self.rb_upgrade.isChecked() else 'reinstall'
            self.data['do_backup'] = self.cb_backup.isChecked()
            
        return True

    def prev_step(self):
        idx = self.content_stack.currentIndex()
        if idx > 0:
            self.show_step(idx - 1)

    def finish_setup(self):
        self.btn_next.setEnabled(False)
        self.btn_back.setEnabled(False)
        self.progress_bar.show()
        
        # Start installation thread
        self.worker = InstallationManager(self.data)
        self.thread = QThread()
        self.worker.moveToThread(self.thread)
        
        self.worker.log_signal.connect(self.add_log)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.finished_signal.connect(self.on_finished)
        self.thread.started.connect(self.worker.run_install)
        
        self.thread.start()

    @Slot(str, str)
    def add_log(self, msg, level):
        color = "#0f0" if level == "info" else "#f00"
        self.log_view.append(f"<span style='color:{color}'>[{datetime.now().strftime('%H:%M:%S')}] {msg}</span>")

    @Slot(int, str)
    def update_progress(self, val, text):
        self.progress_bar.setValue(val)
        self.add_log(text, "info")

    @Slot(bool, str)
    def on_finished(self, success, msg):
        self.thread.quit()
        if success:
            InfoBar.success("Erfolg", msg, duration=5000, position=InfoBarPosition.TOP, parent=self)
            self.btn_next.setText("Beenden")
            self.btn_next.setEnabled(True)
            self.btn_next.clicked.disconnect()
            self.btn_next.clicked.connect(self.close)
        else:
            InfoBar.error("Fehler", msg, duration=-1, position=InfoBarPosition.TOP, parent=self)
            self.btn_back.setEnabled(True)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    setTheme(Theme.DARK)
    window = GlassInstaller()
    window.show()
    sys.exit(app.exec())
