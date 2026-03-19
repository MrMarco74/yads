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
    from qfluentwidgets import (FluentWindow, SubtitleLabel, NavigationWidget, 
                                 FluentIcon as FIF, PrimaryPushButton, TransparentPushButton,
                                 LineEdit, CheckBox, RadioButton, BodyLabel, 
                                 InfoBar, InfoBarPosition, AcrylicWindow, 
                                 FramelessWindow, setTheme, Theme, ProgressBar, 
                                 TextEdit, CaptionLabel, ScrollArea)
except ImportError:
    from qfluentwidgets import (FluentWindow, SubtitleLabel, NavigationWidget, 
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
REGISTRY_USER = "yads-installer"
REGISTRY_TOKEN = "glpat-secret-token-installer-read-only"
COMPOSE_FILE = "docker-compose.yml"
NGINX_TEMPLATE = "nginx.conf.template"
JSON_CONTENT = "application/json"

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

    def run_install(self):
        """Main installation sequence — data driven to reduce complexity."""
        steps = [
            (20, "Authentifiziere bei Registry...", self.login_registry),
            (30, "Generiere kryptografische Schlüssel...", self.generate_secrets),
            (40, "Schreibe Umgebungsvariablen...", self.write_env),
            (50, "Downloade Docker Images (Dies kann dauern)...", 
             lambda: self.run_docker(["compose", "pull"])),
            (80, "Starte Container...", 
             lambda: self.run_docker(["compose", "up", "-d"])),
        ]

        try:
            self.progress_signal.emit(10, "Initialisiere...")
            for progress_val, label, func in steps:
                self.progress_signal.emit(progress_val, label)
                func()
            
            self.progress_signal.emit(100, "Fertig!")
            self.finished_signal.emit(True, "YADS wurde erfolgreich installiert und gestartet!")
        except Exception as e:
            self.log_signal.emit(f"FEHLER: {str(e)}", "error")
            self.finished_signal.emit(False, str(e))

    def login_registry(self):
        cmd = ["docker", "login", REGISTRY_URL, "-u", REGISTRY_USER, "-p", REGISTRY_TOKEN]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Registry Login fehlgeschlagen: {res.stderr}")
        self.log_signal.emit("Registry Login erfolgreich.", "info")

    def generate_secrets(self):
        self.secrets = {
            'POSTGRES_PASSWORD': secrets.token_urlsafe(16),
            'REDIS_PASSWORD': secrets.token_urlsafe(16),
            'SECRET_KEY': secrets.token_urlsafe(32),
            'SIGNING_KEY': secrets.token_urlsafe(32),
            'REFRESH_SECRET': secrets.token_urlsafe(32),
        }

    def write_env(self):
        lines = [
            f"YADS_HOST={self.data['host']}",
            f"YADS_PORT={self.data['api_port']}",
            f"YADS_LICENSE={self.data.get('license_key', '')}",
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
            raise RuntimeError(f"Docker Kommando fehlgeschlagen mit Code {process.returncode}")

# --- UI Components ---

class GlassInstaller(AcrylicWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("YADS Setup Wizard")
        self.setWindowIcon(QIcon("logo.png")) # Assume logo.png exists in build
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
            'license_key': ''
        }

        self.setup_ui()
        self.show_step(0)

    def setup_ui(self):
        # Main Layout
        self.main_layout = QHBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # 1. Sidebar (Navigation Placeholder)
        self.sidebar_frame = QFrame(self)
        self.sidebar_frame.setFixedWidth(240)
        self.sidebar_frame.setStyleSheet("background: rgba(0,0,0,60); border-right: 1px solid rgba(255,255,255,10);")
        
        # 2. Content Area
        self.content_stack = QStackedWidget(self)
        self.content_stack.setStyleSheet("background: transparent;")
        
        # Add steps
        self.content_stack.addWidget(self.create_welcome_step())
        self.content_stack.addWidget(self.create_dependency_step())
        self.content_stack.addWidget(self.create_network_step())
        self.content_stack.addWidget(self.create_idp_step())
        self.content_stack.addWidget(self.create_monitoring_step())
        self.content_stack.addWidget(self.create_license_step())
        self.content_stack.addWidget(self.create_admin_step())
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
        
        self.main_layout.addWidget(self.sidebar_frame)
        self.main_layout.addLayout(right_panel)

    def create_welcome_step(self) -> QFrame:
        page = QFrame()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(60, 40, 60, 40)
        layout.setAlignment(Qt.AlignCenter)

        title = SubtitleLabel("Willkommen bei YADS", page)
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
        self.input_admin_user = LineEdit(page)
        self.input_admin_user.setText("admin")
        form.addWidget(BodyLabel("Benutzername:"))
        form.addWidget(self.input_admin_user)
        
        self.input_admin_pass = LineEdit(page)
        self.input_admin_pass.setEchoMode(LineEdit.Password)
        form.addWidget(BodyLabel("Passwort:"))
        form.addWidget(self.input_admin_pass)
        
        layout.addLayout(form)
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
        self.content_stack.setCurrentIndex(index)
        self.btn_back.setEnabled(index > 0)
        
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
                
        elif idx == 3: # IDP
            if self.rb_local.isChecked():
                self.data['auth_mode'] = 'simple'
            elif self.rb_keycloak.isChecked():
                self.data['auth_mode'] = 'keycloak'
            else:
                self.data['auth_mode'] = 'oidc'
            
        elif idx == 4: # Monitoring
            if self.rb_mon_none.isChecked():
                self.data['mon_choice'] = '1'
            elif self.rb_mon_bundled.isChecked():
                self.data['mon_choice'] = '2'
            else:
                self.data['mon_choice'] = '3'
            
        elif idx == 5: # License
            self.data['license_key'] = self.input_license.toPlainText().strip()
            
        elif idx == 6: # Admin
            if not self.input_admin_user.text() or not self.input_admin_pass.text():
                InfoBar.warning("Eingabe fehlt", "Benutzername und Passwort erforderlich.", parent=self)
                return False
            self.data['admin_user'] = self.input_admin_user.text()
            self.data['admin_pass'] = self.input_admin_pass.text()
            
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
