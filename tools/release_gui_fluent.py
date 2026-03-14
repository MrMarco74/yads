#!/usr/bin/env python3
"""
YADS Release Manager - Modern Fluent UI
Built with PySide6 + QFluentWidgets
"""
import sys
import os
import re
import threading
import queue
import subprocess
import traceback
from pathlib import Path
from typing import Optional

# Add the tools directory to path
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

# Global crash log — catches Python exceptions AND C/Qt segfaults
import faulthandler
_CRASH_LOG = Path("/tmp/release_manager_crash.log")
_crash_log_fh = open(_CRASH_LOG, "w")
faulthandler.enable(file=_crash_log_fh)

def _excepthook(exc_type, exc_value, exc_tb):
    msg = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    _CRASH_LOG.write_text(msg)
    sys.__excepthook__(exc_type, exc_value, exc_tb)

sys.excepthook = _excepthook

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHF]|\r')

from PySide6.QtCore import Qt, Signal, QObject, QThread, QTimer, QSize, Slot
from PySide6.QtGui import QIcon, QFont, QColor
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QFrame, QFileDialog, QSizePolicy, QSpacerItem
)

from qfluentwidgets import (
    FluentIcon as FIF,
    NavigationInterface, NavigationItemPosition, NavigationWidget,
    MessageBox, InfoBar, InfoBarPosition,
    CardWidget, HeaderCardWidget, PrimaryPushButton, PushButton,
    TransparentPushButton, ToolButton,
    LineEdit, PasswordLineEdit, ComboBox, CheckBox,
    TextEdit, BodyLabel, StrongBodyLabel, SubtitleLabel, TitleLabel,
    setTheme, Theme, setThemeColor, isDarkTheme,
    ScrollArea, SmoothScrollArea,
    ProgressBar, IndeterminateProgressBar,
    FluentWindow, SplashScreen,
    SwitchButton, NavigationTreeWidget
)

def detect_system_dark_mode() -> bool:
    """Detect if system is using dark mode"""
    try:
        import darkdetect
        return darkdetect.isDark()
    except:
        pass

    # Fallback: check GTK settings on Linux
    try:
        import subprocess
        result = subprocess.run(
            ['gsettings', 'get', 'org.gnome.desktop.interface', 'color-scheme'],
            capture_output=True, text=True, timeout=2
        )
        if 'dark' in result.stdout.lower():
            return True
    except:
        pass

    # Fallback: check GTK theme name
    try:
        import subprocess
        result = subprocess.run(
            ['gsettings', 'get', 'org.gnome.desktop.interface', 'gtk-theme'],
            capture_output=True, text=True, timeout=2
        )
        if 'dark' in result.stdout.lower():
            return True
    except:
        pass

    return False


def get_log_stylesheet(dark: bool = None) -> str:
    """Get stylesheet for log view based on theme"""
    if dark is None:
        dark = isDarkTheme()

    if dark:
        return """
            TextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                border-radius: 8px;
                padding: 12px;
            }
        """
    else:
        return """
            TextEdit {
                background-color: #f5f5f5;
                color: #1e1e1e;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                border-radius: 8px;
                padding: 12px;
                border: 1px solid #e0e0e0;
            }
        """
from qfluentwidgets.components.material import AcrylicLineEdit


def _insert_log_line(log_view, message: str, level: str = "info"):
    """Thread-safe HTML log insert with escaping and document size limit."""
    import html as _html
    from datetime import datetime
    dark = isDarkTheme()
    if dark:
        colors = {"info": "#d4d4d4", "success": "#4ec9b0", "warning": "#dcdcaa", "error": "#f14c4c"}
        ts_color = "#6a9955"
    else:
        colors = {"info": "#1e1e1e", "success": "#107c10", "warning": "#ca5010", "error": "#d13438"}
        ts_color = "#107c10"
    color = colors.get(level, colors["info"])
    timestamp = datetime.now().strftime("%H:%M:%S")
    safe_msg = _html.escape(str(message))
    line = f'<span style="color:{ts_color};">[{timestamp}]</span> <span style="color:{color};">{safe_msg}</span><br>'
    # Trim oldest 200 lines when document exceeds 2000 blocks to prevent OOM
    doc = log_view.document()
    if doc.blockCount() > 2000:
        cur = log_view.textCursor()
        cur.movePosition(cur.MoveOperation.Start)
        cur.movePosition(cur.MoveOperation.Down, cur.MoveMode.KeepAnchor, 200)
        cur.removeSelectedText()
    cur = log_view.textCursor()
    cur.movePosition(cur.MoveOperation.End)
    log_view.setTextCursor(cur)
    log_view.insertHtml(line)
    log_view.ensureCursorVisible()


# Import release modules
try:
    from release import ReleaseOrchestrator
    from release_lib.config import ReleaseConfig
except ImportError as e:
    print(f"Error importing release modules: {e}")


class LogSignals(QObject):
    """Signals for thread-safe log updates"""
    log_message = Signal(str, str)  # message, level
    operation_finished = Signal(bool, str)  # success, message
    progress_update = Signal(int, int, str)  # current, total, description


class StdoutCapture:
    """Captures stdout and emits to signal"""
    def __init__(self, signal):
        self.signal = signal
        self.buffer = ""

    def write(self, text):
        if text:
            # Buffer incomplete lines
            self.buffer += text
            while '\n' in self.buffer:
                line, self.buffer = self.buffer.split('\n', 1)
                if line.strip():
                    self.signal.emit(line, "info")

    def flush(self):
        if self.buffer.strip():
            self.signal.emit(self.buffer, "info")
            self.buffer = ""


class ReleaseWorker(QThread):
    """Worker thread for release operations"""

    def __init__(self, operation: str, params: dict, project_root: Path):
        super().__init__()
        self.operation = operation
        self.params = params
        self.project_root = project_root
        self.signals = LogSignals()
        self.cancelled = False
        self.current_uploader = None

    def run(self):
        # Capture stdout to redirect print statements to log
        old_stdout = sys.stdout
        sys.stdout = StdoutCapture(self.signals.log_message)

        try:
            if self.operation == "release":
                self._execute_release()
            elif self.operation == "retry_upload":
                self._retry_upload()
            self._log("Diagnostic: Worker execution finished. Application should remain active.", "info")
        finally:
            sys.stdout.flush()
            sys.stdout = old_stdout

    def cancel(self):
        self.cancelled = True
        if self.current_uploader and self.current_uploader.current_process:
            try:
                self.current_uploader.current_process.terminate()
            except:
                pass

    def _log(self, message: str, level: str = "info"):
        self.signals.log_message.emit(message, level)

    def _execute_release(self):
        try:
            bump = self.params.get('bump_type', 'patch')
            channel = self.params.get('channel', 'stable')
            dry_run = self.params.get('dry_run', True)
            manual_version = self.params.get('manual_version', '')

            channel_display = "🔷 BETA" if channel == 'beta' else "🟢 STABLE"
            if manual_version:
                self._log(f"Starting Release (Version: {manual_version}, Channel: {channel_display}, Dry Run: {dry_run})", "info")
            else:
                self._log(f"Starting Release (Bump: {bump}, Channel: {channel_display}, Dry Run: {dry_run})", "info")

            # Set environment variables
            os.environ['YADS_FTP_PASSWORD'] = self.params.get('ftp_pass', '')
            os.environ['GEMINI_API_KEY'] = os.getenv('GEMINI_API_KEY', '')

            orchestrator = ReleaseOrchestrator(str(self.project_root))

            try:
                orchestrator.load_config()
            except Exception as e:
                self._log(f"Config note: {e}", "warning")
                if not hasattr(orchestrator, 'config') or orchestrator.config is None:
                    orchestrator.config = ReleaseConfig("/dev/nonexistent")
                    orchestrator.config.config = {}

            # Apply GUI settings
            self._apply_config(orchestrator)

            # Re-initialize uploader
            from release_lib.uploader import ReleaseUploader
            orchestrator.uploader = ReleaseUploader(orchestrator.config.config, str(self.project_root))
            self.current_uploader = orchestrator.uploader

            # Run release
            success = orchestrator.execute_release(
                bump_type=bump,
                dry_run=dry_run,
                use_editor=False,
                interactive=False,
                target_version=manual_version if manual_version else None,
                channel=channel
            )

            if success:
                self.signals.operation_finished.emit(True, "Release completed successfully!")
            else:
                self.signals.operation_finished.emit(False, "Release process failed")

        except Exception as e:
            self._log(f"Critical error: {e}", "error")
            self.signals.operation_finished.emit(False, str(e))

    def _retry_upload(self):
        try:
            version = self.params.get('version', '')
            dry_run = self.params.get('dry_run', True)
            channel = self.params.get('upload_channel', 'stable')

            if not version:
                self.signals.operation_finished.emit(False, "No version selected")
                return

            channel_display = "🔷 BETA" if channel == 'beta' else "🟢 STABLE"
            if dry_run:
                self._log(f"DRY RUN: Upload Preview for v{version} ({channel_display})", "info")
            else:
                self._log(f"Retrying Upload for v{version} ({channel_display})", "info")

            os.environ['YADS_FTP_PASSWORD'] = self.params.get('ftp_pass', '')

            orchestrator = ReleaseOrchestrator(str(self.project_root))

            try:
                orchestrator.load_config()
            except Exception as e:
                self._log(f"Config note: {e}", "warning")
                if not hasattr(orchestrator, 'config') or orchestrator.config is None:
                    orchestrator.config = ReleaseConfig("/dev/nonexistent")
                    orchestrator.config.config = {}

            self._apply_config(orchestrator)

            from release_lib.uploader import ReleaseUploader
            orchestrator.uploader = ReleaseUploader(orchestrator.config.config, str(self.project_root))
            self.current_uploader = orchestrator.uploader

            success = orchestrator.retry_upload(version, channel=channel, dry_run=dry_run)

            if dry_run:
                self.signals.operation_finished.emit(True, "Dry run complete - no files uploaded")
            elif success:
                self.signals.operation_finished.emit(True, "Upload completed successfully!")
            else:
                self.signals.operation_finished.emit(False, "Upload failed")

        except Exception as e:
            self._log(f"Critical error: {e}", "error")
            self.signals.operation_finished.emit(False, str(e))

    def _apply_config(self, orchestrator):
        """Apply GUI settings to orchestrator config"""
        config = orchestrator.config.config

        if 'upload' not in config: config['upload'] = {}
        if 'ssh' not in config['upload']: config['upload']['ssh'] = {}
        if 'ftp' not in config['upload']: config['upload']['ftp'] = {}
        if 'paths' not in config['upload']: config['upload']['paths'] = {}

        # SSH settings
        ssh_host = self.params.get('ssh_host', '')
        ssh_user = self.params.get('ssh_user', '')
        # Read upload_ssh_disabled directly from YAML (not a GUI field)
        try:
            import yaml as _yaml
            _cfg_path = orchestrator.config.config_file if hasattr(orchestrator.config, 'config_file') else None
            if _cfg_path is None:
                import pathlib
                _cfg_path = pathlib.Path.home() / '.yads' / 'release_gui.yaml'
            _raw = _yaml.safe_load(open(_cfg_path)) or {} if pathlib.Path(_cfg_path).exists() else {}
            ssh_disabled = _raw.get('upload_ssh_disabled', False)
        except Exception:
            ssh_disabled = self.params.get('upload_ssh_disabled', False)
        if ssh_host and ssh_user and not ssh_disabled:
            config['upload']['method'] = 'ssh'
            config['upload']['ssh']['host'] = ssh_host
            config['upload']['ssh']['user'] = ssh_user
            config['upload']['ssh']['password'] = self.params.get('ssh_pass', '')
            ssh_key = self.params.get('ssh_key', '').strip()
            config['upload']['ssh']['key_file'] = ssh_key if ssh_key else ''
            try:
                config['upload']['ssh']['port'] = int(self.params.get('ssh_port', 22))
            except ValueError:
                config['upload']['ssh']['port'] = 22
        else:
            config['upload']['method'] = 'ftp'

        # FTP settings
        ftp_host = self.params.get('ftp_host', '')
        if ftp_host:
            config['upload']['ftp']['host'] = ftp_host
        config['upload']['ftp']['user'] = self.params.get('ftp_user', '')
        config['upload']['ftp']['password'] = self.params.get('ftp_pass', '')
        if 'port' not in config['upload']['ftp']:
            config['upload']['ftp']['port'] = 21

        # Paths based on method
        if config['upload']['method'] == 'ssh':
            path_releases = self.params.get('ssh_path_releases', '/en/releases/').strip()
            path_en = self.params.get('ssh_path_en', '/en/').strip()
            path_de = self.params.get('ssh_path_de', '/de/').strip()
        else:
            path_releases = self.params.get('ftp_path_releases', '/en/releases/').strip()
            path_en = self.params.get('ftp_path_en', '/en/').strip()
            path_de = self.params.get('ftp_path_de', '/de/').strip()

        if path_releases:
            if not path_releases.endswith('/'): path_releases += '/'
            config['upload']['paths']['releases'] = path_releases
        if path_en:
            if not path_en.endswith('/'): path_en += '/'
            config['upload']['paths']['homepage_en'] = path_en
        if path_de:
            if not path_de.endswith('/'): path_de += '/'
            config['upload']['paths']['homepage_de'] = path_de

        # Translation settings
        if 'translation' not in config: config['translation'] = {}
        config['translation']['service'] = self.params.get('ai_service', 'gemini')

        if config['translation']['service'] == 'gemini':
            config['translation']['api_key'] = self.params.get('gemini_key', '')
        elif config['translation']['service'] == 'vertexai':
            config['translation']['project_id'] = self.params.get('gcp_project', '')
            config['translation']['location'] = self.params.get('gcp_location', 'us-central1')

        # Re-initialize translator
        from release_lib.translator import ChangelogTranslator
        orchestrator.translator = ChangelogTranslator(
            api_key=self.params.get('gemini_key') if config['translation']['service'] == 'gemini' else None,
            service=config['translation']['service'],
            project_id=self.params.get('gcp_project') if config['translation']['service'] == 'vertexai' else None,
            location=self.params.get('gcp_location', 'us-central1'),
            model_name=self.params.get('ai_model', 'gemini-2.0-flash')
        )

        if orchestrator.translator.model:
            orchestrator.changelog_manager.set_ai_model(
                orchestrator.translator.model,
                orchestrator.translator.service
            )


class GuiTestWorker(QThread):
    """Worker thread for running Playwright GUI tests"""

    def __init__(self, target_url: str, dana_host: str):
        super().__init__()
        self.target_url = target_url
        self.dana_host = dana_host
        self.signals = LogSignals()
        self.current_process = None
        self.cancelled = False

    def run(self):
        try:
            self._log(f"🚀 Preparing Remote environment on {self.dana_host}...", "info")
            # 1. Sync files to Dana
            # Use absolute paths and exclude virtual environments
            project_root = script_dir.parent
            dana_path = "~/yads-testenv"
            self._log("Syncing tools/ and docker-compose.testlab.yml to Dana (excluding venvs)...", "info")
            
            subprocess.run(["ssh", self.dana_host, f"mkdir -p {dana_path}"], check=True)
            
            sync_cmd = [
                "rsync", "-avz",
                "--exclude", "venv",
                "--exclude", ".venv",
                "--exclude", "*_venv", 
                "--exclude", "__pycache__",
                "--exclude", ".git",
                "--exclude", ".pytest_cache",
                "--exclude", ".env*",
                "--exclude", "config.env",
                str(project_root) + "/", 
                f"{self.dana_host}:{dana_path}/"
            ]
            subprocess.run(sync_cmd, check=True)

            # 2. Ensure environment is up
            self._log("Starting test environment on Dana...", "info")
            subprocess.run(["ssh", self.dana_host, f"cd {dana_path} && docker compose -f docker-compose.testlab.yml up -d"], check=True)

            # 2b. Stream-wait for YADS API to become healthy (output → GUI log)
            self._log("Waiting for YADS API to become ready on Dana...", "info")
            wait_cmd = [
                "ssh", self.dana_host,
                f"for i in $(seq 1 60); do "
                f"python3 -c \"import urllib.request; urllib.request.urlopen('http://localhost:8085/', timeout=3)\" 2>/dev/null "
                f"  && echo '[API] YADS API is ready.' && exit 0; "
                f"echo \"[API] Waiting for YADS API... ($i/60)\"; sleep 3; done; "
                f"echo '[API] ERROR: YADS API did not become ready after 180s'; exit 1"
            ]
            wait_proc = subprocess.Popen(
                wait_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, universal_newlines=True,
            )
            for line in wait_proc.stdout:
                line = _ANSI_RE.sub('', line).strip()
                if line:
                    self._log(line, "info")
            wait_proc.wait()
            if wait_proc.returncode != 0:
                self._log("YADS API did not become ready in time. Aborting tests.", "error")
                self.signals.operation_finished.emit(False, "YADS API startup timeout on Dana")
                return

            # 2c. Stream-wait for gui-tester container (Playwright install takes time)
            self._log("Waiting for gui-tester container to be ready (installing Playwright)...", "info")
            tester_wait_cmd = [
                "ssh", self.dana_host,
                f"cd {dana_path} && for i in $(seq 1 90); do "
                f"docker compose -f docker-compose.testlab.yml exec -T gui-tester "
                f"  python3 -c 'import playwright; print(\"Playwright OK\")' 2>/dev/null "
                f"  && exit 0; "
                f"echo \"[Tester] Setting up gui-tester... ($i/90)\"; sleep 5; done; "
                f"echo '[Tester] ERROR: gui-tester not ready after 450s'; exit 1"
            ]
            tester_proc = subprocess.Popen(
                tester_wait_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, universal_newlines=True,
            )
            for line in tester_proc.stdout:
                line = _ANSI_RE.sub('', line).strip()
                if line:
                    self._log(line, "info")
            tester_proc.wait()
            if tester_proc.returncode != 0:
                self._log("gui-tester container did not become ready. Aborting.", "error")
                self.signals.operation_finished.emit(False, "gui-tester setup timeout")
                return

            # 3. Run tests inside container
            self._log("▶ Launching GUI test suite...", "info")
            cmd = [
                "ssh", self.dana_host,
                # -u = unbuffered stdout/stderr so lines reach us immediately
                f"cd {dana_path} && docker compose -f docker-compose.testlab.yml exec -T gui-tester python3 -u tools/gui_test_runner.py --url {self.target_url}"
            ]
            
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            for line in self.current_process.stdout:
                if self.cancelled:
                    self.current_process.terminate()
                    break
                
                line = _ANSI_RE.sub('', line).strip()
                if line:
                    lo = line.lower()
                    if "❌" in line or "FAILURE" in line or "CRITICAL" in line or lo.startswith("error"):
                        level = "error"
                    elif "⚠" in line or "warning" in lo:
                        level = "warning"
                    elif "✅" in line or "passed" in lo or "success" in lo or "report generated" in lo:
                        level = "success"
                    elif "▶" in line or "pre-step" in lo or "testing page" in lo or "screenshot" in lo:
                        level = "info"
                    else:
                        level = "info"
                    self._log(line, level)

            self.current_process.wait()
            success = self.current_process.returncode == 0
            
            # Sync results back from Dana to local
            self._log("Syncing test results back from Dana...", "info")
            local_results = Path(__file__).parent.parent / "tests" / "results" / "GUI-Tests"
            local_results.mkdir(parents=True, exist_ok=True)
            subprocess.run(["rsync", "-avz", f"{self.dana_host}:{dana_path}/tests/results/", str(local_results) + "/"], check=False)

            if self.cancelled:
                self._log("Tests stopped by user.", "warning")
            elif success:
                self.signals.operation_finished.emit(True, "GUI Tests completed successfully.")
            else:
                self.signals.operation_finished.emit(False, f"GUI Tests failed with code {self.current_process.returncode}")

        except Exception as e:
            self._log(f"Critical error: {e}", "error")
            self.signals.operation_finished.emit(False, str(e))

    def cancel(self):
        self.cancelled = True
        if self.current_process:
            try:
                self.current_process.terminate()
            except:
                pass

    def _log(self, message: str, level: str = "info"):
        self.signals.log_message.emit(message, level)


class ProdDeployWorker(QThread):
    """Worker thread for PROD deployment"""

    def __init__(self, project_root: Path, wipe_reinstall: bool = False, setup_token: str = None,
                 deploy_app: bool = True, deploy_worker: bool = True, deploy_backup: bool = True):
        super().__init__()
        self.project_root = project_root
        self.wipe_reinstall = wipe_reinstall
        self.setup_token = setup_token
        self.deploy_app = deploy_app
        self.deploy_worker = deploy_worker  # only needed when scanner tools / Python deps change
        self.deploy_backup = deploy_backup
        self.signals = LogSignals()
        self.cancelled = False
        self.current_process = None

        # Deployment target
        self.remote_host = "root@prod.example.com"
        self.stack_name = "yads"
        self.remote_deploy_dir = "~/deploy/yads"

        # SSH Connection Sharing (ControlMaster)
        import tempfile
        self.control_socket = Path(tempfile.gettempdir()) / f"yads_deploy_{os.getpid()}.sock"

        # Image names — pushed to registry.yads-security.com for prod pulls
        self.docker_compose_file = "docker-compose.swarm.yml"
        self.registry_image        = "registry.yads-security.com/yads/yads-api:latest"
        self.worker_registry_image = "registry.yads-security.com/yads/yads-worker:latest"
        self.backup_registry_image = "registry.yads-security.com/yads/yads-backup:latest"

        self.services_to_update = [
            f"{self.stack_name}_yads-api",
            f"{self.stack_name}_yads-worker-primary",
            f"{self.stack_name}_yads-backup"
        ]
        self.data_volumes = [
            f"{self.stack_name}_postgres_data",
            f"{self.stack_name}_redis_data",
            f"{self.stack_name}_logs",
            f"{self.stack_name}_data",
            f"{self.stack_name}_nuclei_templates"
        ]

    def _execute_cleanup_prod(self):
        try:
            self._log("🧹 Manually requested cleanup on PROD...", "warning")
            self.signals.progress_update.emit(10, 100, "Initiating cleanup...")
            
            # Ensure socket dir exists
            if not self.control_socket.parent.exists():
                self.control_socket.parent.mkdir(parents=True, exist_ok=True)
                
            self._log("Establishing persistent SSH connection for cleanup...", "info")
            if not self._run_cmd(["ssh", "-fN", self.remote_host]):
                self._log("Warning: Could not start ControlMaster, proceeding normally.", "warning")

            self._log("Running 'docker system prune -af' on remote host...", "info")
            self.signals.progress_update.emit(30, 100, "Pruning Docker system...")
            
            # Prune everything: -a (all unused images), -f (force)
            success = self._run_cmd(["ssh", self.remote_host, "docker system prune -af"])
            
            if success:
                self._log("✅ Cleanup successful. Checking disk space...", "success")
                self._run_cmd(["ssh", self.remote_host, "df -h /"])
                self.signals.operation_finished.emit(True, "Remote cleanup complete.")
            else:
                self.signals.operation_finished.emit(False, "Remote cleanup failed.")
        except Exception as e:
            self._log(f"Error during cleanup: {e}", "error")
            self.signals.operation_finished.emit(False, str(e))

    def run(self):
        try:
            if hasattr(self, 'operation') and self.operation == "cleanup_prod":
                self._execute_cleanup_prod()
            else:
                self._execute_deploy()
            self._log("Diagnostic: Worker execution finished successfully. Application should remain active.", "info")
        except Exception as e:
            self._log(f"Critical error during deployment: {e}", "error")
            self.signals.operation_finished.emit(False, str(e))
        finally:
            self._cleanup_ssh()

    def _cleanup_ssh(self):
        """Close the SSH ControlMaster connection"""
        if self.control_socket.exists():
            self._log("Closing master SSH connection...", "info")
            subprocess.run(["ssh", "-o", f"ControlPath={self.control_socket}", "-O", "exit", self.remote_host], 
                           stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            try:
                self.control_socket.unlink(missing_ok=True)
            except:
                pass

    def cancel(self):
        self.cancelled = True
        if self.current_process:
            try:
                self.current_process.terminate()
            except:
                pass
        self._cleanup_ssh()

    def _log(self, message: str, level: str = "info"):
        self.signals.log_message.emit(message, level)

    def _inject_ssh_opts(self, cmd: list) -> list:
        if not cmd: return cmd
        
        # Stability and Connection Sharing options
        all_opts = [
            "-o", f"ControlPath={self.control_socket}",
            "-o", "ControlMaster=auto",
            "-o", "ControlPersist=10m",
            "-o", "ClearAllForwardings=yes",
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3"
        ]
        
        if cmd[0] in ['ssh', 'scp']:
            return [cmd[0]] + all_opts + cmd[1:]
        elif cmd[0] == 'rsync':
            ssh_str = f"ssh {' '.join(all_opts)}"
            # Find where source/dest starts in rsync. Usually rsync [opts] src dest
            # We want to insert -e "ssh ..."
            return ['rsync', '-e', ssh_str] + cmd[1:]
        return cmd

    def _run_cmd(self, cmd: list, shell=False, cwd=None, is_rsync=False) -> bool:
        if self.cancelled:
            return False

        if cwd is None:
            cwd = str(self.project_root)

        # Inject options to avoid port forwarding conflicts and reuse connections
        if not shell:
            cmd = self._inject_ssh_opts(cmd)

        self._log(f"Running: {' '.join(cmd) if not shell else cmd}", "info")
        
        try:
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                shell=shell,
                cwd=cwd,
                bufsize=1,
                universal_newlines=True
            )

            for line in self.current_process.stdout:
                if self.cancelled:
                    self.current_process.terminate()
                    break

                # Strip ANSI escape codes and bare carriage returns
                line = _ANSI_RE.sub('', line)
                if not line.strip():
                    continue

                # Filter noise (mostly from initial master connection attempt)
                if any(x in line for x in ["channel_setup_fwd_listener_tcpip", "cannot listen to port", "Address already in use"]):
                    continue
                
                # Parse rsync progress
                if is_rsync and "%" in line:
                    match = re.search(r'(\d+)%', line)
                    if match:
                        percent = int(match.group(1))
                        self.signals.progress_update.emit(percent, 100, "Transferring images...")
                        if percent % 10 == 0:
                            self._log(line.strip(), "info")
                        continue

                self._log(line.strip(), "info")

            self.current_process.wait()
            success = self.current_process.returncode == 0
            
            if not success and not self.cancelled:
                self._log(f"Command failed with return code {self.current_process.returncode}", "error")
            
            return success
        except Exception as e:
            self._log(f"Error executing command: {e}", "error")
            return False
        finally:
            self.current_process = None

    def _check_image_cache(self) -> bool:
        """
        Return True if the local yads:latest image is up-to-date
        (image exists AND git working tree is clean AND git HEAD matches
        the YADS_GIT_SHA label in the image).
        """
        try:
            # Check if image exists
            r = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", "yads:latest"],
                capture_output=True, text=True
            )
            if r.returncode != 0:
                self._log("Image cache: no local image found — will build fresh.", "info")
                return False

            # Get git SHA from image label
            img_sha_r = subprocess.run(
                ["docker", "image", "inspect", "--format",
                 "{{index .Config.Labels \"YADS_GIT_SHA\"}}", "yads:latest"],
                capture_output=True, text=True
            )
            img_sha = img_sha_r.stdout.strip()

            # Get current git HEAD SHA
            git_sha_r = subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                cwd=str(self.project_root)
            )
            git_sha = git_sha_r.stdout.strip()

            # Check if working tree is dirty
            dirty_r = subprocess.run(
                ["git", "status", "--porcelain"], capture_output=True, text=True,
                cwd=str(self.project_root)
            )
            dirty = bool(dirty_r.stdout.strip())

            if dirty:
                self._log("Image cache: working tree has uncommitted changes — rebuilding.", "info")
                return False
            if img_sha and git_sha and img_sha == git_sha:
                self._log(f"Image cache: image matches HEAD {git_sha[:8]} — skipping build.", "success")
                return True
            self._log(f"Image cache: SHA mismatch (image={img_sha[:8] if img_sha else 'none'}, HEAD={git_sha[:8]}) — rebuilding.", "info")
            return False
        except Exception as e:
            self._log(f"Image cache check failed: {e} — will rebuild.", "info")
            return False

    def _elapsed(self, start: float) -> str:
        import time as _t
        s = int(_t.time() - start)
        return f"{s//60}m {s%60}s" if s >= 60 else f"{s}s"

    def _execute_deploy(self):
        import time as _time
        _deploy_start = _time.time()
        try:
            if self.wipe_reinstall:
                self._log("🚀 Starting Production Deployment (FRESH INSTALL)", "warning")
            else:
                self._log("🚀 Starting Production Deployment (Update Path)", "success")
            self.signals.progress_update.emit(0, 100, "Initializing connection...")
            
            # 0. Establish Master Connection
            self._log("Establishing persistent SSH connection...", "info")
            if not self._run_cmd(["ssh", "-fN", self.remote_host]):
                self._log("Warning: Could not start ControlMaster, will proceed with standard connections", "warning")

            # 0.1 Registry auth pre-flight — re-login so PROD can pull images
            try:
                import yaml as _yaml
                _cfg_path = Path.home() / ".yads" / "release_gui.yaml"
                _raw = _yaml.safe_load(open(_cfg_path)) or {} if _cfg_path.exists() else {}
                _reg_user = _raw.get('registry_user', '').strip()
                _reg_pass = _raw.get('registry_pass', '').strip()
                _registry = "registry.yads-security.com"
                if _reg_user and _reg_pass:
                    self._log(f"Step 0.0/8: Logging into registry on PROD ({_registry})...", "info")
                    login_cmd = f"echo {_reg_pass!r} | docker login {_registry} -u {_reg_user} --password-stdin"
                    if self._run_cmd(["ssh", self.remote_host, login_cmd]):
                        self._log("  ✅ Registry login successful.", "success")
                    else:
                        self._log("  ⚠️  Registry login failed — pulls may fail if auth is expired!", "warning")
                else:
                    self._log("Step 0.0/8: No registry credentials in config — skipping docker login.", "info")
            except Exception as _e:
                self._log(f"Step 0.0/8: Registry login skipped ({_e}).", "warning")

            # 0.2 Automatic Cleanup if space is low
            self._log("Step 0.1/8: Checking remote disk space...", "info")
            check_space = subprocess.run(
                self._inject_ssh_opts(["ssh", self.remote_host, "df --output=avail / | tail -n 1"]),
                capture_output=True, text=True
            )
            try:
                avail_kb = int(check_space.stdout.strip())
                avail_gb = avail_kb / (1024 * 1024)
                self._log(f"Available space on remote: {avail_gb:.2f} GB", "info")
                if avail_gb < 10:  # Threshold for safety (YADS image is ~5.3GB)
                    self._log(f"⚠️  Low disk space ({avail_gb:.2f} GB). Running automatic cleanup...", "warning")
                    self._run_cmd(["ssh", self.remote_host, "docker system prune -f"])
                    self._log("Automatic cleanup finished.", "info")
            except:
                self._log("Could not determine remote disk space, proceeding anyway.", "warning")

            if self.wipe_reinstall:
                import time
                self._log("==================================================", "warning")
                self._log(f"SETUP TOKEN: {self.setup_token}", "success")
                self._log("Save this token to access the setup wizard!", "warning")
                self._log("==================================================", "warning")

                self._log("Step 0.5/8: Wiping existing installation...", "warning")
                self.signals.progress_update.emit(2, 100, "Wiping existing installation...")
                
                self._log("Removing existing stack...", "info")
                self._run_cmd(["ssh", self.remote_host, f"docker stack rm {self.stack_name}"])

                self._log("Waiting for services to stop (max 60s)...", "info")
                for i in range(30):
                    result = subprocess.run(["ssh", self.remote_host, f"docker ps -q --filter label=com.docker.stack.namespace={self.stack_name}"], capture_output=True, text=True)
                    if not result.stdout.strip():
                        self._log("All containers stopped.", "info")
                        break
                    time.sleep(2)
                
                self._log("Pruning containers...", "info")
                self._run_cmd(["ssh", self.remote_host, f"docker container prune -f --filter label=com.docker.stack.namespace={self.stack_name}"])

                self._log("Removing data volumes...", "info")
                for vol in self.data_volumes:
                    self._run_cmd(["ssh", self.remote_host, f"docker volume rm {vol}"])
                
                self._log("Removing stack networks...", "info")
                self._run_cmd(["ssh", self.remote_host, f"docker network rm {self.stack_name}_yads-internal {self.stack_name}_yads-frontend"])

                self._log("Removing old images...", "info")
                self._run_cmd(["ssh", self.remote_host,
                               f"docker rmi {self.registry_image} {self.worker_registry_image} {self.backup_registry_image}"])
                self._log("Wipe complete.", "success")

            # ── Step 1: Build API image ────────────────────────────────────────
            self.signals.progress_update.emit(3, 100, "Checking image cache...")
            use_cached_api = False
            if not self.wipe_reinstall and self.deploy_app:
                use_cached_api = self._check_image_cache()

            if self.deploy_app:
                if use_cached_api:
                    self._log("Step 1a: ⚡ API image up-to-date (no source changes)", "success")
                    self.signals.progress_update.emit(8, 100, "Using cached API image...")
                else:
                    git_sha = subprocess.run(
                        ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                        cwd=str(self.project_root)
                    ).stdout.strip()
                    self._log("Step 1a: Building YADS API image (no scanner tools)...", "info")
                    self.signals.progress_update.emit(5, 100, "Building API image...")
                    build_cmd = [
                        "docker", "build",
                        "--target", "api",
                        "--build-arg", f"YADS_GIT_SHA={git_sha}",
                        "-t", "yads-api:latest",
                        "-t", self.registry_image,
                        "."
                    ]
                    if not self._run_cmd(build_cmd):
                        return self.signals.operation_finished.emit(False, "API build failed")
                    self._log("Step 1a: API image built.", "success")
            else:
                self._log("Step 1a: Skipping API build.", "warning")

            # ── Step 1b: Build Worker image (optional) ─────────────────────────
            if self.deploy_worker:
                self._log("Step 1b: Building YADS Worker image...", "info")
                self.signals.progress_update.emit(8, 100, "Building Worker image...")
                # Use Dockerfile.worker (pre-baked tools base) if available — much faster.
                # Falls back to --target worker (inline full build) if Dockerfile.worker is missing.
                tools_image = f"{RebuildToolsWorker.TOOLS_REGISTRY_IMAGE}:{getattr(self, 'tools_tag', '1.0')}"
                worker_dockerfile = self.project_root / "Dockerfile.worker"
                if worker_dockerfile.exists():
                    self._log(f"  Using Dockerfile.worker with pre-baked tools image ({tools_image})...", "info")
                    worker_build_cmd = [
                        "docker", "build",
                        "-f", "Dockerfile.worker",
                        "--build-arg", f"TOOLS_IMAGE={tools_image}",
                        "-t", "yads-worker:latest",
                        "-t", self.worker_registry_image,
                        "."
                    ]
                else:
                    self._log("  Dockerfile.worker not found — falling back to inline build (slow).", "warning")
                    worker_build_cmd = [
                        "docker", "build",
                        "--target", "worker",
                        "-t", "yads-worker:latest",
                        "-t", self.worker_registry_image,
                        "."
                    ]
                if not self._run_cmd(worker_build_cmd):
                    return self.signals.operation_finished.emit(False, "Worker build failed")
                self._log("Step 1b: Worker image built.", "success")
            else:
                self._log("Step 1b: Skipping Worker image build (code-only deploy).", "info")

            # ── Step 2: Build Backup image ─────────────────────────────────────
            if self.deploy_backup:
                self._log("Step 2: Building backup container image...", "info")
                self.signals.progress_update.emit(15, 100, "Building backup image...")
                if not self._run_cmd(["docker", "build", "-t", "yads-backup:latest", "backup/"]):
                    return self.signals.operation_finished.emit(False, "Backup build failed")
                if not self._run_cmd(["docker", "tag", "yads-backup:latest", self.backup_registry_image]):
                    return self.signals.operation_finished.emit(False, "Backup tagging failed")
            else:
                self._log("Step 2: Skipping Backup build.", "warning")

            # ── Step 3+4: Push images to registry.yads-security.com ──────────
            # Prod server pulls directly from registry during service update.
            self.signals.progress_update.emit(20, 100, "Pushing images to registry...")
            self._run_cmd(["ssh", self.remote_host, f"mkdir -p {self.remote_deploy_dir}"])

            images_to_push = []
            if self.deploy_app and not use_cached_api:
                images_to_push.append((self.registry_image, "API"))
            if self.deploy_worker:
                images_to_push.append((self.worker_registry_image, "Worker"))
            if self.deploy_backup:
                images_to_push.append((self.backup_registry_image, "Backup"))

            if not images_to_push:
                self._log("All images cached — nothing to push.", "success")
            else:
                total_imgs = len(images_to_push)
                for idx, (img, label) in enumerate(images_to_push, 1):
                    pct = 20 + int((idx / total_imgs) * 55)
                    self._log(f"Step 3/{total_imgs}: Pushing {label} image to registry...", "info")
                    self.signals.progress_update.emit(pct, 100, f"Pushing {label} image...")
                    if not self._run_cmd(["docker", "push", img]):
                        return self.signals.operation_finished.emit(False, f"{label} image push failed")
                    self._log(f"  ✅ {label} image pushed.", "success")

            self._log("Step 4: All images in registry.", "success")

            # 4. Config
            self._log("Step 6/8: Transferring configuration...", "info")
            self.signals.progress_update.emit(90, 100, "Transferring config...")
            if not self._run_cmd(["scp", self.docker_compose_file, f"{self.remote_host}:{self.remote_deploy_dir}/"]):
                return self.signals.operation_finished.emit(False, "Config transfer failed")
            
            if (self.project_root / ".env").exists():
                self._run_cmd(["scp", ".env", f"{self.remote_host}:{self.remote_deploy_dir}/"])

            if self.wipe_reinstall and hasattr(self, 'setup_token'):
                self._log("Injecting SETUP_TOKEN into remote .env...", "info")
                inject_cmd = f"cd {self.remote_deploy_dir} && (grep -q '^SETUP_TOKEN=' .env 2>/dev/null && sed -i 's/^SETUP_TOKEN=.*/SETUP_TOKEN={self.setup_token}/' .env || echo 'SETUP_TOKEN={self.setup_token}' >> .env)"
                self._run_cmd(["ssh", self.remote_host, inject_cmd])

            self._log("Creating backup directories on remote host...", "info")
            self._run_cmd(["ssh", self.remote_host, "mkdir -p '/mnt/backups/yads/daily' '/mnt/backups/yads/monthly'"])

            # 5. Deploy & Update
            self._log("Step 7/8: Deploying stack...", "info")
            self.signals.progress_update.emit(95, 100, "Finalizing deployment...")
            
            combined_deploy_cmd = [
                f"cd {self.remote_deploy_dir}",
                "set -a && [ -f .env ] && source .env; set +a",
                f"docker stack deploy --with-registry-auth -c {self.docker_compose_file} {self.stack_name}"
            ]
            
            if not self.wipe_reinstall:
                self._log("Forcing service updates...", "info")
                for service in self.services_to_update:
                    if "backup" in service:
                        if self.deploy_backup:
                            combined_deploy_cmd.append(f"docker service update --with-registry-auth --force --image {self.backup_registry_image} {service}")
                        else:
                            self._log(f"Skipping update for {service} (Backup skipped)", "info")
                    elif "worker" in service:
                        if self.deploy_worker:
                            combined_deploy_cmd.append(f"docker service update --with-registry-auth --force --image {self.worker_registry_image} {service}")
                        else:
                            self._log(f"Skipping update for {service} (Worker skipped)", "info")
                    else:
                        if self.deploy_app:
                            combined_deploy_cmd.append(f"docker service update --with-registry-auth --force --image {self.registry_image} {service}")
                        else:
                            self._log(f"Skipping update for {service} (App skipped)", "info")
                
            full_remote_cmd = " && ".join(combined_deploy_cmd)
            
            if not self._run_cmd(["ssh", self.remote_host, full_remote_cmd]):
                return self.signals.operation_finished.emit(False, "Remote deployment/update failed")

            # 6. Service status check
            self._log("Step 8/8: Verifying service health...", "info")
            import time as _time
            _time.sleep(10)
            # Show service table in log
            self._run_cmd(
                ["ssh", self.remote_host,
                 f"docker service ls --filter label=com.docker.stack.namespace={self.stack_name} "
                 f"--format 'table {{{{.Name}}}}\\t{{{{.Replicas}}}}\\t{{{{.Image}}}}'"]
            )
            # Check for any 0/N failures (exclude intentional 0/0 entries)
            check_cmd = (
                f"docker service ls --filter label=com.docker.stack.namespace={self.stack_name} "
                f"--format '{{{{.Replicas}}}}' | grep -v '^0/0' | grep '^0/' || true"
            )
            result = subprocess.run(
                self._inject_ssh_opts(["ssh", self.remote_host, check_cmd]),
                capture_output=True, text=True
            )
            if result.stdout.strip():
                self._log(f"⚠️  Some services have 0 replicas running: {result.stdout.strip()}", "warning")
            else:
                self._log("✅ All expected services are running!", "success")

            # 7. Post-deploy smoke test
            self._log("Running smoke test (HTTP health check)...", "info")
            import time as _t2
            _t2.sleep(5)  # brief settle time
            try:
                import urllib.request, urllib.error
                _smoke_url = "https://prod.example.com/health"
                req = urllib.request.Request(_smoke_url, headers={"User-Agent": "YADS-Deploy-SmokeTest/1.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    if resp.status == 200:
                        self._log(f"✅ Smoke test passed — HTTP 200 from {_smoke_url}", "success")
                    else:
                        self._log(f"⚠️  Smoke test: unexpected status {resp.status} from {_smoke_url}", "warning")
            except urllib.error.URLError as _se:
                self._log(f"⚠️  Smoke test failed (URL error): {_se.reason} — check nginx/proxy config", "warning")
            except Exception as _se:
                self._log(f"⚠️  Smoke test failed: {_se}", "warning")

            _total = self._elapsed(_deploy_start)
            self.signals.progress_update.emit(100, 100, f"Success! ({_total})")
            self._log(f"✅ Deployment to PROD completed successfully! [total time: {_total}]", "success")
            self.signals.operation_finished.emit(True, f"PROD Update finished in {_total}")

        finally:
            # Cleanup locals ALWAYS
            self._log("Cleaning up local archives...", "info")
            import os
            for f in ["yads_deploy.tgz", "yads_backup_deploy.tgz"]:
                try:
                    p = self.project_root / f
                    if p.exists():
                        os.remove(p)
                except:
                    pass


class RebuildToolsWorker(QThread):
    """
    Builds and pushes the pre-baked yads-tools base image (Dockerfile.tools).
    Only needed when Playwright, Nuclei, or Nmap versions change — not on every code push.
    """

    TOOLS_REGISTRY_IMAGE = "registry.yads-security.com/yads/yads-tools"

    def __init__(self, project_root: Path, tools_tag: str = "1.0"):
        super().__init__()
        self.project_root = project_root
        self.tools_tag = tools_tag
        self.signals = LogSignals()
        self.cancelled = False
        self.current_process = None

    def _log(self, message: str, level: str = "info"):
        self.signals.log_message.emit(message, level)

    def _run_cmd(self, cmd: list, shell: bool = False, cwd=None) -> bool:
        if self.cancelled:
            return False
        cwd = cwd or self.project_root
        self._log(f"$ {cmd if shell else ' '.join(str(c) for c in cmd)}", "cmd")
        try:
            self.current_process = subprocess.Popen(
                cmd, shell=shell, cwd=cwd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            for line in self.current_process.stdout:
                self._log(line.rstrip(), "info")
            self.current_process.wait()
            ok = self.current_process.returncode == 0
            if not ok:
                self._log(f"Command failed (exit {self.current_process.returncode})", "error")
            return ok
        except Exception as e:
            self._log(f"Error running command: {e}", "error")
            return False

    def run(self):
        import time
        start = time.time()
        local_tag = f"yads-tools:{self.tools_tag}"
        registry_tag = f"{self.TOOLS_REGISTRY_IMAGE}:{self.tools_tag}"

        self._log(f"=== Rebuild Scanner Tools Base Image (tag: {self.tools_tag}) ===", "info")
        self._log("This takes 15-20 min (Playwright/Chromium download). Run only when tool versions change.", "warning")

        self.signals.progress_update.emit(0, 100, "Building yads-tools image...")

        # Step 1: Build
        self._log("Step 1/3: Building Dockerfile.tools...", "info")
        if not self._run_cmd([
            "docker", "build",
            "-f", "Dockerfile.tools",
            "-t", local_tag,
            "-t", registry_tag,
            "."
        ]):
            return self.signals.operation_finished.emit(False, "Tools image build failed")

        self.signals.progress_update.emit(70, 100, "Pushing to registry...")

        # Step 2: Push
        self._log("Step 2/3: Pushing to registry...", "info")
        if not self._run_cmd(["docker", "push", registry_tag]):
            return self.signals.operation_finished.emit(False, "Tools image push failed")

        self.signals.progress_update.emit(95, 100, "Verifying...")

        # Step 3: Verify
        self._log("Step 3/3: Verifying image in registry...", "info")
        if not self._run_cmd(["docker", "manifest", "inspect", registry_tag]):
            self._log("Manifest check skipped (not critical)", "warning")

        elapsed = f"{int(time.time() - start) // 60}m {int(time.time() - start) % 60}s"
        self.signals.progress_update.emit(100, 100, f"Done! ({elapsed})")
        self._log(f"✅ yads-tools:{self.tools_tag} built and pushed in {elapsed}", "success")
        self._log(f"ℹ️  Next worker build will use this image via Dockerfile.worker.", "info")
        self.signals.operation_finished.emit(True, f"Tools image {self.tools_tag} ready")


class ProdDeployPage(QWidget):
    """Production deployment page"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("prodDeployPage")
        self.worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        # Title
        title = TitleLabel("Update PROD", self)
        layout.addWidget(title)

        # Info Banner
        self.status_label = BodyLabel(
            "⚠️  Production Update — existing stack only, no data wiped. Target: root@prod.example.com", self
        )
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # Checkbox overlay logic
        self.wipe_check = CheckBox("Wipe Data (NEUINSTALLATION)", self)
        self.wipe_check.setToolTip("WARNING: This will destroy all production data and database!")
        self.wipe_check.stateChanged.connect(self._on_wipe_toggled)
        layout.addWidget(self.wipe_check)

        # Component selection
        selection_group = QHBoxLayout()
        selection_group.setSpacing(20)
        
        self.deploy_app_check = CheckBox("Deploy API image", self)
        self.deploy_app_check.setChecked(True)
        self.deploy_app_check.setToolTip("Build & deploy the lightweight API image (~600 MB). Always needed for code changes.")
        selection_group.addWidget(self.deploy_app_check)

        self.deploy_worker_check = CheckBox("Deploy Worker image", self)
        self.deploy_worker_check.setChecked(False)
        self.deploy_worker_check.setToolTip(
            "Build & deploy the Worker image (Dockerfile.worker, uses pre-baked yads-tools base).\n"
            "Only needed when Python dependencies change. Build time: ~2-3 min."
        )
        selection_group.addWidget(self.deploy_worker_check)

        self.deploy_backup_check = CheckBox("Deploy Backup Service", self)
        self.deploy_backup_check.setChecked(False)
        self.deploy_backup_check.setToolTip("Rebuild and deploy the backup sidecar container.")
        selection_group.addWidget(self.deploy_backup_check)

        selection_group.addStretch()
        layout.addLayout(selection_group)

        # Scanner Tools rebuild card (rare — only when Playwright/Nuclei/Nmap versions change)
        tools_card = CardWidget(self)
        tools_layout = QHBoxLayout(tools_card)
        tools_layout.setContentsMargins(20, 12, 20, 12)
        tools_layout.setSpacing(12)

        tools_label = BodyLabel(
            "Scanner Tools Base Image (yads-tools)  —  rebuild only when Playwright / Nuclei / Nmap version changes",
            self
        )
        tools_label.setStyleSheet("color: #888; font-size: 12px;")
        tools_layout.addWidget(tools_label)

        tools_layout.addStretch()

        self.tools_tag_input = LineEdit(self)
        self.tools_tag_input.setText("1.0")
        self.tools_tag_input.setFixedWidth(60)
        self.tools_tag_input.setToolTip("Image version tag, e.g. 1.0, 1.1")
        tools_layout.addWidget(self.tools_tag_input)

        self.rebuild_tools_btn = PushButton(FIF.UPDATE, "Rebuild & Push Tools Image", self)
        self.rebuild_tools_btn.setFixedWidth(240)
        self.rebuild_tools_btn.setToolTip(
            "Build Dockerfile.tools → yads-tools:<tag> and push to the registry.\n"
            "Takes 15-20 min. Run this before deploying a Worker with updated tool versions."
        )
        self.rebuild_tools_btn.clicked.connect(self._on_rebuild_tools)
        tools_layout.addWidget(self.rebuild_tools_btn)

        layout.addWidget(tools_card)

        # Action Card
        action_card = CardWidget(self)
        action_layout = QHBoxLayout(action_card)
        action_layout.setContentsMargins(20, 20, 20, 20)
        action_layout.setSpacing(16)

        self.deploy_btn = PrimaryPushButton(FIF.SEND, "Deploy to PROD (Update)", self)
        self.deploy_btn.setFixedWidth(240)
        self.deploy_btn.clicked.connect(self._on_deploy)
        action_layout.addWidget(self.deploy_btn)

        self.cancel_btn = PushButton(FIF.CLOSE, "Cancel", self)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel)
        action_layout.addWidget(self.cancel_btn)

        self.retry_btn = PushButton(FIF.SYNC, "Retry / Wiederholen", self)
        self.retry_btn.setVisible(False)
        self.retry_btn.clicked.connect(self._on_retry)
        action_layout.addWidget(self.retry_btn)

        self.rollback_btn = PushButton(FIF.HISTORY, "Rollback", self)
        self.rollback_btn.setVisible(False)
        self.rollback_btn.setToolTip("Roll back all services to their previous image (docker service update --rollback)")
        self.rollback_btn.clicked.connect(self._on_rollback)
        action_layout.addWidget(self.rollback_btn)

        self.cleanup_btn = ToolButton(FIF.DELETE, self)
        self.cleanup_btn.setToolTip("Cleanup Disk: docker system prune -af on PROD")
        self.cleanup_btn.clicked.connect(self._on_cleanup_request)
        action_layout.addWidget(self.cleanup_btn)

        self.ssh_status_label = BodyLabel("○ Checking SSH...", self)
        self.ssh_status_label.setStyleSheet("color: gray; font-size: 12px;")
        action_layout.addWidget(self.ssh_status_label)

        action_layout.addStretch()
        layout.addWidget(action_card)

        # SSH pre-check timer (60s interval)
        self._ssh_check_timer = QTimer(self)
        self._ssh_check_timer.setInterval(60000)
        self._ssh_check_timer.timeout.connect(self._check_ssh)

        # Progress
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(4)

        self.progress_label = BodyLabel("Ready", self)
        progress_layout.addWidget(self.progress_label)

        self.progress_bar = ProgressBar(self)
        self.progress_bar.setValue(0)
        self.progress_bar.setMinimumHeight(16)
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)

        layout.addLayout(progress_layout)

        # Log Card
        log_card = CardWidget(self)
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(20, 16, 20, 20)
        log_layout.setSpacing(12)

        log_header = QHBoxLayout()
        log_title = SubtitleLabel("Deployment Logs", self)
        log_header.addWidget(log_title)
        log_header.addStretch()

        clear_btn = TransparentPushButton(FIF.DELETE, "Clear", self)
        clear_btn.clicked.connect(self._clear_logs)
        log_header.addWidget(clear_btn)
        log_layout.addLayout(log_header)

        # Log filter bar
        from qfluentwidgets import SearchLineEdit
        self._log_filter = SearchLineEdit(self)
        self._log_filter.setPlaceholderText("Filter logs…")
        self._log_filter.setFixedHeight(28)
        self._log_filter.textChanged.connect(self._apply_log_filter)
        log_layout.addWidget(self._log_filter)

        self.log_view = TextEdit(self)
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(350)
        self.log_view.setStyleSheet(get_log_stylesheet())
        log_layout.addWidget(self.log_view)

        layout.addWidget(log_card, 1)
        self._all_log_lines: list[tuple[str, str]] = []  # (text, level)

    def _apply_log_filter(self, text: str):
        """Re-render log_view showing only lines containing filter text."""
        self.log_view.clear()
        for line, level in self._all_log_lines:
            if not text or text.lower() in line.lower():
                self._append_log_html(line, level)

    def _on_wipe_toggled(self, state):
        if self.wipe_check.isChecked():
            self.status_label.setText("🛑 WIPE & REINSTALL — ALL REMOTE DATA WILL BE DESTROYED!")
        else:
            self.status_label.setText("⚠️  Production Update — existing stack only, no data wiped. Target: root@prod.example.com")

    def _on_deploy(self):
        msg = (
            "You are about to start a LIVE deployment to prod.example.com.\n\n"
            "This will build, transfer, and update the application services.\n"
        )
        if self.wipe_check.isChecked():
            msg += "\n🛑 WARNING: NEUINSTALLATION selected!\nTHIS WILL DESTROY ALL DATA ON THE REMOTE HOST!\n- PostgreSQL database\n- Redis data\n- Logs and config\n\n"
        msg += "Proceed?"

        box = MessageBox("Confirm Production Deployment", msg, self)
        if box.exec():
            if self.wipe_check.isChecked():
                import secrets
                from PySide6.QtWidgets import QApplication
                from qfluentwidgets import MessageBoxBase, SubtitleLabel, LineEdit
                
                setup_token = secrets.token_hex(16)
                
                class TokenDialog(MessageBoxBase):
                    def __init__(self, token, parent=None):
                        super().__init__(parent)
                        self.titleLabel = SubtitleLabel("Save Setup Token", self)
                        self.tokenEdit = LineEdit(self)
                        self.tokenEdit.setText(token)
                        self.tokenEdit.setReadOnly(True)
                        self.viewLayout.addWidget(self.titleLabel)
                        self.viewLayout.addWidget(self.tokenEdit)
                        self.yesButton.setText("Copy and Continue")
                        self.cancelButton.setText("Cancel")
                        self.widget.setMinimumWidth(350)
                
                token_box = TokenDialog(setup_token, self)
                if token_box.exec():
                    QApplication.clipboard().setText(setup_token)
                    InfoBar.success("Copied", "Setup token copied to clipboard", parent=self, position=InfoBarPosition.TOP)
                    self._start_worker(setup_token)
                else:
                    return
            else:
                self._start_worker(None)

    def _on_cleanup_request(self):
        box = MessageBox(
            "Confirm Remote Cleanup",
            "This will run 'docker system prune -af' on root@prod.example.com.\n\n"
            "This removes ALL unused containers, networks, and images (including non-dangling ones).\n"
            "Volumes are NOT deleted.\n\n"
            "Proceed?",
            self
        )
        if box.exec():
            self._start_worker_op("cleanup_prod")

    def _start_worker(self, setup_token=None):
        self._last_setup_token = setup_token
        self._start_worker_op("release")

    def _start_worker_op(self, operation: str):
        self.deploy_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.cleanup_btn.setEnabled(False)
        self.retry_btn.setVisible(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.log_view.clear()

        # Store a reference to avoid early garbage collection
        self._active_worker = ProdDeployWorker(
            script_dir.parent, 
            wipe_reinstall=self.wipe_check.isChecked() if operation == "release" else False, 
            setup_token=getattr(self, '_last_setup_token', None) if operation == "release" else None,
            deploy_app=self.deploy_app_check.isChecked() if operation == "release" else False,
            deploy_worker=self.deploy_worker_check.isChecked() if operation == "release" else False,
            deploy_backup=self.deploy_backup_check.isChecked() if operation == "release" else False
        )
        self._active_worker.operation = operation
        self._active_worker.signals.log_message.connect(self._on_log)
        self._active_worker.signals.operation_finished.connect(self._on_finished)
        self._active_worker.signals.progress_update.connect(self._on_progress)
        self._active_worker.finished.connect(self._on_thread_finished)
        self._active_worker.start()

    def _on_progress(self, current: int, total: int, description: str):
        self.progress_bar.setValue(current)
        self.progress_label.setText(description)
        if current > 0 and current < 100:
            self.progress_bar.setVisible(True)
        elif current == 0:
            self.progress_bar.setVisible(False)

    def _on_cancel(self):
        if hasattr(self, '_active_worker') and self._active_worker:
            self._active_worker.cancel()
            self._log("Cancel requested... terminating deployment.", "warning")

    def _on_log(self, message: str, level: str):
        self._log(message, level)

    def _append_log_html(self, message: str, level: str):
        _insert_log_line(self.log_view, message, level)

    def _log(self, message: str, level: str = "info"):
        self._all_log_lines.append((message, level))
        filt = getattr(self, '_log_filter', None)
        if filt is None or not filt.text() or filt.text().lower() in message.lower():
            _insert_log_line(self.log_view, message, level)

    def _clear_logs(self):
        self._all_log_lines.clear()
        self.log_view.clear()

    def _on_finished(self, success: bool, message: str):
        self.deploy_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.cleanup_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.progress_label.setText("Complete" if success else "Failed")
        self._deploy_success = success
        self._deploy_message = message

        if success:
            self._log(message, "success")
        else:
            self._log(message, "error")

    def _on_thread_finished(self):
        """Called after QThread.run() returns — safe to delete worker now."""
        success = getattr(self, '_deploy_success', False)
        message = getattr(self, '_deploy_message', "")
        if success:
            self.retry_btn.setVisible(False)
            self.rollback_btn.setVisible(False)
            InfoBar.success("Deployment Complete", message, parent=self, position=InfoBarPosition.TOP, duration=5000)
        elif message:
            self.retry_btn.setVisible(True)
            self.rollback_btn.setVisible(True)
            InfoBar.error("Deployment Failed", message, parent=self, position=InfoBarPosition.TOP, duration=8000)
        if hasattr(self, '_active_worker') and self._active_worker:
            self._active_worker.deleteLater()
            self._active_worker = None

    def _on_retry(self):
        """Re-run the deployment with same parameters."""
        self.retry_btn.setVisible(False)
        self.rollback_btn.setVisible(False)
        self._start_worker(getattr(self, '_last_setup_token', None))

    def _on_rebuild_tools(self):
        """Build and push the pre-baked yads-tools base image (Dockerfile.tools)."""
        tag = self.tools_tag_input.text().strip() or "1.0"
        box = MessageBox(
            "Rebuild Scanner Tools Base Image",
            f"This will build Dockerfile.tools → yads-tools:{tag} and push it to the registry.\n\n"
            f"This takes 15-20 minutes (Playwright/Chromium download).\n"
            f"Run only when Playwright, Nuclei, or Nmap versions change.\n\n"
            "Proceed?",
            self
        )
        if not box.exec():
            return

        self.rebuild_tools_btn.setEnabled(False)
        self.deploy_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.log_view.clear()
        self._all_log_lines.clear()

        self._active_worker = RebuildToolsWorker(script_dir.parent, tools_tag=tag)
        self._active_worker.signals.log_message.connect(self._on_log)
        self._active_worker.signals.progress_update.connect(self._on_progress)
        self._active_worker.signals.operation_finished.connect(self._on_tools_rebuild_finished)
        self._active_worker.finished.connect(self._on_tools_rebuild_thread_finished)
        self._active_worker.start()

    def _on_tools_rebuild_finished(self, success: bool, message: str):
        self._tools_rebuild_success = success
        self._tools_rebuild_message = message
        if success:
            self._log(message, "success")
        else:
            self._log(message, "error")

    def _on_tools_rebuild_thread_finished(self):
        self.rebuild_tools_btn.setEnabled(True)
        self.deploy_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        success = getattr(self, '_tools_rebuild_success', False)
        message = getattr(self, '_tools_rebuild_message', "")
        if success:
            InfoBar.success("Tools Image Ready", message, parent=self, position=InfoBarPosition.TOP, duration=5000)
        else:
            InfoBar.error("Tools Image Build Failed", message, parent=self, position=InfoBarPosition.TOP, duration=8000)
        if hasattr(self, '_active_worker') and self._active_worker:
            self._active_worker.deleteLater()
            self._active_worker = None

    def _on_rollback(self):
        """Roll back all stack services to their previous image."""
        box = MessageBox(
            "Confirm Rollback",
            "Roll back all YADS services to their previous Docker image?\n\n"
            "This runs: docker service update --rollback <service> for each service.",
            self
        )
        if not box.exec():
            return
        self.rollback_btn.setVisible(False)
        self._log("=== ROLLBACK INITIATED ===", "warning")

        worker = getattr(self, '_active_worker', None)
        services = getattr(worker, 'services_to_update', None) if worker else None
        if not services:
            # Fallback: use known service list
            services = ["yads_yads-api", "yads_yads-worker-primary", "yads_yads-backup"]
        remote_host = getattr(worker, 'remote_host', "root@prod.example.com") if worker else "root@prod.example.com"

        import threading, subprocess as _sp
        def run_rollback():
            for svc in services:
                self._log(f"Rolling back {svc}...", "info")
                r = _sp.run(
                    ["ssh", "-o", "ConnectTimeout=15", remote_host,
                     f"docker service update --rollback {svc}"],
                    capture_output=True, text=True, timeout=60
                )
                if r.returncode == 0:
                    self._log(f"✅ {svc} rolled back", "success")
                else:
                    self._log(f"⚠️  {svc} rollback failed: {r.stderr.strip()}", "warning")
            self._log("=== ROLLBACK COMPLETE ===", "success")
        threading.Thread(target=run_rollback, daemon=True).start()

    def showEvent(self, event):
        super().showEvent(event)
        self._check_ssh()
        self._ssh_check_timer.start()

    def hideEvent(self, event):
        super().hideEvent(event)
        self._ssh_check_timer.stop()

    def _check_ssh(self):
        """Check SSH connectivity to prod host in background."""
        import threading
        def run():
            try:
                result = subprocess.run(
                    ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
                     "root@prod.example.com", "echo", "ok"],
                    capture_output=True, text=True, timeout=8
                )
                ok = result.returncode == 0
            except Exception:
                ok = False
            # Update label from main thread
            QTimer.singleShot(0, lambda: self._update_ssh_status(ok))
        threading.Thread(target=run, daemon=True).start()

    def _update_ssh_status(self, ok: bool):
        if ok:
            self.ssh_status_label.setText("✓ SSH Connected")
            self.ssh_status_label.setStyleSheet("color: #22c55e; font-size: 12px;")
        else:
            self.ssh_status_label.setText("✗ SSH Unreachable")
            self.ssh_status_label.setStyleSheet("color: #ef4444; font-size: 12px;")


class TestLabWorker(QThread):
    """Worker thread for test-lab environment control (init/start/stop/status)"""

    COMPOSE_FILE = "docker-compose.testlab.yml"

    def __init__(self, project_root: Path, action: str):
        super().__init__()
        self.project_root = project_root
        self.action = action
        self.signals = LogSignals()
        self.cancelled = False
        self.current_process = None

    # ── Cancel support ────────────────────────────────────────────────────────
    def cancel(self):
        self.cancelled = True
        if self.current_process:
            try:
                self.current_process.terminate()
            except Exception:
                pass

    def run(self):
        try:
            self._execute()
        except Exception as e:
            self._log(f"Critical error: {e}", "error")
            self.signals.operation_finished.emit(False, str(e))

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _log(self, msg: str, level: str = "info"):
        self.signals.log_message.emit(msg, level)

    def _compose(self, *args) -> list:
        return ["docker", "compose", "-f", self.COMPOSE_FILE] + list(args)

    def _run_cmd(self, cmd: list) -> bool:
        if self.cancelled:
            return False
        self._log(f"▶ {' '.join(cmd)}", "info")
        try:
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(self.project_root),
                bufsize=1,
            )
            for line in self.current_process.stdout:
                if self.cancelled:
                    self.current_process.terminate()
                    break
                cleaned = _ANSI_RE.sub("", line.strip())
                if cleaned:
                    self._log(cleaned, "info")
            self.current_process.wait()
            ok = self.current_process.returncode == 0
            self.current_process = None
            return ok
        except Exception as e:
            self._log(f"Command error: {e}", "error")
            self.current_process = None
            return False

    def _compose_file_exists(self) -> bool:
        p = self.project_root / self.COMPOSE_FILE
        if not p.exists():
            self._log(f"❌  {self.COMPOSE_FILE} not found in {self.project_root}", "error")
            self._log("Run 'Init' first or check your project root.", "warning")
            return False
        return True

    # ── Actions ───────────────────────────────────────────────────────────────
    def _execute(self):
        if self.action == "init":
            self._do_init()
        elif self.action == "start":
            self._do_start()
        elif self.action == "stop":
            self._do_stop()
        elif self.action == "status":
            self._do_status()

    def _do_init(self):
        """Teardown existing testlab, pull images, create containers (no start)."""
        if not self._compose_file_exists():
            return self.signals.operation_finished.emit(False, "Compose file missing")

        self._log("── Init: stopping and removing existing testlab containers ──", "warning")
        self._run_cmd(self._compose("down", "--remove-orphans", "-v"))

        self._log("── Pulling latest images ──", "info")
        ok = self._run_cmd(self._compose("pull"))
        if not ok:
            self._log("Some image pulls failed — may be intentional for local builds.", "warning")

        self._log("── Building custom images (if any) ──", "info")
        self._run_cmd(self._compose("build"))

        self._log("── Creating containers (not started) ──", "info")
        ok = self._run_cmd(self._compose("create"))
        if not ok:
            return self.signals.operation_finished.emit(False, "Container creation failed — check logs")

        self._log("✅  Init complete. Containers are ready. Click Start to launch.", "success")
        self.signals.operation_finished.emit(True, "Test lab initialised")

    def _do_start(self):
        if not self._compose_file_exists():
            return self.signals.operation_finished.emit(False, "Compose file missing")
        self._log("── Starting test-lab containers ──", "info")
        ok = self._run_cmd(self._compose("up", "-d", "--no-build"))
        if ok:
            self._log("✅  Test lab started.", "success")
            self.signals.operation_finished.emit(True, "Test lab started")
        else:
            self.signals.operation_finished.emit(False, "Start failed — run Init first if containers are missing")

    def _do_stop(self):
        if not self._compose_file_exists():
            return self.signals.operation_finished.emit(False, "Compose file missing")
        self._log("── Stopping test-lab containers ──", "info")
        ok = self._run_cmd(self._compose("down"))
        if ok:
            self._log("✅  Test lab stopped.", "success")
            self.signals.operation_finished.emit(True, "Test lab stopped")
        else:
            self.signals.operation_finished.emit(False, "Stop failed")

    def _do_status(self):
        if not self._compose_file_exists():
            return self.signals.operation_finished.emit(False, "Compose file missing")
        self._log("── Test-lab container status ──", "info")
        ok = self._run_cmd(self._compose("ps", "--format", "table"))
        self._log("", "info")
        # Also show network
        self._log("── Docker network ──", "info")
        try:
            result = subprocess.run(
                ["docker", "network", "inspect", "yads-testlab",
                 "--format", "{{.Name}} | Subnet: {{range .IPAM.Config}}{{.Subnet}}{{end}} | Internal: {{.Internal}}"],
                capture_output=True, text=True, cwd=str(self.project_root)
            )
            if result.returncode == 0:
                self._log(result.stdout.strip(), "info")
            else:
                self._log("Network 'yads-testlab' not found — run Init first.", "warning")
        except Exception as e:
            self._log(f"Network inspect error: {e}", "warning")
        if ok:
            self.signals.operation_finished.emit(True, "Status retrieved")
        else:
            self.signals.operation_finished.emit(False, "Status command failed")


class TestLabPage(QWidget):
    """Test-lab environment page — isolated vulnerable targets for scanner validation."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("testLabPage")
        self._active_worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        # ── Title ──
        layout.addWidget(TitleLabel("Test Lab Environment", self))

        info = BodyLabel(
            "Isolated vulnerable target stack for validating all scanner modules.\n"
            "Network: yads-testlab (bridge, no external routing from test containers).\n"
            "⚠  Never expose testlab containers to the internet — for internal testing only.",
            self,
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # ── Container Status Grid ──
        status_card = CardWidget(self)
        status_layout = QVBoxLayout(status_card)
        status_layout.setContentsMargins(20, 16, 20, 16)
        status_layout.setSpacing(8)
        status_layout.addWidget(SubtitleLabel("Included Target Services", self))
        grid_text = BodyLabel(
            "• dvwa.testlab.local          :8080   — DVWA (SQL Injection, XSS, Open Redirect, Cookies)\n"
            "• juice.testlab.local         :3000   — OWASP Juice Shop (API Security, CORS, Missing Auth)\n"
            "• badssl.testlab.local        :4443   — Weak TLS (TLS 1.0, RC4, self-signed, no HSTS)\n"
            "• badheaders.testlab.local    :8081   — Nginx: missing CSP/HSTS/X-Frame-Options, no WAF\n"
            "• graphql.testlab.local       :4000   — GraphQL with introspection + field suggestions\n"
            "• ws.testlab.local            :8765   — WebSocket (ws://, no auth, no origin check)\n"
            "• gitexpose.testlab.local     :8082   — Exposed /.git, /.env, /backup.sql, JS secrets\n"
            "• loginpage.testlab.local     :8083   — Spray surface: /admin, /api/login, /wp-login.php\n"
            "• dns.testlab.local           :53     — CoreDNS (AXFR enabled, CNAME takeover record)\n"
            "• mockapis.testlab.local      :9000   — Mock AbuseIPDB / HIBP / OTX for passive scanners",
            self,
        )
        grid_text.setWordWrap(True)
        grid_text.setFont(QFont("Courier New", 9))
        status_layout.addWidget(grid_text)
        layout.addWidget(status_card)

        # ── Action Buttons ──
        action_card = CardWidget(self)
        action_layout = QHBoxLayout(action_card)
        action_layout.setContentsMargins(20, 20, 20, 20)
        action_layout.setSpacing(16)

        self.init_btn = PrimaryPushButton(FIF.DEVELOPER_TOOLS, "Init", self)
        self.init_btn.setFixedWidth(140)
        self.init_btn.setToolTip("First-time setup or full reset: pulls images, builds custom containers, creates (but does not start) all services.")
        self.init_btn.clicked.connect(lambda: self._on_action("init"))

        self.start_btn = PushButton(FIF.PLAY, "Start", self)
        self.start_btn.setFixedWidth(140)
        self.start_btn.setToolTip("Start all testlab containers. Run Init first if starting for the first time.")
        self.start_btn.clicked.connect(lambda: self._on_action("start"))

        self.stop_btn = PushButton(FIF.POWER_BUTTON, "Stop", self)
        self.stop_btn.setFixedWidth(140)
        self.stop_btn.setToolTip("Stop all testlab containers (data is preserved).")
        self.stop_btn.clicked.connect(lambda: self._on_action("stop"))

        self.status_btn = PushButton(FIF.SEARCH, "Status", self)
        self.status_btn.setFixedWidth(140)
        self.status_btn.setToolTip("Show running containers and network info.")
        self.status_btn.clicked.connect(lambda: self._on_action("status"))

        self.cancel_btn = PushButton(FIF.CLOSE, "Cancel", self)
        self.cancel_btn.setFixedWidth(100)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel)

        for btn in (self.init_btn, self.start_btn, self.stop_btn, self.status_btn, self.cancel_btn):
            action_layout.addWidget(btn)
        action_layout.addStretch()
        layout.addWidget(action_card)

        # ── Worker Network Card ──
        net_card = CardWidget(self)
        net_layout = QHBoxLayout(net_card)
        net_layout.setContentsMargins(20, 14, 20, 14)
        net_layout.setSpacing(16)

        net_info = BodyLabel(
            "Worker network:  connect the running yads-worker container to the testlab network so it can scan targets.",
            self,
        )
        net_info.setWordWrap(True)
        net_layout.addWidget(net_info, 1)

        self.worker_connect_btn = PushButton(FIF.LINK, "Connect Worker", self)
        self.worker_connect_btn.setFixedWidth(160)
        self.worker_connect_btn.setToolTip("docker network connect yads-testlab yads-worker")
        self.worker_connect_btn.clicked.connect(lambda: self._worker_net("connect"))

        self.worker_disconnect_btn = PushButton(FIF.CANCEL_MEDIUM, "Disconnect Worker", self)
        self.worker_disconnect_btn.setFixedWidth(160)
        self.worker_disconnect_btn.setToolTip("docker network disconnect yads-testlab yads-worker")
        self.worker_disconnect_btn.clicked.connect(lambda: self._worker_net("disconnect"))

        net_layout.addWidget(self.worker_connect_btn)
        net_layout.addWidget(self.worker_disconnect_btn)
        layout.addWidget(net_card)

        # ── Progress ──
        self.progress_label = BodyLabel("Ready — no action running.", self)
        layout.addWidget(self.progress_label)

        self.busy_bar = IndeterminateProgressBar(self)
        self.busy_bar.setVisible(False)
        layout.addWidget(self.busy_bar)

        # ── Log View ──
        log_card = CardWidget(self)
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(20, 16, 20, 20)
        log_layout.setSpacing(12)

        log_header = QHBoxLayout()
        log_header.addWidget(SubtitleLabel("Output", self))
        log_header.addStretch()
        clear_btn = TransparentPushButton(FIF.DELETE, "Clear", self)
        clear_btn.clicked.connect(lambda: self.log_view.clear())
        log_header.addWidget(clear_btn)
        log_layout.addLayout(log_header)

        self.log_view = TextEdit(self)
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(280)
        self.log_view.setStyleSheet(get_log_stylesheet())
        log_layout.addWidget(self.log_view)
        layout.addWidget(log_card, 1)

    # ── Slots ─────────────────────────────────────────────────────────────────
    def _on_action(self, action: str):
        if action == "init":
            msg = (
                "Init will:\n"
                "  1. Stop and REMOVE all existing testlab containers + volumes\n"
                "  2. Pull latest images\n"
                "  3. Build custom test services\n"
                "  4. Create containers (not started)\n\n"
                "Use this for first-time setup or to recover a broken environment.\n\n"
                "Proceed?"
            )
            box = MessageBox("Init Test Lab", msg, self)
            if not box.exec():
                return
        elif action in ("start", "stop", "status"):
            pass  # no confirmation needed
        self._start_worker(action)

    def _start_worker(self, action: str):
        from pathlib import Path as _Path
        project_root = _Path(__file__).parent.parent
        self._active_worker = TestLabWorker(project_root, action)
        self._active_worker.signals.log_message.connect(self._on_log)
        self._active_worker.signals.operation_finished.connect(self._on_finished)
        self._active_worker.finished.connect(self._active_worker.deleteLater)
        self._set_busy(True, action)
        self.log_view.clear()
        self._active_worker.start()

    def _on_cancel(self):
        if self._active_worker:
            self._active_worker.cancel()
            self._log("Cancel requested…", "warning")

    def _on_log(self, msg: str, level: str):
        _insert_log_line(self.log_view, msg, level)

    def _log(self, msg: str, level: str = "info"):
        _insert_log_line(self.log_view, msg, level)

    def _on_finished(self, success: bool, message: str):
        self._set_busy(False)
        self._active_worker = None
        if success:
            InfoBar.success("Done", message, parent=self, position=InfoBarPosition.TOP, duration=5000)
        else:
            InfoBar.error("Error", message, parent=self, position=InfoBarPosition.TOP, duration=8000)

    def _worker_net(self, action: str):
        """Connect or disconnect yads-worker from the yads-testlab network."""
        container = "yads-worker"
        network = "yads-testlab"
        cmd = ["docker", "network", action, network, container]
        self._log(f"▶ {' '.join(cmd)}", "info")
        self.worker_connect_btn.setEnabled(False)
        self.worker_disconnect_btn.setEnabled(False)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                verb = "connected to" if action == "connect" else "disconnected from"
                self._log(f"✅ Worker {verb} {network}", "success")
                InfoBar.success("Done", f"Worker {verb} {network}",
                                parent=self, position=InfoBarPosition.TOP, duration=4000)
            else:
                msg = (result.stderr.strip() or result.stdout.strip()) or f"exit code {result.returncode}"
                self._log(f"❌ {msg}", "error")
                InfoBar.error("Failed", msg, parent=self, position=InfoBarPosition.TOP, duration=6000)
        except Exception as e:
            self._log(f"Error: {e}", "error")
            InfoBar.error("Error", str(e), parent=self, position=InfoBarPosition.TOP, duration=6000)
        finally:
            self.worker_connect_btn.setEnabled(True)
            self.worker_disconnect_btn.setEnabled(True)

    def _set_busy(self, busy: bool, action: str = ""):
        for btn in (self.init_btn, self.start_btn, self.stop_btn, self.status_btn,
                    self.worker_connect_btn, self.worker_disconnect_btn):
            btn.setEnabled(not busy)
        self.cancel_btn.setEnabled(busy)
        self.busy_bar.setVisible(busy)
        if busy:
            self.busy_bar.start()
            self.progress_label.setText(f"Running: {action}…")
        else:
            self.busy_bar.stop()
            self.progress_label.setText("Ready")


class DanaDeployWorker(QThread):
    """Worker thread for deploying/controlling the YADS test environment on dana via SSH."""

    def __init__(self, action: str, ssh_host: str, ssh_user: str, ssh_port: str,
                 ssh_key: str, remote_path: str, project_root: Path):
        super().__init__()
        self.action = action
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.ssh_port = ssh_port or "22"
        self.ssh_key = ssh_key
        self.remote_path = remote_path.rstrip("/") or "~/yads-testenv"
        self.project_root = project_root
        self.signals = LogSignals()
        self.cancelled = False

    def cancel(self):
        self.cancelled = True

    def run(self):
        try:
            self._execute()
        except Exception as e:
            self.signals.log_message.emit(f"Critical error: {e}", "error")
            self.signals.operation_finished.emit(False, str(e))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _log(self, msg: str, level: str = "info"):
        self.signals.log_message.emit(msg, level)

    @property
    def _remote(self):
        return f"{self.ssh_user}@{self.ssh_host}"

    def _ssh_opts(self) -> list:
        opts = [
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-o", "StrictHostKeyChecking=accept-new",
            "-p", self.ssh_port,
        ]
        if self.ssh_key:
            opts += ["-i", str(Path(self.ssh_key).expanduser())]
        return opts

    def _run_ssh(self, command: str) -> bool:
        if self.cancelled:
            return False
        cmd = ["ssh"] + self._ssh_opts() + [self._remote, command]
        self._log(f"▶ {self._remote}: {command}", "info")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                if self.cancelled:
                    proc.terminate()
                    break
                cleaned = _ANSI_RE.sub("", line.strip())
                if cleaned:
                    self._log(cleaned, "info")
            proc.wait()
            return proc.returncode == 0
        except Exception as e:
            self._log(f"SSH error: {e}", "error")
            return False

    def _run_rsync(self, local_src: str, remote_dest: str) -> bool:
        if self.cancelled:
            return False
        rsync_ssh = "ssh " + " ".join(self._ssh_opts())
        cmd = ["rsync", "-avz", "--progress", "-e", rsync_ssh,
               local_src, f"{self._remote}:{remote_dest}"]
        self._log(f"▶ rsync {local_src} → {self._remote}:{remote_dest}", "info")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                if self.cancelled:
                    proc.terminate()
                    break
                cleaned = _ANSI_RE.sub("", line.strip())
                if cleaned:
                    self._log(cleaned, "info")
            proc.wait()
            return proc.returncode == 0
        except FileNotFoundError:
            self._log("rsync not found, falling back to scp…", "warning")
            return self._run_scp(local_src, remote_dest)
        except Exception as e:
            self._log(f"rsync error: {e}", "error")
            return False

    def _run_scp(self, local_src: str, remote_dest: str) -> bool:
        cmd = ["scp"] + self._ssh_opts() + [local_src, f"{self._remote}:{remote_dest}"]
        self._log(f"▶ scp {local_src} → {self._remote}:{remote_dest}", "info")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.stdout.strip():
                self._log(result.stdout.strip(), "info")
            return result.returncode == 0
        except Exception as e:
            self._log(f"scp error: {e}", "error")
            return False

    # ── Actions ───────────────────────────────────────────────────────────────

    def _execute(self):
        if self.action == "deploy":
            self._do_deploy()
        elif self.action == "start":
            self._do_start()
        elif self.action == "stop":
            self._do_stop()
        elif self.action == "status":
            self._do_status()
        else:
            self.signals.operation_finished.emit(False, f"Unknown action: {self.action}")

    def _do_deploy(self):
        self._log("── Step 1: Ensure remote directory ──", "info")
        if not self._run_ssh(f"mkdir -p {self.remote_path}"):
            return self.signals.operation_finished.emit(False, "Could not create remote directory")

        compose_src = str(self.project_root / "docker-compose.testlab.yml")
        if not Path(compose_src).exists():
            self._log(f"❌ docker-compose.testlab.yml not found at {compose_src}", "error")
            return self.signals.operation_finished.emit(
                False, "docker-compose.testlab.yml not found locally — create it first"
            )

        self._log("── Step 2: Transfer docker-compose.testlab.yml ──", "info")
        if not self._run_rsync(compose_src, self.remote_path + "/"):
            return self.signals.operation_finished.emit(False, "File transfer failed")

        testlab_dir = self.project_root / "testlab"
        if testlab_dir.exists():
            self._log("── Step 2b: Transfer testlab/ build contexts ──", "info")
            # trailing slash on src = sync contents into remote testlab/
            if not self._run_rsync(str(testlab_dir) + "/", self.remote_path + "/testlab/"):
                return self.signals.operation_finished.emit(False, "testlab/ transfer failed")
        else:
            self._log("⚠ testlab/ directory not found locally — custom builds may fail.", "warning")

        env_src = str(self.project_root / ".env.test")
        if Path(env_src).exists():
            self._log("── Step 2c: Transfer .env.test ──", "info")
            self._run_rsync(env_src, self.remote_path + "/")

        self._log("── Step 3: Pull images on dana ──", "info")
        self._run_ssh(
            f"cd {self.remote_path} && docker compose -f docker-compose.testlab.yml pull"
        )

        self._log("── Step 4: Start services on dana ──", "info")
        ok = self._run_ssh(
            f"cd {self.remote_path} && docker compose -f docker-compose.testlab.yml up -d --remove-orphans"
        )
        if ok:
            self._log("✅  Test environment deployed and started on dana.", "success")
            self.signals.operation_finished.emit(True, "Deployed to dana successfully")
        else:
            self.signals.operation_finished.emit(False, "docker compose up failed on dana")

    def _do_start(self):
        self._log("── Starting test environment on dana ──", "info")
        ok = self._run_ssh(
            f"cd {self.remote_path} && docker compose -f docker-compose.testlab.yml up -d"
        )
        if ok:
            self._log("✅  Test environment started on dana.", "success")
            self.signals.operation_finished.emit(True, "Test environment started on dana")
        else:
            self.signals.operation_finished.emit(
                False, "Start failed — run Deploy first if not yet deployed"
            )

    def _do_stop(self):
        self._log("── Stopping test environment on dana ──", "info")
        ok = self._run_ssh(
            f"cd {self.remote_path} && docker compose -f docker-compose.testlab.yml down"
        )
        if ok:
            self._log("✅  Test environment stopped on dana.", "success")
            self.signals.operation_finished.emit(True, "Test environment stopped on dana")
        else:
            self.signals.operation_finished.emit(False, "Stop failed")

    def _do_status(self):
        self._log("── Container status on dana ──", "info")
        self._run_ssh(
            f"cd {self.remote_path} && docker compose -f docker-compose.testlab.yml ps"
        )
        self._log("── Resource usage ──", "info")
        self._run_ssh(
            "docker stats --no-stream "
            "--format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' 2>/dev/null | head -20"
        )
        self.signals.operation_finished.emit(True, "Status retrieved")


class DanaDeployPage(QWidget):
    """Deploy and control the YADS test environment on the dana server."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("danaDeployPage")
        self._active_worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        layout.addWidget(TitleLabel("Test Env · Dana", self))

        info = BodyLabel(
            "Deploy and manage the YADS test environment on the dana server via SSH.\n"
            "Uses docker-compose.testlab.yml from the project root.",
            self,
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # ── SSH Connection Card ──
        conn_card = CardWidget(self)
        conn_layout = QVBoxLayout(conn_card)
        conn_layout.setContentsMargins(20, 16, 20, 16)
        conn_layout.setSpacing(10)
        conn_layout.addWidget(SubtitleLabel("SSH Connection", self))

        row1 = QHBoxLayout()
        row1.addWidget(BodyLabel("Host:", self))
        self.host_edit = LineEdit(self)
        self.host_edit.setPlaceholderText("dana or dana.lan.example.internal")
        self.host_edit.setFixedWidth(220)
        row1.addWidget(self.host_edit)
        row1.addSpacing(12)
        row1.addWidget(BodyLabel("Port:", self))
        self.port_edit = LineEdit(self)
        self.port_edit.setText("22")
        self.port_edit.setFixedWidth(60)
        row1.addWidget(self.port_edit)
        row1.addSpacing(12)
        row1.addWidget(BodyLabel("User:", self))
        self.user_edit = LineEdit(self)
        self.user_edit.setPlaceholderText("root")
        self.user_edit.setFixedWidth(120)
        row1.addWidget(self.user_edit)
        row1.addStretch()
        conn_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(BodyLabel("Key File:", self))
        self.key_edit = LineEdit(self)
        self.key_edit.setPlaceholderText("~/.ssh/id_rsa  (leave empty for default)")
        self.key_edit.setMinimumWidth(260)
        row2.addWidget(self.key_edit)
        row2.addSpacing(12)
        row2.addWidget(BodyLabel("Remote Path:", self))
        self.path_edit = LineEdit(self)
        self.path_edit.setPlaceholderText("~/yads-testenv")
        self.path_edit.setFixedWidth(200)
        row2.addWidget(self.path_edit)
        row2.addStretch()
        conn_layout.addLayout(row2)

        row3 = QHBoxLayout()
        save_btn = PushButton(FIF.SAVE, "Save", self)
        save_btn.setFixedWidth(100)
        save_btn.clicked.connect(self._save_connection)
        row3.addWidget(save_btn)
        row3.addSpacing(16)
        self.ssh_status_label = BodyLabel("○ Not checked", self)
        self.ssh_status_label.setStyleSheet("color: gray; font-size: 12px;")
        row3.addWidget(self.ssh_status_label)
        row3.addStretch()
        check_btn = PushButton(FIF.SYNC, "Test SSH", self)
        check_btn.setFixedWidth(100)
        check_btn.clicked.connect(self._check_ssh)
        row3.addWidget(check_btn)
        conn_layout.addLayout(row3)

        layout.addWidget(conn_card)

        # ── Action Buttons ──
        action_card = CardWidget(self)
        action_layout = QHBoxLayout(action_card)
        action_layout.setContentsMargins(20, 20, 20, 20)
        action_layout.setSpacing(16)

        self.deploy_btn = PrimaryPushButton(FIF.SEND, "Deploy & Start", self)
        self.deploy_btn.setFixedWidth(160)
        self.deploy_btn.setToolTip(
            "Transfer docker-compose.testlab.yml to dana and start all test services."
        )
        self.deploy_btn.clicked.connect(lambda: self._on_action("deploy"))

        self.start_btn = PushButton(FIF.PLAY, "Start", self)
        self.start_btn.setFixedWidth(120)
        self.start_btn.setToolTip("Start already-deployed services on dana.")
        self.start_btn.clicked.connect(lambda: self._on_action("start"))

        self.stop_btn = PushButton(FIF.POWER_BUTTON, "Stop", self)
        self.stop_btn.setFixedWidth(120)
        self.stop_btn.setToolTip("Stop all test services on dana (data preserved).")
        self.stop_btn.clicked.connect(lambda: self._on_action("stop"))

        self.status_btn = PushButton(FIF.SEARCH, "Status", self)
        self.status_btn.setFixedWidth(120)
        self.status_btn.setToolTip("Show running containers and resource usage on dana.")
        self.status_btn.clicked.connect(lambda: self._on_action("status"))

        self.cancel_btn = PushButton(FIF.CLOSE, "Cancel", self)
        self.cancel_btn.setFixedWidth(100)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel)

        for btn in (self.deploy_btn, self.start_btn, self.stop_btn,
                    self.status_btn, self.cancel_btn):
            action_layout.addWidget(btn)
        action_layout.addStretch()
        layout.addWidget(action_card)

        # ── Progress ──
        self.progress_label = BodyLabel("Ready", self)
        layout.addWidget(self.progress_label)

        self.busy_bar = IndeterminateProgressBar(self)
        self.busy_bar.setVisible(False)
        layout.addWidget(self.busy_bar)

        # ── Log View ──
        log_card = CardWidget(self)
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(20, 16, 20, 20)
        log_layout.setSpacing(12)

        log_header = QHBoxLayout()
        log_header.addWidget(SubtitleLabel("Output", self))
        log_header.addStretch()
        clear_btn = TransparentPushButton(FIF.DELETE, "Clear", self)
        clear_btn.clicked.connect(lambda: self.log_view.clear())
        log_header.addWidget(clear_btn)
        log_layout.addLayout(log_header)

        self.log_view = TextEdit(self)
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(280)
        self.log_view.setStyleSheet(get_log_stylesheet())
        log_layout.addWidget(self.log_view)
        layout.addWidget(log_card, 1)

        self._load_connection()

        # Periodic SSH reachability check (60 s)
        self._ssh_timer = QTimer(self)
        self._ssh_timer.setInterval(60000)
        self._ssh_timer.timeout.connect(self._check_ssh)

    # ── Config persistence ────────────────────────────────────────────────────

    def _config_path(self) -> Path:
        return Path.home() / ".yads" / "release_gui.yaml"

    def _load_connection(self):
        p = self._config_path()
        if not p.exists():
            return
        try:
            import yaml
            with open(p) as f:
                d = yaml.safe_load(f) or {}
            self.host_edit.setText(d.get("dana_host", ""))
            self.port_edit.setText(str(d.get("dana_port", "22")))
            self.user_edit.setText(d.get("dana_user", "root"))
            self.key_edit.setText(d.get("dana_key", ""))
            self.path_edit.setText(d.get("dana_remote_path", "~/yads-testenv"))
        except Exception:
            pass

    def _save_connection(self):
        import yaml
        p = self._config_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        data: dict = {}
        if p.exists():
            try:
                with open(p) as f:
                    data = yaml.safe_load(f) or {}
            except Exception:
                pass
        data["dana_host"] = self.host_edit.text().strip()
        data["dana_port"] = self.port_edit.text().strip() or "22"
        data["dana_user"] = self.user_edit.text().strip() or "root"
        data["dana_key"] = self.key_edit.text().strip()
        data["dana_remote_path"] = self.path_edit.text().strip() or "~/yads-testenv"
        try:
            with open(p, "w") as f:
                yaml.dump(data, f)
            InfoBar.success("Saved", "Dana connection settings saved.",
                            parent=self, position=InfoBarPosition.TOP, duration=3000)
        except Exception as e:
            InfoBar.error("Error", str(e), parent=self, position=InfoBarPosition.TOP)

    # ── SSH reachability ──────────────────────────────────────────────────────

    def _check_ssh(self):
        host = self.host_edit.text().strip()
        if not host:
            self.ssh_status_label.setText("⚠ No host configured")
            self.ssh_status_label.setStyleSheet("color: orange; font-size: 12px;")
            InfoBar.warning("No Host", "Enter a hostname before testing SSH.",
                            parent=self, position=InfoBarPosition.TOP, duration=4000)
            return
        user = self.user_edit.text().strip() or "root"
        port = self.port_edit.text().strip() or "22"
        key = self.key_edit.text().strip()
        self.ssh_status_label.setText("○ Checking…")
        self.ssh_status_label.setStyleSheet("color: gray; font-size: 12px;")
        self._log(f"Testing SSH connection to {user}@{host}:{port} …", "info")

        opts = ["-o", "ConnectTimeout=5", "-o", "BatchMode=yes", "-p", port]
        if key:
            opts += ["-i", str(Path(key).expanduser())]

        import threading
        def run():
            stderr_out = ""
            try:
                r = subprocess.run(
                    ["ssh"] + opts + [f"{user}@{host}", "echo ok"],
                    capture_output=True, text=True, timeout=8,
                )
                ok = r.returncode == 0
                stderr_out = r.stderr.strip()
            except Exception as e:
                ok = False
                stderr_out = str(e)
            QTimer.singleShot(0, lambda: self._update_ssh_status(ok, host, stderr_out))
        threading.Thread(target=run, daemon=True).start()

    def _update_ssh_status(self, ok: bool, host: str = "", detail: str = ""):
        if ok:
            self.ssh_status_label.setText("✓ SSH Connected")
            self.ssh_status_label.setStyleSheet("color: #22c55e; font-size: 12px;")
            self._log(f"✅ SSH connection to {host} successful.", "success")
            InfoBar.success("SSH OK", f"Connected to {host}",
                            parent=self, position=InfoBarPosition.TOP, duration=4000)
        else:
            self.ssh_status_label.setText("✗ SSH Unreachable")
            self.ssh_status_label.setStyleSheet("color: #ef4444; font-size: 12px;")
            msg = f"Cannot reach {host}" + (f": {detail}" if detail else "")
            self._log(f"❌ {msg}", "error")
            InfoBar.error("SSH Failed", msg[:120],
                          parent=self, position=InfoBarPosition.TOP, duration=6000)

    def showEvent(self, event):
        super().showEvent(event)
        self._check_ssh()
        self._ssh_timer.start()

    def hideEvent(self, event):
        super().hideEvent(event)
        self._ssh_timer.stop()

    # ── Action dispatch ───────────────────────────────────────────────────────

    def _on_action(self, action: str):
        host = self.host_edit.text().strip()
        if not host:
            InfoBar.warning("No Host", "Configure a dana hostname first.",
                            parent=self, position=InfoBarPosition.TOP)
            return
        if action == "deploy":
            box = MessageBox(
                "Deploy to Dana",
                f"Transfer docker-compose.testlab.yml to {host} and start all test services.\n\nProceed?",
                self,
            )
            if not box.exec():
                return
        elif action == "stop":
            box = MessageBox(
                "Stop Test Env on Dana",
                f"Stop all test services on {host}?\n(Data is preserved.)",
                self,
            )
            if not box.exec():
                return
        self._start_worker(action)

    def _start_worker(self, action: str):
        from pathlib import Path as _Path
        project_root = _Path(__file__).parent.parent
        self._active_worker = DanaDeployWorker(
            action=action,
            ssh_host=self.host_edit.text().strip(),
            ssh_user=self.user_edit.text().strip() or "root",
            ssh_port=self.port_edit.text().strip() or "22",
            ssh_key=self.key_edit.text().strip(),
            remote_path=self.path_edit.text().strip() or "~/yads-testenv",
            project_root=project_root,
        )
        self._active_worker.signals.log_message.connect(self._on_log)
        self._active_worker.signals.operation_finished.connect(self._on_finished)
        self._active_worker.finished.connect(self._active_worker.deleteLater)
        self._set_busy(True, action)
        self.log_view.clear()
        self._active_worker.start()

    def _on_cancel(self):
        if self._active_worker:
            self._active_worker.cancel()
            self._log("Cancel requested…", "warning")

    def _on_log(self, msg: str, level: str):
        _insert_log_line(self.log_view, msg, level)

    def _log(self, msg: str, level: str = "info"):
        _insert_log_line(self.log_view, msg, level)

    def _on_finished(self, success: bool, message: str):
        self._set_busy(False)
        self._active_worker = None
        if success:
            InfoBar.success("Done", message, parent=self,
                            position=InfoBarPosition.TOP, duration=5000)
        else:
            InfoBar.error("Error", message, parent=self,
                          position=InfoBarPosition.TOP, duration=8000)

    def _set_busy(self, busy: bool, action: str = ""):
        for btn in (self.deploy_btn, self.start_btn, self.stop_btn, self.status_btn):
            btn.setEnabled(not busy)
        self.cancel_btn.setEnabled(busy)
        self.busy_bar.setVisible(busy)
        if busy:
            self.busy_bar.start()
            self.progress_label.setText(f"Running: {action}…")
        else:
            self.busy_bar.stop()
            self.progress_label.setText("Ready")


class LocalDeployWorker(QThread):
    """Worker thread for local environment controls"""
    def __init__(self, project_root: Path, action: str, wipe_data: bool = False, setup_token: str = None, auth_mode: str = "local", profiles: list = None):
        super().__init__()
        self.project_root = project_root
        self.action = action
        self.wipe_data = wipe_data
        self.setup_token = setup_token
        self.auth_mode = auth_mode
        self.profiles = profiles or []
        self.signals = LogSignals()
        self.cancelled = False
        self.current_process = None

    def run(self):
        try:
            self._execute_action()
        except Exception as e:
            self._log(f"Critical error: {e}", "error")
            self.signals.operation_finished.emit(False, str(e))

    def cancel(self):
        self.cancelled = True
        if self.current_process:
            try:
                self.current_process.terminate()
            except:
                pass

    def _log(self, message: str, level: str = "info"):
        self.signals.log_message.emit(message, level)

    def _run_cmd(self, cmd: list, shell=False) -> bool:
        if self.cancelled: return False
        self._log(f"Running: {' '.join(cmd) if not shell else cmd}", "info")
        try:
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                shell=shell,
                cwd=str(self.project_root),
                bufsize=1,
                universal_newlines=True
            )
            for line in self.current_process.stdout:
                if self.cancelled:
                    self.current_process.terminate()
                    break
                self._log(line.strip(), "info")
            self.current_process.wait()
            return self.current_process.returncode == 0
        except Exception as e:
            self._log(f"Error executing command: {e}", "error")
            return False
        finally:
            self.current_process = None

    def _profile_flags(self) -> list:
        """Build --profile flags for active profiles."""
        flags = []
        for p in self.profiles:
            flags += ["--profile", p]
        return flags

    def _update_env(self, key: str, value: str):
        """Write or update a key=value line in .env."""
        env_path = self.project_root / ".env"
        lines = env_path.read_text().splitlines() if env_path.exists() else []
        lines = [l for l in lines if not l.startswith(f"{key}=")]
        lines.append(f"{key}={value}")
        env_path.write_text("\n".join(lines) + "\n")

    def _execute_action(self):
        self.signals.progress_update.emit(0, 100, f"Starting local {self.action}...")

        profile_flags = self._profile_flags()
        profile_info = f" (profiles: {', '.join(self.profiles)})" if self.profiles else " (core only)"

        if self.action == "start":
            self._log(f"Starting local environment{profile_info}...", "info")

            if self.wipe_data:
                self._log("Wiping volumes (Neuinstallation) first...", "warning")
                # Down with all known profiles so every container is included
                self._run_cmd(["docker", "compose", "--profile", "keycloak", "--profile", "monitoring", "down", "-v"])
                self._run_cmd(["docker", "volume", "rm", "--force", "yads_nuclei_templates"])
                self._log("Resetting data/config.env for fresh setup...", "info")
                self._run_cmd([
                    "docker", "run", "--rm",
                    "-v", f"{self.project_root}/data:/data",
                    "alpine", "sh", "-c", "rm -f /data/config.env"
                ])

            if self.setup_token:
                self._log("Injecting SETUP_TOKEN into .env...", "info")
                self._update_env("SETUP_TOKEN", self.setup_token)

            self._log(f"Setting AUTH_MODE={self.auth_mode} in .env...", "info")
            self._update_env("AUTH_MODE", self.auth_mode)

            profiles_val = ",".join(self.profiles) if self.profiles else ""
            self._update_env("COMPOSE_PROFILES", profiles_val)
            self._log(f"COMPOSE_PROFILES={profiles_val or '(none)'}", "info")

            # Sanity-check: warn if critical vars are missing from .env
            _required = ["POSTGRES_PASSWORD", "SUPPORT_ADMIN_TOKEN", "WORKER_REGISTRATION_TOKEN"]
            env_path = self.project_root / ".env"
            env_content = env_path.read_text() if env_path.exists() else ""
            _missing = [k for k in _required if not any(l.startswith(f"{k}=") for l in env_content.splitlines())]
            if _missing:
                self._log(f"⚠️  Missing critical .env vars: {', '.join(_missing)} — Swarm/prod may fail!", "warning")

            build_cmd = ["docker", "compose"] + profile_flags + ["build"]
            up_cmd    = ["docker", "compose"] + profile_flags + ["up", "-d"]

            self._log("Building containers...", "info")
            if not self._run_cmd(build_cmd):
                return self.signals.operation_finished.emit(False, "Build failed")

            self._log("Starting services...", "info")
            if not self._run_cmd(up_cmd):
                return self.signals.operation_finished.emit(False, "Start failed")

            self.signals.operation_finished.emit(True, f"Local environment started{profile_info}")

        elif self.action == "stop":
            self._log(f"Stopping local environment{profile_info}...", "info")
            # Always stop ALL profiles so no containers are left behind
            down_cmd = ["docker", "compose",
                        "--profile", "keycloak",
                        "--profile", "monitoring",
                        "down"]
            if self.wipe_data:
                self._log("Will wipe data volumes...", "warning")
                down_cmd.append("-v")

            if not self._run_cmd(down_cmd):
                return self.signals.operation_finished.emit(False, "Stop failed")

            msg = "Local environment stopped and wiped" if self.wipe_data else "Local environment stopped"
            self.signals.operation_finished.emit(True, msg)


class LocalDeployPage(QWidget):
    """Local deployment page for dev environment management"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("localDeployPage")
        self.worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        # Title
        title = TitleLabel("Local Environment", self)
        layout.addWidget(title)

        self.status_label = BodyLabel(
            "ℹ️  Local Docker Compose — manages your local development stack.", self
        )
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.wipe_check = CheckBox("Wipe Data (NEUINSTALLATION / DELETE VOLUMES)", self)
        self.wipe_check.setToolTip("WARNING: This removes all local db data upon start/stop!")
        self.wipe_check.stateChanged.connect(self._on_wipe_toggled)
        layout.addWidget(self.wipe_check)

        # SSO / Auth Mode Toggle
        auth_row = QHBoxLayout()
        auth_row.setSpacing(12)
        self.oidc_switch = SwitchButton(self)
        self.oidc_switch.setChecked(False)
        self.oidc_switch.setOnText("SSO aktiv (AUTH_MODE=oidc)")
        self.oidc_switch.setOffText("Lokale Anmeldung (AUTH_MODE=local)")
        self.oidc_switch.checkedChanged.connect(self._on_oidc_toggled)
        auth_row.addWidget(self.oidc_switch)
        auth_row.addStretch()
        layout.addLayout(auth_row)

        # Docker Compose Profile Toggles
        profile_card = CardWidget(self)
        profile_layout = QVBoxLayout(profile_card)
        profile_layout.setContentsMargins(20, 12, 20, 12)
        profile_layout.setSpacing(8)
        profile_layout.addWidget(StrongBodyLabel("Docker Compose Profile", self))

        profile_row = QHBoxLayout()
        profile_row.setSpacing(24)
        self.profile_keycloak = CheckBox("Keycloak / SSO", self)
        self.profile_monitoring = CheckBox("Monitoring (Grafana · Prometheus · Loki · MinIO)", self)
        profile_row.addWidget(self.profile_keycloak)
        profile_row.addWidget(self.profile_monitoring)
        profile_row.addStretch()
        profile_layout.addLayout(profile_row)

        layout.addWidget(profile_card)
        self._load_profiles_from_env()

        # Action Card
        action_card = CardWidget(self)
        action_layout = QHBoxLayout(action_card)
        action_layout.setContentsMargins(20, 20, 20, 20)
        action_layout.setSpacing(16)

        self.start_btn = PrimaryPushButton(FIF.PLAY, "Start Environment", self)
        self.start_btn.setFixedWidth(200)
        self.start_btn.clicked.connect(lambda: self._on_action("start"))
        action_layout.addWidget(self.start_btn)

        self.stop_btn = PushButton(FIF.POWER_BUTTON, "Stop Environment", self)
        self.stop_btn.setFixedWidth(200)
        self.stop_btn.clicked.connect(lambda: self._on_action("stop"))
        action_layout.addWidget(self.stop_btn)

        self.cancel_btn = PushButton(FIF.CLOSE, "Cancel", self)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel)
        action_layout.addWidget(self.cancel_btn)

        action_layout.addStretch()
        layout.addWidget(action_card)

        # Progress
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(4)
        
        self.progress_label = BodyLabel("Ready", self)
        progress_layout.addWidget(self.progress_label)
        
        self.progress_bar = ProgressBar(self)
        self.progress_bar.setValue(0)
        self.progress_bar.setMinimumHeight(16)
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        self.indeterminate_progress = IndeterminateProgressBar(self)
        self.indeterminate_progress.setVisible(False)
        progress_layout.addWidget(self.indeterminate_progress)
        
        layout.addLayout(progress_layout)

        # Log Card
        log_card = CardWidget(self)
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(20, 16, 20, 20)
        log_layout.setSpacing(12)

        log_header = QHBoxLayout()
        log_title = SubtitleLabel("Execution Logs", self)
        log_header.addWidget(log_title)
        log_header.addStretch()

        clear_btn = TransparentPushButton(FIF.DELETE, "Clear", self)
        clear_btn.clicked.connect(self._clear_logs)
        log_header.addWidget(clear_btn)
        log_layout.addLayout(log_header)

        self.log_view = TextEdit(self)
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(300)
        self.log_view.setStyleSheet(get_log_stylesheet())
        log_layout.addWidget(self.log_view)

        layout.addWidget(log_card, 1)

    def _on_wipe_toggled(self, state):
        if self.wipe_check.isChecked():
            self.status_label.setText("🛑 WIPE aktiv — lokale Datenbank wird beim Start/Stop gelöscht!")
        else:
            self.status_label.setText("ℹ️  Local Docker Compose — manages your local development stack.")

    def _load_profiles_from_env(self):
        """Pre-populate profile checkboxes from COMPOSE_PROFILES in .env."""
        env_path = script_dir.parent / ".env"
        if not env_path.exists():
            return
        for line in env_path.read_text().splitlines():
            if line.startswith("COMPOSE_PROFILES="):
                val = line.split("=", 1)[1].strip()
                profiles = [p.strip() for p in val.split(",") if p.strip()]
                self.profile_keycloak.setChecked("keycloak" in profiles)
                self.profile_monitoring.setChecked("monitoring" in profiles)
                break

    def _active_profiles(self) -> list:
        profiles = []
        if self.profile_keycloak.isChecked():
            profiles.append("keycloak")
        if self.profile_monitoring.isChecked():
            profiles.append("monitoring")
        return profiles

    def _on_oidc_toggled(self, checked: bool):
        if checked:
            InfoBar.info("SSO aktiviert", "AUTH_MODE=oidc wird beim nächsten Start gesetzt. Keycloak muss laufen.", parent=self, position=InfoBarPosition.TOP)
        else:
            InfoBar.info("Lokale Anmeldung", "AUTH_MODE=local wird beim nächsten Start gesetzt.", parent=self, position=InfoBarPosition.TOP)

    def _on_action(self, action: str):
        msg = f"You are about to {action} the local Docker environment.\n\n"
        if self.wipe_check.isChecked():
            msg += "🛑 WARNING: NEUINSTALLATION selected!\nTHIS WILL DESTROY ALL LOCAL DATA VOLUMES!\n\n"
        msg += "Proceed?"

        box = MessageBox(f"Confirm Local {action.title()}", msg, self)
        if box.exec():
            setup_token = None
            if action == "start" and self.wipe_check.isChecked():
                import secrets
                from PySide6.QtWidgets import QApplication
                from qfluentwidgets import MessageBoxBase, SubtitleLabel, LineEdit as _LineEdit

                setup_token = secrets.token_hex(16)

                class TokenDialog(MessageBoxBase):
                    def __init__(self, token, parent=None):
                        super().__init__(parent)
                        self.titleLabel = SubtitleLabel("Save Setup Token", self)
                        self.tokenEdit = _LineEdit(self)
                        self.tokenEdit.setText(token)
                        self.tokenEdit.setReadOnly(True)
                        self.viewLayout.addWidget(self.titleLabel)
                        self.viewLayout.addWidget(self.tokenEdit)
                        self.yesButton.setText("Copy and Continue")
                        self.cancelButton.setText("Cancel")
                        self.widget.setMinimumWidth(350)

                token_box = TokenDialog(setup_token, self)
                if token_box.exec():
                    QApplication.clipboard().setText(setup_token)
                    InfoBar.success("Copied", "Setup token copied to clipboard", parent=self, position=InfoBarPosition.TOP)
                else:
                    return
            # Disk space check before starting a build
            if action == "start":
                import shutil
                free_bytes = shutil.disk_usage("/").free
                free_gb = free_bytes / (1024 ** 3)
                if free_gb < 5.0:
                    warn_box = MessageBox(
                        "Low Disk Space",
                        f"Only {free_gb:.1f} GB free on /.\nDocker builds may fail. Continue anyway?",
                        self
                    )
                    if not warn_box.exec():
                        return
            self._start_worker(action, setup_token)

    def _start_worker(self, action: str, setup_token=None):
        self._last_action = action
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.indeterminate_progress.setVisible(True)
        self.indeterminate_progress.start()
        self.log_view.clear()

        auth_mode = "oidc" if self.oidc_switch.isChecked() else "local"
        self._active_worker = LocalDeployWorker(script_dir.parent, action, wipe_data=self.wipe_check.isChecked(), setup_token=setup_token, auth_mode=auth_mode, profiles=self._active_profiles())
        self._active_worker.signals.log_message.connect(self._on_log)
        self._active_worker.signals.operation_finished.connect(self._on_finished)
        self._active_worker.start()

    def _on_cancel(self):
        if hasattr(self, '_active_worker') and self._active_worker:
            self._active_worker.cancel()
            self._log("Cancel requested... terminating.", "warning")

    def _on_log(self, message: str, level: str):
        self._log(message, level)

    def _log(self, message: str, level: str = "info"):
        _insert_log_line(self.log_view, message, level)

    def _clear_logs(self):
        self.log_view.clear()

    def _on_finished(self, success: bool, message: str):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.indeterminate_progress.stop()
        self.indeterminate_progress.setVisible(False)
        self.progress_label.setText("Complete" if success else "Failed")

        if success:
            InfoBar.success("Success", message, parent=self, position=InfoBarPosition.TOP, duration=5000)
            self._log(message, "success")
            if getattr(self, '_last_action', None) == "start":
                import webbrowser
                url = "http://localhost:8085"
                self._log(f"Opening browser in 5 seconds: {url}", "info")
                QTimer.singleShot(5000, lambda: webbrowser.open(url))
        else:
            InfoBar.error("Failed", message, parent=self, position=InfoBarPosition.TOP, duration=8000)
            self._log(message, "error")

        if hasattr(self, '_active_worker') and self._active_worker:
            self._active_worker.deleteLater()
            self._active_worker = None

class SettingsCard(CardWidget):
    """A card widget for settings sections"""

    def __init__(self, title: str, icon: FIF, parent=None):
        super().__init__(parent)
        self.setObjectName(title.replace(" ", ""))

        self.vBoxLayout = QVBoxLayout(self)
        self.vBoxLayout.setContentsMargins(20, 20, 20, 20)
        self.vBoxLayout.setSpacing(12)

        # Header
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        icon_widget = ToolButton(icon, self)
        icon_widget.setIconSize(QSize(20, 20))
        icon_widget.setEnabled(False)
        header_layout.addWidget(icon_widget)

        title_label = SubtitleLabel(title, self)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        self.vBoxLayout.addLayout(header_layout)

    def addRow(self, label_text: str, widget: QWidget, hint: str = None):
        """Add a labeled row to the card"""
        row_layout = QHBoxLayout()
        row_layout.setSpacing(12)

        label = BodyLabel(label_text, self)
        label.setFixedWidth(120)
        row_layout.addWidget(label)

        widget.setMinimumWidth(280)
        row_layout.addWidget(widget)

        if hint:
            hint_label = BodyLabel(hint, self)
            hint_label.setStyleSheet("color: gray;")
            row_layout.addWidget(hint_label)

        row_layout.addStretch()
        self.vBoxLayout.addLayout(row_layout)
        return widget


class ReleasePage(QWidget):
    """Main release automation page"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("releasePage")
        self.parent_window = parent
        self.worker = None

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        # Title
        title = TitleLabel("Release Automation", self)
        layout.addWidget(title)

        # Release Options Card
        options_card = CardWidget(self)
        options_layout = QVBoxLayout(options_card)
        options_layout.setContentsMargins(20, 20, 20, 20)
        options_layout.setSpacing(16)

        # Row 1: Bump type, channel, and version
        row1 = QHBoxLayout()
        row1.setSpacing(20)

        bump_label = BodyLabel("Update Type:", self)
        row1.addWidget(bump_label)

        self.bump_combo = ComboBox(self)
        self.bump_combo.addItems(["patch", "minor", "major"])
        self.bump_combo.setCurrentIndex(0)
        self.bump_combo.setFixedWidth(120)
        row1.addWidget(self.bump_combo)

        row1.addSpacing(20)

        channel_label = BodyLabel("Channel:", self)
        row1.addWidget(channel_label)

        self.channel_combo = ComboBox(self)
        self.channel_combo.addItems(["stable", "beta"])
        self.channel_combo.setCurrentIndex(0)
        self.channel_combo.setFixedWidth(100)
        self.channel_combo.currentTextChanged.connect(self._on_channel_changed)
        row1.addWidget(self.channel_combo)

        # Channel indicator badge
        self.channel_badge = BodyLabel("", self)
        self._update_channel_badge()
        row1.addWidget(self.channel_badge)

        row1.addSpacing(20)

        version_label = BodyLabel("or Version:", self)
        row1.addWidget(version_label)

        self.version_edit = LineEdit(self)
        self.version_edit.setPlaceholderText("e.g. 1.2.3")
        self.version_edit.setFixedWidth(120)
        row1.addWidget(self.version_edit)

        row1.addSpacing(20)

        self.dry_run_check = CheckBox("Dry Run (Preview Only)", self)
        self.dry_run_check.setChecked(True)
        row1.addWidget(self.dry_run_check)

        row1.addStretch()
        options_layout.addLayout(row1)

        # Row 2: Buttons
        row2 = QHBoxLayout()
        row2.setSpacing(12)

        self.release_btn = PrimaryPushButton(FIF.PLAY, "Run Release Process", self)
        self.release_btn.setFixedWidth(180)
        self.release_btn.clicked.connect(self._on_release)
        row2.addWidget(self.release_btn)

        self.retry_btn = PushButton(FIF.SYNC, "Retry Upload", self)
        self.retry_btn.setFixedWidth(140)
        self.retry_btn.clicked.connect(self._on_retry_upload)
        row2.addWidget(self.retry_btn)

        self.version_combo = ComboBox(self)
        self.version_combo.setPlaceholderText("Select version")
        self.version_combo.setFixedWidth(120)
        row2.addWidget(self.version_combo)

        self.refresh_btn = ToolButton(FIF.SYNC, self)
        self.refresh_btn.clicked.connect(self._refresh_versions)
        row2.addWidget(self.refresh_btn)

        # Upload channel selector
        self.upload_channel_combo = ComboBox(self)
        self.upload_channel_combo.addItems(["stable", "beta"])
        self.upload_channel_combo.setFixedWidth(80)
        row2.addWidget(self.upload_channel_combo)

        self.upload_dry_run = CheckBox("Dry Run", self)
        self.upload_dry_run.setChecked(True)
        row2.addWidget(self.upload_dry_run)

        row2.addSpacing(20)

        self.download_btn = PushButton(FIF.DOWNLOAD, "Download Files", self)
        self.download_btn.clicked.connect(self._on_download)
        row2.addWidget(self.download_btn)

        self.cancel_btn = PushButton(FIF.CLOSE, "Cancel", self)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel)
        row2.addWidget(self.cancel_btn)

        row2.addStretch()
        options_layout.addLayout(row2)

        layout.addWidget(options_card)

        # Progress
        self.progress_bar = IndeterminateProgressBar(self)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Log Card
        log_card = CardWidget(self)
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(20, 16, 20, 20)
        log_layout.setSpacing(12)

        log_header = QHBoxLayout()
        log_title = SubtitleLabel("Execution Logs", self)
        log_header.addWidget(log_title)
        log_header.addStretch()

        clear_btn = TransparentPushButton(FIF.DELETE, "Clear", self)
        clear_btn.clicked.connect(self._clear_logs)
        log_header.addWidget(clear_btn)
        log_layout.addLayout(log_header)

        self.log_view = TextEdit(self)
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(300)
        self.log_view.setStyleSheet(get_log_stylesheet())
        log_layout.addWidget(self.log_view)

        layout.addWidget(log_card, 1)

        # Load versions
        self._refresh_versions()

    def _on_channel_changed(self, channel: str):
        """Handle channel selection change"""
        self._update_channel_badge()

    def _update_channel_badge(self):
        """Update the channel indicator badge"""
        channel = self.channel_combo.currentText()
        if channel == "beta":
            self.channel_badge.setText("🔷 BETA")
            self.channel_badge.setStyleSheet("color: #818cf8; font-weight: bold;")
        else:
            self.channel_badge.setText("🟢 STABLE")
            self.channel_badge.setStyleSheet("color: #10b981; font-weight: bold;")

    def _refresh_versions(self):
        """Scan releases folder for available versions"""
        self.version_combo.clear()
        releases_dir = script_dir.parent / "releases"
        versions = []

        if releases_dir.exists():
            for f in releases_dir.iterdir():
                if f.is_file() and f.name.endswith("_customer_pkg.zip"):
                    match = re.search(r'_v(\d+\.\d+\.\d+)_customer_pkg\.zip$', f.name)
                    if match:
                        versions.append(match.group(1))

        versions.sort(key=lambda v: [int(x) for x in v.split('.')], reverse=True)

        for v in versions:
            self.version_combo.addItem(v)

        if versions:
            self.version_combo.setCurrentIndex(0)

    def _get_params(self) -> dict:
        """Gather all parameters from settings"""
        settings = self.parent_window.settings_page
        return {
            'bump_type': self.bump_combo.currentText(),
            'channel': self.channel_combo.currentText(),
            'dry_run': self.dry_run_check.isChecked(),
            'manual_version': self.version_edit.text().strip(),
            'ssh_host': settings.ssh_host.text(),
            'ssh_port': settings.ssh_port.text(),
            'ssh_user': settings.ssh_user.text(),
            'ssh_pass': settings.ssh_pass.text(),
            'ssh_key': settings.ssh_key.text(),
            'ssh_path_releases': settings.ssh_path_releases.text(),
            'ssh_path_en': settings.ssh_path_en.text(),
            'ssh_path_de': settings.ssh_path_de.text(),
            'ftp_host': settings.ftp_host.text(),
            'ftp_user': settings.ftp_user.text(),
            'ftp_pass': settings.ftp_pass.text(),
            'ftp_path_releases': settings.ftp_path_releases.text(),
            'ftp_path_en': settings.ftp_path_en.text(),
            'ftp_path_de': settings.ftp_path_de.text(),
            'ai_service': settings.ai_service.currentText(),
            'gemini_key': settings.gemini_key.text(),
            'gcp_project': settings.gcp_project.text(),
            'gcp_location': settings.gcp_location.text(),
            'ai_model': settings.ai_model.currentText(),
        }

    def _on_release(self):
        """Start release process"""
        if not self.dry_run_check.isChecked():
            box = MessageBox(
                "Upload Confirmation",
                "You are about to upload files to the server.\n\n"
                "Have you downloaded a local backup first?",
                self
            )
            box.yesButton.setText("Continue")
            box.cancelButton.setText("Download First")

            if not box.exec():
                self._on_download()
                return

        self._start_worker("release", self._get_params())

    def _on_retry_upload(self):
        """Retry upload for selected version"""
        version = self.version_combo.currentText()
        if not version:
            InfoBar.warning(
                "No Version",
                "Please select a version from the dropdown",
                parent=self,
                position=InfoBarPosition.TOP
            )
            return

        params = self._get_params()
        params['version'] = version
        params['dry_run'] = self.upload_dry_run.isChecked()
        params['upload_channel'] = self.upload_channel_combo.currentText()

        self._start_worker("retry_upload", params)

    def _start_worker(self, operation: str, params: dict):
        """Start background worker"""
        self._set_buttons_enabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.start()

        self._active_worker = ReleaseWorker(operation, params, script_dir.parent)
        self._active_worker.signals.log_message.connect(self._on_log)
        self._active_worker.signals.operation_finished.connect(self._on_finished)
        self._active_worker.start()

    def _on_cancel(self):
        """Cancel current operation"""
        if hasattr(self, '_active_worker') and self._active_worker:
            self._active_worker.cancel()
            self._log("Cancel requested... terminating operation.", "warning")

    def _on_download(self):
        """Download release files locally"""
        import shutil

        dest_dir = QFileDialog.getExistingDirectory(
            self,
            "Select folder to save release files",
            str(Path.home() / "Downloads")
        )

        if not dest_dir:
            return

        dest_path = Path(dest_dir)
        project_root = script_dir.parent

        # Get version
        try:
            sys.path.insert(0, str(project_root))
            from yads.config import settings
            version = settings.VERSION
        except:
            version_file = project_root / "releases" / "version.json"
            if version_file.exists():
                import json
                with open(version_file) as f:
                    version = json.load(f).get("version", "unknown")
            else:
                version = "unknown"

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
            "release_assets/setup.sh",
            "release_assets/nginx.conf.template",
        ]

        copied = []
        for file_path in files_to_copy:
            src = project_root / file_path
            if src.exists():
                rel_dest = dest_path / file_path
                rel_dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, rel_dest)
                copied.append(file_path)

        if copied:
            InfoBar.success(
                "Download Complete",
                f"Downloaded {len(copied)} files to {dest_dir}",
                parent=self,
                position=InfoBarPosition.TOP,
                duration=5000
            )
            self._log(f"Downloaded {len(copied)} release files to {dest_dir}", "success")
        else:
            InfoBar.warning(
                "No Files",
                "No release files found. Run the release process first.",
                parent=self,
                position=InfoBarPosition.TOP
            )

    def _on_log(self, message: str, level: str):
        """Handle log message from worker"""
        self._log(message, level)

    def _log(self, message: str, level: str = "info"):
        _insert_log_line(self.log_view, message, level)

    def _clear_logs(self):
        self.log_view.clear()

    def _on_finished(self, success: bool, message: str):
        """Handle operation completion"""
        self._set_buttons_enabled(True)
        self.progress_bar.stop()
        self.progress_bar.setVisible(False)

        if success:
            InfoBar.success("Complete", message, parent=self, position=InfoBarPosition.TOP, duration=5000)
            self._log(message, "success")
        else:
            InfoBar.error("Failed", message, parent=self, position=InfoBarPosition.TOP, duration=8000)
            self._log(message, "error")

        if hasattr(self, '_active_worker') and self._active_worker:
            self._active_worker.deleteLater()
            self._active_worker = None

    def _set_buttons_enabled(self, enabled: bool):
        """Enable/disable action buttons"""
        self.release_btn.setEnabled(enabled)
        self.retry_btn.setEnabled(enabled)
        self.download_btn.setEnabled(enabled)
        self.cancel_btn.setEnabled(not enabled)


class SettingsPage(SmoothScrollArea):
    """Settings configuration page"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("settingsPage")
        self.setWidgetResizable(True)

        self.config_dir = Path.home() / ".yads"
        self.config_file = self.config_dir / "release_gui.yaml"

        self._setup_ui()
        self._load_config()

    def _setup_ui(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        # Title
        title = TitleLabel("Configuration", self)
        layout.addWidget(title)

        # SSH Card
        ssh_card = SettingsCard("SSH Deployment", FIF.COMMAND_PROMPT, self)

        self.ssh_host = LineEdit(self)
        self.ssh_host.setPlaceholderText("ssh.example.com")
        ssh_card.addRow("Server:", self.ssh_host)

        self.ssh_port = LineEdit(self)
        self.ssh_port.setText("22")
        self.ssh_port.setFixedWidth(80)
        ssh_card.addRow("Port:", self.ssh_port)

        self.ssh_user = LineEdit(self)
        self.ssh_user.setPlaceholderText("deploy")
        ssh_card.addRow("Username:", self.ssh_user)

        self.ssh_pass = PasswordLineEdit(self)
        self.ssh_pass.setPlaceholderText("Password (or use key)")
        ssh_card.addRow("Password:", self.ssh_pass)

        self.ssh_key = LineEdit(self)
        self.ssh_key.setPlaceholderText("~/.ssh/id_rsa")
        ssh_card.addRow("Key File:", self.ssh_key, "(optional)")

        # SSH Paths
        self.ssh_path_releases = LineEdit(self)
        self.ssh_path_releases.setText("/en/releases/")
        ssh_card.addRow("Releases Path:", self.ssh_path_releases, "(zip + version.json)")

        self.ssh_path_en = LineEdit(self)
        self.ssh_path_en.setText("/en/")
        ssh_card.addRow("Homepage EN:", self.ssh_path_en)

        self.ssh_path_de = LineEdit(self)
        self.ssh_path_de.setText("/de/")
        ssh_card.addRow("Homepage DE:", self.ssh_path_de)

        layout.addWidget(ssh_card)

        # FTP Card
        ftp_card = SettingsCard("FTP Deployment", FIF.GLOBE, self)

        self.ftp_host = LineEdit(self)
        self.ftp_host.setPlaceholderText("ftp.example.com")
        ftp_card.addRow("Server:", self.ftp_host)

        self.ftp_user = LineEdit(self)
        self.ftp_user.setPlaceholderText("ftpuser")
        ftp_card.addRow("Username:", self.ftp_user)

        self.ftp_pass = PasswordLineEdit(self)
        self.ftp_pass.setPlaceholderText("FTP password")
        ftp_card.addRow("Password:", self.ftp_pass)

        # FTP Paths
        self.ftp_path_releases = LineEdit(self)
        self.ftp_path_releases.setText("/en/releases/")
        ftp_card.addRow("Releases Path:", self.ftp_path_releases, "(zip + version.json)")

        self.ftp_path_en = LineEdit(self)
        self.ftp_path_en.setText("/en/")
        ftp_card.addRow("Homepage EN:", self.ftp_path_en)

        self.ftp_path_de = LineEdit(self)
        self.ftp_path_de.setText("/de/")
        ftp_card.addRow("Homepage DE:", self.ftp_path_de)

        layout.addWidget(ftp_card)

        # AI/Translation Card
        ai_card = SettingsCard("AI Translation", FIF.ROBOT, self)

        self.ai_service = ComboBox(self)
        self.ai_service.addItems(["gemini", "vertexai", "manual"])
        ai_card.addRow("Service:", self.ai_service)

        self.gemini_key = PasswordLineEdit(self)
        self.gemini_key.setPlaceholderText("API key for Gemini")
        ai_card.addRow("Gemini Key:", self.gemini_key)

        self.gcp_project = LineEdit(self)
        self.gcp_project.setPlaceholderText("my-gcp-project")
        ai_card.addRow("GCP Project:", self.gcp_project, "(Vertex AI only)")

        self.gcp_location = LineEdit(self)
        self.gcp_location.setText("us-central1")
        ai_card.addRow("GCP Location:", self.gcp_location)

        self.ai_model = ComboBox(self)
        self.ai_model.addItems([
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
            "gemini-1.5-flash",
            "gemini-1.5-flash-latest",
            "gemini-1.5-pro",
            "gemini-1.5-pro-latest"
        ])
        ai_card.addRow("AI Model:", self.ai_model)

        # Check Translation Button
        check_row = QHBoxLayout()
        check_row.setSpacing(12)

        check_label = BodyLabel("Test:", self)
        check_label.setFixedWidth(120)
        check_row.addWidget(check_label)

        self.check_translation_btn = PushButton(FIF.ACCEPT, "Check AI Translation", self)
        self.check_translation_btn.setFixedWidth(200)
        self.check_translation_btn.clicked.connect(self._check_ai_translation)
        check_row.addWidget(self.check_translation_btn)

        self.translation_status = BodyLabel("", self)
        check_row.addWidget(self.translation_status)

        check_row.addStretch()
        ai_card.vBoxLayout.addLayout(check_row)

        layout.addWidget(ai_card)

        # Support Portal Card
        support_card = SettingsCard("Support Portal", FIF.CLOUD, self)

        self.support_portal_url = LineEdit(self)
        self.support_portal_url.setPlaceholderText("https://support.yads-security.com")
        support_card.addRow("Portal URL:", self.support_portal_url)

        self.support_admin_token = PasswordLineEdit(self)
        self.support_admin_token.setPlaceholderText("Admin Bearer Token")
        support_card.addRow("Admin Token:", self.support_admin_token)

        layout.addWidget(support_card)

        # Save Button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        save_btn = PrimaryPushButton(FIF.SAVE, "Save Configuration", self)
        save_btn.setFixedWidth(200)
        save_btn.clicked.connect(self._save_config)
        btn_layout.addWidget(save_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        layout.addStretch()

        self.setWidget(container)

    def _load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                import yaml
                with open(self.config_file, 'r') as f:
                    data = yaml.safe_load(f) or {}

                self.ssh_host.setText(data.get('ssh_host', ''))
                self.ssh_port.setText(str(data.get('ssh_port', '22')))
                self.ssh_user.setText(data.get('ssh_user', ''))
                self.ssh_pass.setText(data.get('ssh_pass', ''))
                self.ssh_key.setText(data.get('ssh_key', ''))
                self.ssh_path_releases.setText(data.get('ssh_path_releases', '/en/releases/'))
                self.ssh_path_en.setText(data.get('ssh_path_en', '/en/'))
                self.ssh_path_de.setText(data.get('ssh_path_de', '/de/'))

                self.ftp_host.setText(data.get('ftp_host', ''))
                self.ftp_user.setText(data.get('ftp_user', ''))
                self.ftp_pass.setText(data.get('ftp_pass', ''))
                self.ftp_path_releases.setText(data.get('ftp_path_releases', '/en/releases/'))
                self.ftp_path_en.setText(data.get('ftp_path_en', '/en/'))
                self.ftp_path_de.setText(data.get('ftp_path_de', '/de/'))

                self.ai_service.setCurrentText(data.get('ai_service', 'gemini'))
                self.gemini_key.setText(data.get('gemini_key', ''))
                self.gcp_project.setText(data.get('gcp_project', ''))
                self.gcp_location.setText(data.get('gcp_location', 'us-central1'))
                self.ai_model.setCurrentText(data.get('ai_model', 'gemini-2.0-flash'))
                self.support_portal_url.setText(data.get('support_portal_url', 'https://support.yads-security.com'))
                self.support_admin_token.setText(data.get('support_admin_token', ''))

            except Exception as e:
                print(f"Error loading config: {e}")

    def _save_config(self):
        """Save configuration to file"""
        import yaml

        self.config_dir.mkdir(parents=True, exist_ok=True)

        data = {
            'ssh_host': self.ssh_host.text(),
            'ssh_port': self.ssh_port.text(),
            'ssh_user': self.ssh_user.text(),
            'ssh_pass': self.ssh_pass.text(),
            'ssh_key': self.ssh_key.text(),
            'ssh_path_releases': self.ssh_path_releases.text(),
            'ssh_path_en': self.ssh_path_en.text(),
            'ssh_path_de': self.ssh_path_de.text(),
            'ftp_host': self.ftp_host.text(),
            'ftp_user': self.ftp_user.text(),
            'ftp_pass': self.ftp_pass.text(),
            'ftp_path_releases': self.ftp_path_releases.text(),
            'ftp_path_en': self.ftp_path_en.text(),
            'ftp_path_de': self.ftp_path_de.text(),
            'ai_service': self.ai_service.currentText(),
            'gemini_key': self.gemini_key.text(),
            'gcp_project': self.gcp_project.text(),
            'gcp_location': self.gcp_location.text(),
            'ai_model': self.ai_model.currentText(),
            'support_portal_url': self.support_portal_url.text().strip(),
            'support_admin_token': self.support_admin_token.text().strip(),
        }

        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(data, f)

            InfoBar.success(
                "Saved",
                "Configuration saved successfully!",
                parent=self,
                position=InfoBarPosition.TOP,
                duration=3000
            )
        except Exception as e:
            InfoBar.error(
                "Error",
                f"Could not save settings: {e}",
                parent=self,
                position=InfoBarPosition.TOP
            )

    def _check_ai_translation(self):
        """Test AI translation service with a sample text"""
        self.check_translation_btn.setEnabled(False)
        self.translation_status.setText("Testing...")
        self.translation_status.setStyleSheet("color: gray;")

        # Capture UI values in main thread before starting background thread
        service = self.ai_service.currentText()
        model = self.ai_model.currentText()
        api_key = self.gemini_key.text().strip()
        project = self.gcp_project.text().strip()
        location = self.gcp_location.text().strip() or "us-central1"

        # Run in separate thread to not block UI
        def run_check():
            try:
                if service == "manual":
                    return (False, "Manual mode - no AI service configured")

                # Test text (English changelog entry)
                test_text = "### Added\n- New feature: Custom Report Builder with 200+ template variables"

                if service == "gemini":
                    if not api_key:
                        return (False, "Gemini API key not configured")

                    import google.generativeai as genai
                    genai.configure(api_key=api_key)
                    model_instance = genai.GenerativeModel(model)

                    prompt = f"""Translate the following English changelog entry to German.
Keep the markdown formatting intact. Only return the translated text, no explanations.

{test_text}"""

                    response = model_instance.generate_content(prompt)
                    translated = response.text.strip()

                    if translated and "###" in translated:
                        return (True, f"✓ Translation OK\n\nOriginal:\n{test_text}\n\nTranslated:\n{translated}")
                    else:
                        return (False, f"Unexpected response: {translated[:100]}...")

                elif service == "vertexai":
                    if not project:
                        return (False, "GCP Project ID not configured")

                    import vertexai
                    from vertexai.generative_models import GenerativeModel

                    vertexai.init(project=project, location=location)
                    model_instance = GenerativeModel(model)

                    prompt = f"""Translate the following English changelog entry to German.
Keep the markdown formatting intact. Only return the translated text, no explanations.

{test_text}"""

                    response = model_instance.generate_content(prompt)
                    translated = response.text.strip()

                    if translated and "###" in translated:
                        return (True, f"✓ Translation OK\n\nOriginal:\n{test_text}\n\nTranslated:\n{translated}")
                    else:
                        return (False, f"Unexpected response: {translated[:100]}...")

                return (False, f"Unknown service: {service}")

            except ImportError as e:
                return (False, f"Missing library: {e}")
            except Exception as e:
                return (False, f"Error: {str(e)}")

        import threading

        def on_complete(result):
            success, message = result
            self.check_translation_btn.setEnabled(True)

            if success:
                self.translation_status.setText("✓ OK")
                self.translation_status.setStyleSheet("color: #10b981; font-weight: bold;")
                # Show full result in dialog
                box = MessageBox(
                    "AI Translation Check - Success",
                    message,
                    self
                )
                box.yesButton.setText("OK")
                box.cancelButton.hide()
                box.exec()
            else:
                self.translation_status.setText("✗ Failed")
                self.translation_status.setStyleSheet("color: #ef4444; font-weight: bold;")
                InfoBar.error(
                    "Translation Check Failed",
                    message[:100] + ("..." if len(message) > 100 else ""),
                    parent=self,
                    position=InfoBarPosition.TOP,
                    duration=8000
                )

        def thread_func():
            result = run_check()
            # Use QTimer to update UI from main thread
            QTimer.singleShot(0, lambda: on_complete(result))

        thread = threading.Thread(target=thread_func, daemon=True)
        thread.start()


class ThemeToggleWidget(NavigationWidget):
    """Widget for theme toggle in navigation sidebar"""

    themeChanged = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(isSelectable=False, parent=parent)
        self.setFixedHeight(40)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 4, 16, 4)
        layout.setSpacing(8)

        # Sun/Moon icon
        self.icon_label = BodyLabel("", self)
        self._update_icon()
        layout.addWidget(self.icon_label)

        layout.addStretch()

        # Switch
        self.switch = SwitchButton(self)
        self.switch.setChecked(isDarkTheme())
        self.switch.checkedChanged.connect(self._on_toggle)
        layout.addWidget(self.switch)

    def _update_icon(self):
        if isDarkTheme():
            self.icon_label.setText("🌙 Dark")
        else:
            self.icon_label.setText("☀️ Light")

    def _on_toggle(self, is_dark: bool):
        import json
        if is_dark:
            setTheme(Theme.DARK)
        else:
            setTheme(Theme.LIGHT)

        self._update_icon()

        # Save preference
        config_file = Path.home() / ".yads" / "release_manager_settings.json"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump({"dark_mode": is_dark}, f)

        self.themeChanged.emit(is_dark)


class AboutPage(QWidget):
    """About page with app info"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("aboutPage")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        # Title
        title = TitleLabel("About", self)
        layout.addWidget(title)

        # Info Card
        info_card = CardWidget(self)
        info_layout = QVBoxLayout(info_card)
        info_layout.setContentsMargins(30, 30, 30, 30)
        info_layout.setSpacing(16)

        app_title = TitleLabel("YADS Release Manager", self)
        app_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_layout.addWidget(app_title)

        version_label = SubtitleLabel("Version 2.1 - Fluent UI Edition", self)
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_layout.addWidget(version_label)

        desc = BodyLabel(
            "A modern release automation tool for YADS.\n\n"
            "Features:\n"
            "• Automated version bumping (patch/minor/major)\n"
            "• AI-powered changelog translation (Gemini/Vertex AI)\n"
            "• SSH and FTP upload support\n"
            "• Dry-run mode for safe previews\n"
            "• Local backup before upload\n\n"
            "Built with PySide6 and QFluentWidgets",
            self
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_layout.addWidget(desc)

        info_layout.addStretch()
        layout.addWidget(info_card)
        layout.addStretch()


class TestManagerSignals(QObject):
    log_message     = Signal(str, str)   # message, level
    tests_found     = Signal(list)       # list of dicts {node_id, name}
    test_status     = Signal(str, str)   # node_id, status
    summary         = Signal(int, int, int, float)  # passed, failed, skipped, secs
    finished        = Signal(bool, str)


class TestManagerWorker(QThread):
    """Discovers tests via AST scan; runs them via docker compose."""

    RESULT_RE  = re.compile(r'(tests/\S+::\S+)\s+(PASSED|FAILED|ERROR|SKIPPED)')
    SUMMARY_RE = {
        "passed":  re.compile(r'(\d+) passed'),
        "failed":  re.compile(r'(\d+) failed'),
        "skipped": re.compile(r'(\d+) skipped'),
    }

    def __init__(self, action: str, project_root: Path, args: list = None):
        super().__init__()
        self.action       = action        # "discover" | "run" | "run_marker"
        self.project_root = project_root
        self.args         = args or []    # node_ids  OR  [marker_string]
        self.signals      = TestManagerSignals()
        self.cancelled    = False
        self._proc        = None

    def cancel(self):
        self.cancelled = True
        if self._proc:
            try: self._proc.terminate()
            except Exception: pass

    def run(self):
        try:
            if self.action == "discover":
                self._do_discover()
            elif self.action == "run":
                self._do_run(self.args)
            elif self.action == "run_marker":
                self._do_run_marker(self.args[0] if self.args else "")
        except Exception as e:
            self.signals.log_message.emit(f"Critical error: {e}", "error")
            self.signals.finished.emit(False, str(e))

    def _log(self, msg: str, level: str = "info"):
        self.signals.log_message.emit(msg, level)

    # ── Discover ──────────────────────────────────────────────────────────────

    def _do_discover(self):
        import ast as _ast
        tests_dir = self.project_root / "tests"
        if not tests_dir.exists():
            self._log("❌ tests/ directory not found in project root.", "error")
            return self.signals.finished.emit(False, "tests/ not found")

        nodes = []
        for test_file in sorted(tests_dir.glob("test_*.py")):
            rel = test_file.relative_to(self.project_root).as_posix()
            self._log(f"  scanning {rel}", "info")
            try:
                tree = _ast.parse(test_file.read_text())
            except SyntaxError as e:
                self._log(f"  ⚠ Syntax error in {rel}: {e}", "warning")
                continue

            # Top-level test functions
            for node in _ast.iter_child_nodes(tree):
                if isinstance(node, _ast.FunctionDef) and node.name.startswith("test_"):
                    nodes.append({"node_id": f"{rel}::{node.name}", "name": node.name})

            # Class-based tests
            for node in _ast.walk(tree):
                if isinstance(node, _ast.ClassDef) and node.name.startswith("Test"):
                    for item in node.body:
                        if isinstance(item, _ast.FunctionDef) and item.name.startswith("test_"):
                            nid = f"{rel}::{node.name}::{item.name}"
                            nodes.append({"node_id": nid, "name": item.name})

        n = len(nodes)
        self._log(f"✅ Found {n} test{'s' if n != 1 else ''}.", "success")
        self.signals.tests_found.emit(nodes)
        self.signals.finished.emit(True, f"{n} tests discovered")

    # ── Run ───────────────────────────────────────────────────────────────────

    def _pytest_cmd(self, extra: str) -> list:
        return [
            "docker", "compose",
            "-f", str(self.project_root / "docker-compose.test.yml"),
            "run", "--rm", "test-runner",
            "sh", "-c",
            f"pip install -q pytest pytest-asyncio pytest-cov anyio && "
            f"python -m pytest -v --tb=short --no-header {extra}",
        ]

    def _stream(self, cmd: list, node_ids_to_mark: list) -> tuple:
        """Run cmd, stream output, parse results. Returns (passed, failed, skipped, duration)."""
        import time
        passed = failed = skipped = 0
        t0 = time.time()

        for nid in node_ids_to_mark:
            self.signals.test_status.emit(nid, "running")

        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, cwd=str(self.project_root),
            )
            for line in self._proc.stdout:
                if self.cancelled:
                    self._proc.terminate()
                    break
                clean = _ANSI_RE.sub("", line.rstrip())
                if not clean:
                    continue
                self._log(clean, "info")
                m = self.RESULT_RE.search(clean)
                if m:
                    nid, st = m.group(1), m.group(2).lower()
                    self.signals.test_status.emit(nid, st)
                    if st == "passed":     passed  += 1
                    elif st in ("failed", "error"): failed  += 1
                    elif st == "skipped":  skipped += 1
            self._proc.wait()
            ok = self._proc.returncode == 0
            self._proc = None
        except Exception as e:
            self._log(f"Subprocess error: {e}", "error")
            return 0, 1, 0, time.time() - t0

        duration = time.time() - t0
        return passed, failed, skipped, duration

    def _do_run(self, node_ids: list):
        if not node_ids:
            self._log("No tests selected.", "warning")
            return self.signals.finished.emit(False, "Nothing to run")

        self._log(f"▶ Running {len(node_ids)} test(s) via docker compose…", "info")
        cmd = self._pytest_cmd(" ".join(node_ids))
        passed, failed, skipped, dur = self._stream(cmd, node_ids)

        self.signals.summary.emit(passed, failed, skipped, dur)
        msg = f"{passed} passed, {failed} failed, {skipped} skipped in {dur:.1f}s"
        self._log(f"{'✅' if failed == 0 else '❌'} {msg}", "success" if failed == 0 else "error")
        self.signals.finished.emit(failed == 0, msg)

    def _do_run_marker(self, marker: str):
        self._log(f"▶ Running tests marked '{marker}' via docker compose…", "info")
        cmd = self._pytest_cmd(f"-m {marker}")
        passed, failed, skipped, dur = self._stream(cmd, [])

        self.signals.summary.emit(passed, failed, skipped, dur)
        msg = f"{passed} passed, {failed} failed, {skipped} skipped in {dur:.1f}s"
        self._log(f"{'✅' if failed == 0 else '❌'} {msg}", "success" if failed == 0 else "error")
        self.signals.finished.emit(failed == 0, msg)


class TestManagerPage(QWidget):
    """Discover and run YADS integration tests with live status tracking."""

    _STATUS = {
        "idle":    ("—",  "#94a3b8"),
        "running": ("⟳",  "#3b82f6"),
        "passed":  ("✓",  "#22c55e"),
        "failed":  ("✗",  "#ef4444"),
        "error":   ("✗",  "#ef4444"),
        "skipped": ("⊘",  "#f59e0b"),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("testManagerPage")
        self._worker      = None
        self._all_nodes   = []      # list of {node_id, name}
        self._tree_items  = {}      # node_id → QTreeWidgetItem
        self._done_count  = 0
        self._setup_ui()

    # ── UI construction ───────────────────────────────────────────────────────

    def _setup_ui(self):
        from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem, QSplitter
        from qfluentwidgets import SearchLineEdit

        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(16)

        layout.addWidget(TitleLabel("Test Manager", self))

        info = BodyLabel(
            "Discover and run YADS integration tests. "
            "Tests execute inside the dev Docker image via docker-compose.test.yml.",
            self,
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # ── Toolbar ──────────────────────────────────────────────────────────
        tb_card = CardWidget(self)
        tb = QHBoxLayout(tb_card)
        tb.setContentsMargins(16, 12, 16, 12)
        tb.setSpacing(10)

        self.discover_btn = PushButton(FIF.SEARCH, "Discover", self)
        self.discover_btn.setFixedWidth(120)
        self.discover_btn.setToolTip("Scan tests/ with AST — instant, no Docker needed")
        self.discover_btn.clicked.connect(self._on_discover)

        self.run_all_btn = PrimaryPushButton(FIF.PLAY, "Run All", self)
        self.run_all_btn.setFixedWidth(110)
        self.run_all_btn.setEnabled(False)
        self.run_all_btn.clicked.connect(self._on_run_all)

        self.run_sel_btn = PushButton(FIF.PLAY, "Run Selected", self)
        self.run_sel_btn.setFixedWidth(130)
        self.run_sel_btn.setEnabled(False)
        self.run_sel_btn.clicked.connect(self._on_run_selected)

        marker_lbl = BodyLabel("Marker:", self)
        self.marker_combo = ComboBox(self)
        self.marker_combo.addItems(
            ["(all)", "smoke", "auth", "targets", "queue", "users", "integration"]
        )
        self.marker_combo.setFixedWidth(130)

        self.run_marked_btn = PushButton(FIF.FILTER, "Run Marked", self)
        self.run_marked_btn.setFixedWidth(120)
        self.run_marked_btn.setEnabled(False)
        self.run_marked_btn.clicked.connect(self._on_run_marked)

        self.stop_btn = PushButton(FIF.CLOSE, "Stop", self)
        self.stop_btn.setFixedWidth(90)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._on_stop)

        self.toolbar_status = BodyLabel("○ Not discovered", self)
        self.toolbar_status.setStyleSheet("color: gray; font-size: 12px;")

        for w in (self.discover_btn, self.run_all_btn, self.run_sel_btn,
                  marker_lbl, self.marker_combo, self.run_marked_btn, self.stop_btn):
            tb.addWidget(w)
        tb.addSpacing(12)
        tb.addWidget(self.toolbar_status)
        tb.addStretch()
        layout.addWidget(tb_card)

        # ── Tree + Log (splitter) ─────────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.setChildrenCollapsible(False)

        # Left: test tree
        tree_card = CardWidget(self)
        tree_vbox = QVBoxLayout(tree_card)
        tree_vbox.setContentsMargins(12, 12, 12, 12)
        tree_vbox.setSpacing(8)

        tree_hdr = QHBoxLayout()
        self.tree_title = SubtitleLabel("Tests (0)", self)
        tree_hdr.addWidget(self.tree_title)
        tree_hdr.addStretch()
        chk_all = TransparentPushButton(FIF.ACCEPT, "All", self)
        chk_all.setFixedWidth(48)
        chk_all.clicked.connect(lambda: self._set_all_checked(True))
        unchk_all = TransparentPushButton(FIF.CANCEL_MEDIUM, "None", self)
        unchk_all.setFixedWidth(52)
        unchk_all.clicked.connect(lambda: self._set_all_checked(False))
        tree_hdr.addWidget(chk_all)
        tree_hdr.addWidget(unchk_all)
        tree_vbox.addLayout(tree_hdr)

        self._tree_filter = SearchLineEdit(self)
        self._tree_filter.setPlaceholderText("Filter tests…")
        self._tree_filter.setFixedHeight(28)
        self._tree_filter.textChanged.connect(self._apply_tree_filter)
        tree_vbox.addWidget(self._tree_filter)

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Test", "Status"])
        self.tree.setColumnWidth(0, 300)
        self.tree.setColumnWidth(1, 70)
        self.tree.setMinimumWidth(400)
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.tree.itemChanged.connect(self._on_item_checked)
        self.tree.setStyleSheet("QTreeWidget { font-size: 12px; }")
        tree_vbox.addWidget(self.tree, 1)
        splitter.addWidget(tree_card)

        # Right: log
        log_card = CardWidget(self)
        log_vbox = QVBoxLayout(log_card)
        log_vbox.setContentsMargins(12, 12, 12, 12)
        log_vbox.setSpacing(8)

        log_hdr = QHBoxLayout()
        log_hdr.addWidget(SubtitleLabel("Output", self))
        log_hdr.addStretch()
        clear_btn = TransparentPushButton(FIF.DELETE, "Clear", self)
        clear_btn.clicked.connect(lambda: self.log_view.clear())
        log_hdr.addWidget(clear_btn)
        log_vbox.addLayout(log_hdr)

        self.log_view = TextEdit(self)
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet(get_log_stylesheet())
        log_vbox.addWidget(self.log_view, 1)
        splitter.addWidget(log_card)

        splitter.setSizes([420, 620])
        splitter.setMinimumHeight(420)
        layout.addWidget(splitter, 1)

        # ── Summary bar ───────────────────────────────────────────────────────
        sum_card = CardWidget(self)
        sum_row = QHBoxLayout(sum_card)
        sum_row.setContentsMargins(16, 10, 16, 10)
        sum_row.setSpacing(24)

        self.lbl_passed  = BodyLabel("✅  0 passed",  self)
        self.lbl_failed  = BodyLabel("❌  0 failed",  self)
        self.lbl_skipped = BodyLabel("⏭  0 skipped", self)
        self.lbl_time    = BodyLabel("⏱  —",         self)
        self.lbl_passed.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.lbl_failed.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.lbl_skipped.setStyleSheet("color: #94a3b8;")
        self.lbl_time.setStyleSheet("color: gray;")

        self.prog = ProgressBar(self)
        self.prog.setValue(0)
        self.prog.setFixedWidth(180)
        self.prog.setVisible(False)

        for w in (self.lbl_passed, self.lbl_failed, self.lbl_skipped, self.lbl_time):
            sum_row.addWidget(w)
        sum_row.addStretch()
        sum_row.addWidget(self.prog)
        layout.addWidget(sum_card)

    # ── Tree helpers ──────────────────────────────────────────────────────────

    def _populate_tree(self, nodes: list):
        from PySide6.QtWidgets import QTreeWidgetItem
        self.tree.blockSignals(True)
        self.tree.clear()
        self._tree_items.clear()
        self._all_nodes = nodes

        # Group: file → class (or __top__ for bare functions)
        files: dict = {}
        for n in nodes:
            parts = n["node_id"].split("::")
            fname = parts[0]
            if fname not in files:
                files[fname] = {}
            key = parts[1] if len(parts) == 3 else "__top__"
            files[fname].setdefault(key, []).append(n)

        for fname, groups in files.items():
            fi = QTreeWidgetItem([fname.split("/")[-1], ""])
            fi.setFlags(fi.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            fi.setCheckState(0, Qt.CheckState.Checked)
            fi.setExpanded(True)
            self.tree.addTopLevelItem(fi)

            for group, group_nodes in groups.items():
                if group == "__top__":
                    parent = fi
                else:
                    ci = QTreeWidgetItem([group, ""])
                    ci.setFlags(ci.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    ci.setCheckState(0, Qt.CheckState.Checked)
                    ci.setExpanded(True)
                    fi.addChild(ci)
                    parent = ci

                for n in group_nodes:
                    ti = QTreeWidgetItem([n["name"], "—"])
                    ti.setFlags(ti.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    ti.setCheckState(0, Qt.CheckState.Checked)
                    ti.setForeground(1, QColor("#94a3b8"))
                    ti.setData(0, Qt.ItemDataRole.UserRole, n["node_id"])
                    parent.addChild(ti)
                    self._tree_items[n["node_id"]] = ti

        self.tree.blockSignals(False)
        self.tree_title.setText(f"Tests ({len(nodes)})")
        for btn in (self.run_all_btn, self.run_sel_btn, self.run_marked_btn):
            btn.setEnabled(True)

    def _set_item_status(self, node_id: str, status: str):
        item = self._tree_items.get(node_id)
        if not item:
            return
        icon, color = self._STATUS.get(status, self._STATUS["idle"])
        item.setText(1, icon)
        item.setForeground(1, QColor(color))

    def _get_checked_ids(self) -> list:
        return [
            nid for nid, item in self._tree_items.items()
            if item.checkState(0) == Qt.CheckState.Checked
        ]

    def _set_all_checked(self, state: bool):
        self.tree.blockSignals(True)
        cs = Qt.CheckState.Checked if state else Qt.CheckState.Unchecked
        for i in range(self.tree.topLevelItemCount()):
            fi = self.tree.topLevelItem(i)
            fi.setCheckState(0, cs)
            for j in range(fi.childCount()):
                ci = fi.child(j)
                ci.setCheckState(0, cs)
                for k in range(ci.childCount()):
                    ci.child(k).setCheckState(0, cs)
        self.tree.blockSignals(False)

    def _apply_tree_filter(self, text: str):
        for i in range(self.tree.topLevelItemCount()):
            fi = self.tree.topLevelItem(i)
            fi_vis = False
            for j in range(fi.childCount()):
                ci = fi.child(j)
                if ci.childCount():
                    ci_vis = False
                    for k in range(ci.childCount()):
                        ti = ci.child(k)
                        match = not text or text.lower() in ti.text(0).lower()
                        ti.setHidden(not match)
                        if match: ci_vis = True
                    ci.setHidden(not ci_vis)
                    if ci_vis: fi_vis = True
                else:
                    match = not text or text.lower() in ci.text(0).lower()
                    ci.setHidden(not match)
                    if match: fi_vis = True
            fi.setHidden(not fi_vis)

    def _on_item_checked(self, item, column):
        if column != 0:
            return
        state = item.checkState(0)
        self.tree.blockSignals(True)
        for j in range(item.childCount()):
            child = item.child(j)
            child.setCheckState(0, state)
            for k in range(child.childCount()):
                child.child(k).setCheckState(0, state)
        self.tree.blockSignals(False)

    # ── Busy state ────────────────────────────────────────────────────────────

    def _set_busy(self, busy: bool):
        has_tests = bool(self._all_nodes)
        self.discover_btn.setEnabled(not busy)
        self.run_all_btn.setEnabled(not busy and has_tests)
        self.run_sel_btn.setEnabled(not busy and has_tests)
        self.run_marked_btn.setEnabled(not busy and has_tests)
        self.stop_btn.setEnabled(busy)
        self.prog.setVisible(busy)

    def _log(self, msg: str, level: str = "info"):
        _insert_log_line(self.log_view, msg, level)

    # ── Slots ─────────────────────────────────────────────────────────────────

    def _on_discover(self):
        self.log_view.clear()
        self._log("Scanning tests/ directory…", "info")
        from pathlib import Path as _P
        self._worker = TestManagerWorker("discover", _P(__file__).parent.parent)
        self._worker.signals.log_message.connect(self._log)
        self._worker.signals.tests_found.connect(self._on_tests_found)
        self._worker.signals.finished.connect(self._on_discover_finished)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _on_tests_found(self, nodes: list):
        self._populate_tree(nodes)

    def _on_discover_finished(self, ok: bool, msg: str):
        self.toolbar_status.setText(f"{'✓' if ok else '✗'} {msg}")
        self.toolbar_status.setStyleSheet(
            "color: #22c55e; font-size: 12px;" if ok
            else "color: #ef4444; font-size: 12px;"
        )

    def _start_run(self, action: str, args: list):
        self.log_view.clear()
        self._set_busy(True)
        self._done_count = 0
        self.lbl_passed.setText("✅  0 passed");  self.lbl_passed.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.lbl_failed.setText("❌  0 failed");  self.lbl_failed.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.lbl_skipped.setText("⏭  0 skipped"); self.lbl_skipped.setStyleSheet("color: #94a3b8;")
        self.lbl_time.setText("⏱  running…")
        if action == "run":
            self.prog.setRange(0, len(args))
        else:
            self.prog.setRange(0, 0)   # indeterminate for marker runs
        self.prog.setValue(0)

        from pathlib import Path as _P
        self._worker = TestManagerWorker(action, _P(__file__).parent.parent, args)
        self._worker.signals.log_message.connect(self._log)
        self._worker.signals.test_status.connect(self._on_test_status)
        self._worker.signals.summary.connect(self._on_summary)
        self._worker.signals.finished.connect(self._on_run_finished)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _on_run_all(self):
        self._start_run("run", [n["node_id"] for n in self._all_nodes])

    def _on_run_selected(self):
        ids = self._get_checked_ids()
        if not ids:
            InfoBar.warning("Nothing selected", "Check at least one test.",
                            parent=self, position=InfoBarPosition.TOP, duration=3000)
            return
        self._start_run("run", ids)

    def _on_run_marked(self):
        marker = self.marker_combo.currentText()
        if marker == "(all)":
            self._on_run_all()
        else:
            self._start_run("run_marker", [marker])

    def _on_stop(self):
        if self._worker:
            self._worker.cancel()
            self._log("Stop requested…", "warning")

    def _on_test_status(self, node_id: str, status: str):
        self._set_item_status(node_id, status)
        if status in ("passed", "failed", "error", "skipped"):
            self._done_count += 1
            if self.prog.maximum() > 0:
                self.prog.setValue(min(self._done_count, self.prog.maximum()))

    def _on_summary(self, passed: int, failed: int, skipped: int, duration: float):
        self.lbl_passed.setText(f"✅  {passed} passed")
        self.lbl_failed.setText(f"❌  {failed} failed")
        self.lbl_skipped.setText(f"⏭  {skipped} skipped")
        self.lbl_time.setText(f"⏱  {duration:.1f}s")
        self.lbl_passed.setStyleSheet(
            f"color: {'#22c55e' if passed > 0 else '#94a3b8'}; font-weight: bold;")
        self.lbl_failed.setStyleSheet(
            f"color: {'#ef4444' if failed > 0 else '#94a3b8'}; font-weight: bold;")

    def _on_run_finished(self, ok: bool, msg: str):
        self._set_busy(False)
        self._worker = None
        self.prog.setVisible(False)
        if ok:
            InfoBar.success("Tests passed", msg, parent=self,
                            position=InfoBarPosition.TOP, duration=5000)
        else:
            InfoBar.error("Tests failed", msg, parent=self,
                          position=InfoBarPosition.TOP, duration=8000)

def _get_latest_gui_test_report_info():
    """Finds and parses the newest GUI test report from tests/results/GUI-Tests/"""
    results_dir = Path(__file__).parent.parent / "tests" / "results" / "GUI-Tests"
    if not results_dir.exists():
        return None
    
    reports = list(results_dir.rglob("test_result_*.md"))
    if not reports:
        return None

    # Sort by filename (contains timestamp)
    latest_report = sorted(reports)[-1]
    
    try:
        content = latest_report.read_text()
        
        ts_match = re.search(r'YADS GUI Test Report - ([\d\- :]+)', content)
        ver_match = re.search(r'\*\*YADS Version:\*\* ([\d.]+)', content)
        run_match = re.search(r'\*\*Tests Run:\*\* (\d+)', content)
        fail_match = re.search(r'\*\*Failures:\*\* (\d+)', content)
        
        timestamp = ts_match.group(1) if ts_match else "Unknown"
        version = ver_match.group(1) if ver_match else "Unknown"
        tests_run = int(run_match.group(1)) if run_match else 0
        failures = int(fail_match.group(1)) if fail_match else 0
        
        # Parse components
        components = []
        comp_section = re.search(r'## Tested Components\n\n(.*?)(?:\n\n|\n✅|\Z)', content, re.DOTALL)
        if comp_section:
            comp_lines = comp_section.group(1).strip().split('\n')
            for line in comp_lines:
                # - ✅ `/dashboard`
                line_match = re.search(r'- ([✅❌]) `(.*?)`', line)
                if line_match:
                    status_icon = line_match.group(1)
                    path = line_match.group(2)
                    components.append({"path": path, "status": status_icon})
        
        return {
            "timestamp": timestamp,
            "version": version,
            "tests_run": tests_run,
            "failures": failures,
            "components": components,
            "path": latest_report
        }
    except Exception as e:
        print(f"Error parsing report {latest_report}: {e}")
        return None


class GuiTestsPage(QWidget):
    """Page for running and monitoring GUI tests"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("guiTestsPage")
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Header
        header = QHBoxLayout()
        header.addWidget(TitleLabel("Simulated Browser GUI Tests", self))
        header.addStretch()
        layout.addLayout(header)

        # Info
        layout.addWidget(BodyLabel(
            "Führt umfangreiche Tests aller GUI-Funktionen auf Dana durch und prüft parallel die System-Logs.", self
        ))

        # --- Recent Result Card ---
        self.result_card = CardWidget(self)
        self.result_card.setVisible(False)
        res_layout = QVBoxLayout(self.result_card)
        
        self.res_title = SubtitleLabel("Letztes Testergebnis", self.result_card)
        res_layout.addWidget(self.res_title)
        
        self.res_details = BodyLabel("", self.result_card)
        res_layout.addWidget(self.res_details)
        
        layout.addWidget(self.result_card)
        
        # --- Detailed Test List ---
        self.tests_label = StrongBodyLabel("Getestete Komponenten:", self)
        self.tests_label.setVisible(False)
        layout.addWidget(self.tests_label)
        
        self.tests_scroll = SmoothScrollArea(self)
        self.tests_scroll.setWidgetResizable(True)
        self.tests_scroll.setVisible(False)
        self.tests_container = QWidget()
        self.tests_layout = QVBoxLayout(self.tests_container)
        self.tests_layout.setContentsMargins(0, 0, 0, 0)
        self.tests_layout.setSpacing(4)
        self.tests_scroll.setWidget(self.tests_container)
        layout.addWidget(self.tests_scroll)
        # -------------------------

        # Controls Card
        ctrl_card = CardWidget(self)
        ctrl_layout = QVBoxLayout(ctrl_card)
        
        row1 = QHBoxLayout()
        row1.addWidget(StrongBodyLabel("Target URL:", ctrl_card))
        self.target_url = LineEdit(ctrl_card)
        self.target_url.setText("http://dana:8085")
        row1.addWidget(self.target_url)
        
        row1.addSpacing(20)
        row1.addWidget(StrongBodyLabel("Dana Host:", ctrl_card))
        self.dana_host = LineEdit(ctrl_card)
        self.dana_host.setPlaceholderText("e.g. root@dana")
        self.dana_host.setText("root@dana")
        row1.addWidget(self.dana_host)
        
        ctrl_layout.addLayout(row1)

        btn_row = QHBoxLayout()
        self.start_btn = PrimaryPushButton(FIF.PLAY, "Tests starten", ctrl_card)
        self.start_btn.clicked.connect(self._on_start)
        btn_row.addWidget(self.start_btn)

        self.stop_btn = PushButton(FIF.CLOSE, "Stoppen", ctrl_card)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._on_stop)
        btn_row.addWidget(self.stop_btn)

        self.open_reports_btn = TransparentPushButton(FIF.FOLDER, "Ergebnisse öffnen", ctrl_card)
        self.open_reports_btn.clicked.connect(self._on_open_reports)
        btn_row.addWidget(self.open_reports_btn)
        
        btn_row.addStretch()
        ctrl_layout.addLayout(btn_row)
        layout.addWidget(ctrl_card)

        # Log View
        self.log_view = TextEdit(self)
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet(get_log_stylesheet())
        layout.addWidget(self.log_view)

        self._worker = None
        self._update_result_card()

    def _update_result_card(self):
        """Updates the recent result card from the latest report file"""
        info = _get_latest_gui_test_report_info()
        if not info:
            self.result_card.setVisible(False)
            self.tests_label.setVisible(False)
            self.tests_scroll.setVisible(False)
            return

        self.result_card.setVisible(True)
        
        # Determine status
        if info["failures"] == 0:
            status = "✅ BESTANDEN"
            color = "#4ec9b0" if isDarkTheme() else "#107c10"
        else:
            status = f"❌ FEHLGESCHLAGEN ({info['failures']} Fehler)"
            color = "#f14c4c" if isDarkTheme() else "#d13438"
            
        self.res_title.setText(status)
        self.res_title.setStyleSheet(f"color: {color};")
        
        details = (
            f"Version:   v{info['version']}\n"
            f"Zeitpunkt: {info['timestamp']}\n"
            f"Umfang:    {info['tests_run']} Interaktionen"
        )
        self.res_details.setText(details)

        # Update detailed list
        self.tests_label.setVisible(True)
        self.tests_scroll.setVisible(True)
        
        # Clear old items
        while self.tests_layout.count():
            item = self.tests_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        if not info["components"]:
            self.tests_layout.addWidget(BodyLabel("Keine Komponenten-Info verfügbar.", self.tests_container))
        else:
            # Component mapping for human readable names
            MAPPING = {
                "/": "Dashboard (Übersicht)",
                "/workers": "Scan-Worker & Nodes",
                "/scan-profiles": "Scan-Profile",
                "/targets": "Angriffsfläche & Ziele",
                "/tenants": "Mandanten-Verwaltung",
                "/settings": "System-Einstellungen",
                "/logs": "Audit-Logs",
                "/reports": "Berichte & Compliance",
                "/portfolio": "Portfolio-Management",
                "/profile": "Benutzerprofil",
                "/developer": "Entwickler-Portal",
                "/integrations": "Integrationen (Jira/GitHub)",
                "/tags": "Asset-Tagging",
                "/notifications/admin": "Admin-Benachrichtigungen",
                "/storage": "Backup & Storage"
            }

            for comp in info["components"]:
                row = QFrame(self.tests_container)
                row.setStyleSheet("QFrame { background-color: rgba(0,0,0,5); border-radius: 4px; }")
                row_layout = QHBoxLayout(row)
                row_layout.setContentsMargins(10, 5, 10, 5)
                
                status_lbl = BodyLabel(comp["status"], row)
                status_lbl.setFixedWidth(30)
                row_layout.addWidget(status_lbl)
                
                path = comp["path"]
                name = MAPPING.get(path, path)
                name_lbl = BodyLabel(f"<b>{name}</b>", row)
                name_lbl.setFixedWidth(200)
                row_layout.addWidget(name_lbl)
                
                path_lbl = BodyLabel(f"<span style='color: gray;'>{path}</span>", row)
                row_layout.addWidget(path_lbl)
                
                row_layout.addStretch()
                
                self.tests_layout.addWidget(row)
            self.tests_layout.addStretch()

    def _log(self, msg: str, level: str = "info"):
        _insert_log_line(self.log_view, msg, level)

    def _on_start(self):
        self.log_view.clear()
        self._log("Initialisiere GUI-Tests...", "info")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        self._worker = GuiTestWorker(self.target_url.text(), self.dana_host.text())
        self._worker.signals.log_message.connect(self._log)
        self._worker.signals.operation_finished.connect(self._on_finished)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _on_stop(self):
        if self._worker:
            self._worker.cancel()
            self._log("Stoppen angefordert...", "warning")

    def _on_finished(self, ok: bool, msg: str):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._worker = None
        self._update_result_card()
        if ok:
            InfoBar.success("Erfolg", msg, parent=self, duration=5000)
        else:
            InfoBar.error("Fehler", msg, parent=self, duration=8000)

    def _on_open_reports(self):
        reports_path = Path(__file__).parent.parent / "tests" / "results"
        if not reports_path.exists():
            reports_path.mkdir(parents=True, exist_ok=True)
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QUrl
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(reports_path)))


class DevCredsPage(SmoothScrollArea):
    """Dev credentials and URLs overview page"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("devCredsPage")
        self.setWidgetResizable(True)

        container = QWidget()
        self.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(16)

        layout.addWidget(TitleLabel("Dev Credentials & URLs", self))
        layout.addWidget(BodyLabel(
            "Alle Zugangsdaten für die lokale Entwicklungsumgebung (docker compose up).", self
        ))

        SERVICES = [
            {
                "title": "YADS API",
                "entries": [
                    ("URL",      "http://localhost:8085", None, None),
                    ("Lokaler Admin", None, "admin", "admin"),
                    ("OIDC Scanner",  None, "frischkorn-scanner", "Scanner1234!"),
                    ("OIDC Admin",    None, "frischkorn-admin",   "Admin1234!"),
                    ("OIDC Auditor",  None, "frischkorn-auditor", "Auditor1234!"),
                ],
            },
            {
                "title": "Keycloak",
                "entries": [
                    ("URL",           "http://localhost:8080", None, None),
                    ("Admin Console", "http://localhost:8080/admin/master/console/", None, None),
                    ("Admin User",    None, "admin", "admin"),
                    ("Realm",         None, "frischkorn", None),
                ],
            },
            {
                "title": "Grafana",
                "entries": [
                    ("URL",   "http://localhost:3000", None, None),
                    ("Login", None, "admin", "admin"),
                ],
            },
            {
                "title": "Prometheus",
                "entries": [
                    ("URL",     "http://localhost:9090", None, None),
                    ("Auth",    None, "(kein Login)", None),
                ],
            },
            {
                "title": "MinIO",
                "entries": [
                    ("URL (Console)", "http://localhost:9001", None, None),
                    ("URL (API)",     "http://localhost:9000", None, None),
                    ("Login",         None, "minioadmin", "minioadmin123"),
                ],
            },
            {
                "title": "PostgreSQL",
                "entries": [
                    ("Host",     None, "localhost:5432", None),
                    ("Datenbank", None, "yads", None),
                    ("Login",    None, "yads", "yads_dev_local"),
                ],
            },
            {
                "title": "Redis",
                "entries": [
                    ("URL", "redis://localhost:6379/0", None, None),
                    ("Auth", None, "(kein Login)", None),
                ],
            },
        ]

        for svc in SERVICES:
            card = CardWidget(container)
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(24, 16, 24, 16)
            card_layout.setSpacing(10)

            card_layout.addWidget(SubtitleLabel(svc["title"], card))

            for label, url, user, password in svc["entries"]:
                row = QHBoxLayout()
                row.setSpacing(8)

                lbl = BodyLabel(f"<b>{label}:</b>", card)
                lbl.setFixedWidth(120)
                row.addWidget(lbl)

                if url:
                    link = TransparentPushButton(url, card)
                    link.setFixedHeight(28)
                    link.clicked.connect(lambda checked=False, u=url: self._open_url(u))
                    row.addWidget(link)
                elif user:
                    user_lbl = BodyLabel(user, card)
                    row.addWidget(user_lbl)
                if password:
                    row.addStretch()
                    pw_lbl = BodyLabel("●●●●●●●●", card)
                    pw_lbl.setToolTip(password)
                    row.addWidget(pw_lbl)
                    copy_btn = PushButton("Kopieren", card)
                    copy_btn.setFixedWidth(90)
                    copy_btn.setFixedHeight(28)
                    copy_btn.clicked.connect(lambda checked=False, p=password: self._copy(p))
                    row.addWidget(copy_btn)
                else:
                    row.addStretch()

                card_layout.addLayout(row)

            layout.addWidget(card)

        layout.addStretch()

    def _open_url(self, url: str):
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QUrl
        QDesktopServices.openUrl(QUrl(url))

    def _copy(self, text: str):
        QApplication.clipboard().setText(text)
        InfoBar.success(
            title="Kopiert",
            content=f"In die Zwischenablage kopiert.",
            duration=1500,
            parent=self,
            position=InfoBarPosition.TOP_RIGHT,
        )


class BugReportPage(QWidget):
    """Shows bug reports fetched from the support portal admin API."""

    _STATUS_COLORS = {
        "new":      "#ef4444",   # red
        "open":     "#f59e0b",   # amber
        "resolved": "#22c55e",   # green
    }

    _notify_signal = Signal(str, str, str)   # report_id, customer, status
    _fetch_done_signal = Signal(list, str)   # reports, error

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("bugReportPage")
        self._reports = []
        self._config_file = Path.home() / ".yads" / "release_gui.yaml"
        self._known_ids: set = set()
        self._setup_ui()
        self._notify_signal.connect(self._show_desktop_notification)
        self._fetch_done_signal.connect(self._on_fetch_done)
        self._start_poll_timer()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def _setup_ui(self):
        from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView

        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(16)

        # Header
        layout.addWidget(TitleLabel("Bug Reports", self))
        self.sub_label = BodyLabel("Klicke auf einen Report, um ihn im Support-Portal zu öffnen.", self)
        layout.addWidget(self.sub_label)

        # Toolbar
        tb = CardWidget(self)
        tb_row = QHBoxLayout(tb)
        tb_row.setContentsMargins(12, 8, 12, 8)

        self.filter_combo = ComboBox(self)
        self.filter_combo.addItems(["Alle", "new", "open", "resolved"])
        self.filter_combo.setFixedWidth(140)
        self.filter_combo.currentTextChanged.connect(self._apply_filter)
        tb_row.addWidget(BodyLabel("Status:", self))
        tb_row.addWidget(self.filter_combo)
        tb_row.addStretch()

        self.status_label = BodyLabel("", self)
        tb_row.addWidget(self.status_label)

        self.refresh_btn = PrimaryPushButton(FIF.SYNC, "Aktualisieren", self)
        self.refresh_btn.clicked.connect(self._fetch)
        tb_row.addWidget(self.refresh_btn)

        layout.addWidget(tb)

        # Table
        tbl_card = CardWidget(self)
        tbl_layout = QVBoxLayout(tbl_card)
        tbl_layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Status", "Report-ID", "Kunde", "Version", "Datum", "Beschreibung"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 130)
        self.table.setColumnWidth(2, 160)
        self.table.setColumnWidth(3, 70)
        self.table.setColumnWidth(4, 130)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.cellDoubleClicked.connect(self._on_row_double_click)
        self.table.cellClicked.connect(self._on_row_click)

        tbl_layout.addWidget(self.table)
        layout.addWidget(tbl_card, 1)

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------
    def _load_cfg(self):
        try:
            import yaml
            with open(self._config_file) as f:
                data = yaml.safe_load(f) or {}
            url = data.get('support_portal_url', '').strip()
            token = data.get('support_admin_token', '').strip()
            return url, token
        except Exception:
            return '', ''

    # ------------------------------------------------------------------
    # Data fetch (background thread)
    # ------------------------------------------------------------------
    def _fetch(self):
        self.refresh_btn.setEnabled(False)
        self.status_label.setText("Lade…")

        url, token = self._load_cfg()
        if not url or not token:
            self.status_label.setText("⚠ Support-Portal URL / Token fehlt (Einstellungen → Support Portal)")
            self.refresh_btn.setEnabled(True)
            return

        def _worker():
            import urllib.request, urllib.error, json as _json, ssl
            ctx = ssl.create_default_context()
            try:
                req = urllib.request.Request(
                    f"{url.rstrip('/')}/api/admin/reports",
                    headers={"Authorization": f"Bearer {token}"},
                )
                with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                    data = _json.loads(resp.read())
                    return data.get("reports", []), None
            except urllib.error.HTTPError as e:
                return [], f"HTTP {e.code}: {e.read().decode()[:120]}"
            except Exception as e:
                return [], str(e)

        def _thread():
            reports, err = _worker()
            self._fetch_done_signal.emit(reports, err or "")

        threading.Thread(target=_thread, daemon=True).start()

    @Slot(list, str)
    def _on_fetch_done(self, reports, err):
        self.refresh_btn.setEnabled(True)
        if err:
            self.status_label.setText(f"⚠ {err}")
            InfoBar.error("Fehler", err, parent=self, position=InfoBarPosition.TOP, duration=5000)
            return
        self._reports = reports
        self._known_ids = {r["report_id"] for r in reports}
        self._apply_filter(self.filter_combo.currentText())
        self.status_label.setText(f"{len(reports)} Report(s)")

    # ------------------------------------------------------------------
    # Table population
    # ------------------------------------------------------------------
    def _apply_filter(self, status_text: str):
        from PySide6.QtWidgets import QTableWidgetItem
        reports = self._reports
        if status_text and status_text != "Alle":
            reports = [r for r in reports if r.get("status") == status_text]

        self.table.setRowCount(len(reports))
        for row, r in enumerate(reports):
            status = r.get("status", "?")
            color = self._STATUS_COLORS.get(status, "#94a3b8")

            status_item = QTableWidgetItem(status.upper())
            status_item.setForeground(QColor(color))
            font = QFont()
            font.setBold(True)
            status_item.setFont(font)
            self.table.setItem(row, 0, status_item)

            self.table.setItem(row, 1, QTableWidgetItem(r.get("report_id", "")))
            self.table.setItem(row, 2, QTableWidgetItem(r.get("customer_name", "")))
            self.table.setItem(row, 3, QTableWidgetItem(r.get("yads_version", "")))

            # Format date
            dt_raw = r.get("submitted_at", "")
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(dt_raw.replace("Z", "+00:00"))
                dt_str = dt.strftime("%d.%m.%Y %H:%M")
            except Exception:
                dt_str = dt_raw[:16]
            self.table.setItem(row, 4, QTableWidgetItem(dt_str))

            desc = r.get("description", "")[:100]
            self.table.setItem(row, 5, QTableWidgetItem(desc))

            # Store report_id in row for click handler
            for col in range(6):
                item = self.table.item(row, col)
                if item:
                    item.setData(Qt.ItemDataRole.UserRole, r.get("report_id", ""))

    # ------------------------------------------------------------------
    # Click handlers
    # ------------------------------------------------------------------
    def _on_row_click(self, row, _col):
        """Single click: show report-id in status bar."""
        item = self.table.item(row, 1)
        if item:
            self.status_label.setText(f"→ {item.text()}  (Doppelklick zum Öffnen)")

    def _on_row_double_click(self, row, _col):
        """Double click: open report in browser."""
        item = self.table.item(row, 0)
        if not item:
            return
        report_id = item.data(Qt.ItemDataRole.UserRole)
        if not report_id:
            return

        url, _ = self._load_cfg()
        if not url:
            InfoBar.warning("Keine URL", "Support-Portal URL in den Einstellungen konfigurieren.",
                            parent=self, position=InfoBarPosition.TOP)
            return

        import webbrowser
        portal_url = f"{url.rstrip('/')}/reports/{report_id}"
        webbrowser.open(portal_url)
        self.status_label.setText(f"Geöffnet: {portal_url}")

    # ------------------------------------------------------------------
    # Background polling + desktop notifications
    # ------------------------------------------------------------------
    def _start_poll_timer(self):
        from PySide6.QtCore import QTimer
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(5 * 60 * 1000)  # every 5 minutes
        self._poll_timer.timeout.connect(self._poll_for_new_reports)
        self._poll_timer.start()

    def _poll_for_new_reports(self):
        """Fetch reports silently; notify for any new report IDs."""
        url, token = self._load_cfg()
        if not url or not token:
            return

        def _worker():
            import urllib.request, urllib.error, json as _json
            try:
                req = urllib.request.Request(
                    f"{url.rstrip('/')}/api/admin/reports",
                    headers={"Authorization": f"Bearer {token}"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return _json.loads(resp.read()).get("reports", [])
            except Exception:
                return []

        def _on_done(reports):
            if not reports:
                return
            # First run: just seed known IDs without notifying
            if not self._known_ids:
                self._known_ids = {r["report_id"] for r in reports}
                return
            for r in reports:
                rid = r.get("report_id", "")
                if rid and rid not in self._known_ids:
                    self._known_ids.add(rid)
                    self._notify_signal.emit(
                        rid,
                        r.get("customer_name", "?"),
                        r.get("status", "new"),
                    )
            # Keep main table in sync
            self._reports = reports
            self._apply_filter(self.filter_combo.currentText())
            self.status_label.setText(f"{len(reports)} Report(s)")

        def _thread():
            result = _worker()
            from PySide6.QtCore import QTimer
            QTimer.singleShot(0, lambda: _on_done(result))

        threading.Thread(target=_thread, daemon=True).start()

    @Slot(str, str, str)
    def _show_desktop_notification(self, report_id: str, customer: str, status: str):
        """Fire a Linux desktop notification via notify-send."""
        import subprocess
        try:
            subprocess.Popen([
                "notify-send",
                "--urgency=normal",
                "--icon=dialog-warning",
                "--app-name=YADS Release Manager",
                f"Neuer Bug Report: {report_id}",
                f"Kunde: {customer}  |  Status: {status}",
            ])
        except FileNotFoundError:
            pass  # notify-send not available (non-Linux)

    def showEvent(self, event):
        """Auto-refresh when page becomes visible (only if table is empty)."""
        super().showEvent(event)
        if self.table.rowCount() == 0:
            self._fetch()


class MainWindow(FluentWindow):
    """Main application window with fluent navigation"""

    def __init__(self):
        super().__init__()

        self.setWindowTitle("YADS Release Manager")
        self.setMinimumSize(1000, 700)
        self.resize(1100, 800)

        # Load saved theme preference or detect from system
        self.is_dark = self._load_theme_preference()
        if self.is_dark:
            setTheme(Theme.DARK)
        else:
            setTheme(Theme.LIGHT)
        setThemeColor("#0078d4")  # Windows blue

        # Create pages
        self.release_page = ReleasePage(self)
        self.local_deploy_page = LocalDeployPage(self)
        self.prod_deploy_page = ProdDeployPage(self)
        self.testlab_page = TestLabPage(self)
        self.dana_deploy_page = DanaDeployPage(self)
        self.test_manager_page = TestManagerPage(self)
        self.gui_tests_page = GuiTestsPage(self)
        self.dev_creds_page = DevCredsPage(self)
        self.bug_report_page = BugReportPage(self)
        self.settings_page = SettingsPage(self)
        self.about_page = AboutPage(self)

        # Create theme toggle widget
        self.theme_toggle = ThemeToggleWidget(self)
        self.theme_toggle.themeChanged.connect(self._on_theme_changed)

        self._init_navigation()

        # Center window
        self._center_window()

    def _load_theme_preference(self) -> bool:
        """Load saved theme preference or detect from system"""
        import json
        config_file = Path.home() / ".yads" / "release_manager_settings.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    data = json.load(f)
                    return data.get("dark_mode", False)
            except:
                pass
        return detect_system_dark_mode()

    @Slot(bool)
    def _on_theme_changed(self, is_dark: bool):
        """Handle theme change - update stylesheets"""
        self.is_dark = is_dark
        # Update log view stylesheet
        if hasattr(self.release_page, 'log_view'):
            self.release_page.log_view.setStyleSheet(get_log_stylesheet())
        if hasattr(self.local_deploy_page, 'log_view'):
            self.local_deploy_page.log_view.setStyleSheet(get_log_stylesheet())
        if hasattr(self.testlab_page, 'log_view'):
            self.testlab_page.log_view.setStyleSheet(get_log_stylesheet())
        if hasattr(self.dana_deploy_page, 'log_view'):
            self.dana_deploy_page.log_view.setStyleSheet(get_log_stylesheet())
        if hasattr(self.test_manager_page, 'log_view'):
            self.test_manager_page.log_view.setStyleSheet(get_log_stylesheet())

    def _init_navigation(self):
        """Initialize navigation sidebar"""
        # Add pages to stacked widget
        self.addSubInterface(self.release_page, FIF.PLAY, "Release")
        self.addSubInterface(self.local_deploy_page, FIF.APPLICATION, "Local Env")
        self.addSubInterface(self.prod_deploy_page, FIF.SEND, "Update PROD")
        self.addSubInterface(self.testlab_page, FIF.EDUCATION, "Test Lab")
        self.addSubInterface(self.dana_deploy_page, FIF.CLOUD, "Dana Test")
        self.addSubInterface(self.test_manager_page, FIF.CHECKBOX, "Test Manager")
        self.addSubInterface(self.gui_tests_page, FIF.ACCEPT, "GUI Tests")
        self.addSubInterface(self.dev_creds_page, FIF.DEVELOPER_TOOLS, "Dev Creds")
        self.addSubInterface(self.bug_report_page, FIF.FEEDBACK, "Bug Reports")
        self.addSubInterface(self.settings_page, FIF.SETTING, "Settings")

        # Add about at bottom
        self.addSubInterface(
            self.about_page, FIF.INFO, "About",
            position=NavigationItemPosition.BOTTOM
        )

        # Add theme toggle at bottom of navigation
        self.navigationInterface.addWidget(
            routeKey="themeToggle",
            widget=self.theme_toggle,
            onClick=lambda: None,
            position=NavigationItemPosition.BOTTOM
        )

        # Set default
        self.navigationInterface.setCurrentItem(self.release_page.objectName())

    def _center_window(self):
        """Center window on screen"""
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)


def main():
    # Enable high DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("YADS Release Manager")

    # Set window icon
    icon_path = script_dir / "yads_release_manager_logo.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    window = MainWindow()
    window.show()

    # Ensure application doesn't accidentally quit
    app.setQuitOnLastWindowClosed(True)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
