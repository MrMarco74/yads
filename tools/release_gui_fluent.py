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
from pathlib import Path
from typing import Optional

# Add the tools directory to path
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

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
        if ssh_host and ssh_user:
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


class ProdDeployWorker(QThread):
    """Worker thread for PROD deployment (Update path only)"""

    def __init__(self, project_root: Path):
        super().__init__()
        self.project_root = project_root
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

        # Configuration from manual_deploy.sh
        self.docker_compose_file = "docker-compose.swarm.yml"
        self.registry_image = "gitlab.example.internal:5050/apps/yads/yads:latest"
        self.backup_registry_image = "gitlab.example.internal:5050/apps/yads/yads-backup:latest"
        self.services_to_update = [
            f"{self.stack_name}_yads-api",
            f"{self.stack_name}_yads-worker",
            f"{self.stack_name}_yads-worker-primary",
            f"{self.stack_name}_yads-backup"
        ]

    def run(self):
        try:
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

    def _execute_deploy(self):
        try:
            self._log("🚀 Starting Production Deployment (Update Path)", "success")
            self.signals.progress_update.emit(0, 100, "Initializing connection...")
            
            # 0. Establish Master Connection
            self._log("Establishing persistent SSH connection...", "info")
            if not self._run_cmd(["ssh", "-fN", self.remote_host]):
                self._log("Warning: Could not start ControlMaster, will proceed with standard connections", "warning")

            # 1. Local Build
            self._log("Step 1/8: Building YADS Docker image locally...", "info")
            self.signals.progress_update.emit(5, 100, "Building YADS image...")
            if not self._run_cmd(["docker", "build", "--target", "prod", "-t", "yads:latest", "."]):
                return self.signals.operation_finished.emit(False, "Build failed")

            self._log("Tagging image...", "info")
            if not self._run_cmd(["docker", "tag", "yads:latest", self.registry_image]):
                return self.signals.operation_finished.emit(False, "Tagging failed")

            self._log("Step 2/8: Building backup container image...", "info")
            self.signals.progress_update.emit(15, 100, "Building backup image...")
            if not self._run_cmd(["docker", "build", "-t", "yads-backup:latest", "backup/"]):
                return self.signals.operation_finished.emit(False, "Backup build failed")

            if not self._run_cmd(["docker", "tag", "yads-backup:latest", self.backup_registry_image]):
                return self.signals.operation_finished.emit(False, "Backup tagging failed")

            # 2. Transfer
            self._log("Step 3/8: Compressing images...", "info")
            self.signals.progress_update.emit(25, 100, "Compressing images...")
            if not self._run_cmd(f"docker save {self.registry_image} | gzip > yads_deploy.tgz", shell=True):
                return self.signals.operation_finished.emit(False, "Compression failed")
            
            if not self._run_cmd(f"docker save {self.backup_registry_image} | gzip > yads_backup_deploy.tgz", shell=True):
                return self.signals.operation_finished.emit(False, "Backup compression failed")

            self._log("Step 4/8: Transferring images to PROD (rsync)...", "info")
            self.signals.progress_update.emit(40, 100, "Transferring images...")
            self._run_cmd(["ssh", self.remote_host, f"mkdir -p {self.remote_deploy_dir}"])
            # Use rsync for progress reporting
            rsync_cmd = ["rsync", "--info=progress2", "yads_deploy.tgz", "yads_backup_deploy.tgz", f"{self.remote_host}:{self.remote_deploy_dir}/"]
            if not self._run_cmd(rsync_cmd, is_rsync=True):
                self._log("Rsync failed or not found, falling back to scp...", "warning")
                if not self._run_cmd(["scp", "yads_deploy.tgz", "yads_backup_deploy.tgz", f"{self.remote_host}:{self.remote_deploy_dir}/"]):
                    return self.signals.operation_finished.emit(False, "Transfer failed")

            # 3. Load
            self._log("Step 5/8: Loading images on remote host (combined session)...", "info")
            self.signals.progress_update.emit(80, 100, "Loading images on remote...")
            load_cmd = (
                f"gunzip -c {self.remote_deploy_dir}/yads_deploy.tgz | docker load && "
                f"gunzip -c {self.remote_deploy_dir}/yads_backup_deploy.tgz | docker load"
            )
            if not self._run_cmd(["ssh", self.remote_host, load_cmd]):
                return self.signals.operation_finished.emit(False, "Remote docker load failed")

            # 4. Config
            self._log("Step 6/8: Transferring configuration...", "info")
            self.signals.progress_update.emit(90, 100, "Transferring config...")
            if not self._run_cmd(["scp", self.docker_compose_file, f"{self.remote_host}:{self.remote_deploy_dir}/"]):
                return self.signals.operation_finished.emit(False, "Config transfer failed")
            
            if (self.project_root / ".env").exists():
                self._run_cmd(["scp", ".env", f"{self.remote_host}:{self.remote_deploy_dir}/"])

            # 5. Deploy & Update
            self._log("Step 7/8: Deploying stack and forcing updates...", "info")
            self.signals.progress_update.emit(95, 100, "Finalizing deployment...")
            
            combined_deploy_cmd = [
                f"cd {self.remote_deploy_dir}",
                "set -a && [ -f .env ] && source .env; set +a",
                f"docker stack deploy -c {self.docker_compose_file} {self.stack_name}"
            ]
            for service in self.services_to_update:
                img = self.backup_registry_image if "backup" in service else self.registry_image
                combined_deploy_cmd.append(f"docker service update --force --image {img} {service}")
                
            full_remote_cmd = " && ".join(combined_deploy_cmd)
            
            if not self._run_cmd(["ssh", self.remote_host, full_remote_cmd]):
                return self.signals.operation_finished.emit(False, "Remote deployment/update failed")

            self.signals.progress_update.emit(100, 100, "Success!")
            self._log("✅ Deployment to PROD completed successfully!", "success")
            self.signals.operation_finished.emit(True, "PROD Update finished")

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
        self.info_bar = InfoBar.warning(
            "Production Update",
            "This will only update the existing stack. No data will be wiped. Destined for: root@prod.example.com",
            parent=self,
            isClosable=False,
            position=InfoBarPosition.NONE
        )
        layout.addWidget(self.info_bar)

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
        log_title = SubtitleLabel("Deployment Logs", self)
        log_header.addWidget(log_title)
        log_header.addStretch()

        clear_btn = TransparentPushButton(FIF.DELETE, "Clear", self)
        clear_btn.clicked.connect(self._clear_logs)
        log_header.addWidget(clear_btn)
        log_layout.addLayout(log_header)

        self.log_view = TextEdit(self)
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(350)
        self.log_view.setStyleSheet(get_log_stylesheet())
        log_layout.addWidget(self.log_view)

        layout.addWidget(log_card, 1)

    def _on_deploy(self):
        box = MessageBox(
            "Confirm Production Deployment",
            "You are about to start a LIVE deployment to prod.example.com.\n\n"
            "This will build, transfer, and update the application services.\n"
            "No data will be wiped.\n\n"
            "Proceed?",
            self
        )
        if box.exec():
            self._start_worker()

    def _start_worker(self):
        self.deploy_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.indeterminate_progress.setVisible(False)
        self.log_view.clear()

        self.worker = ProdDeployWorker(script_dir.parent)
        self.worker.signals.log_message.connect(self._on_log)
        self.worker.signals.operation_finished.connect(self._on_finished)
        self.worker.signals.progress_update.connect(self._on_progress)
        self.worker.start()

    def _on_progress(self, current: int, total: int, description: str):
        self.progress_bar.setValue(current)
        self.progress_label.setText(description)
        # If it's a long static step, show indeterminate instead? 
        # For now rsync gives real progress.
        if current > 0 and current < 100:
            self.progress_bar.setVisible(True)
            self.indeterminate_progress.setVisible(False)
        elif current == 0:
            self.indeterminate_progress.setVisible(True)
            self.progress_bar.setVisible(False)

    def _on_cancel(self):
        if self.worker:
            self.worker.cancel()
            self._log("Cancel requested... terminating deployment.", "warning")

    def _on_log(self, message: str, level: str):
        self._log(message, level)

    def _log(self, message: str, level: str = "info"):
        dark = isDarkTheme()
        if dark:
            colors = {"info": "#d4d4d4", "success": "#4ec9b0", "warning": "#dcdcaa", "error": "#f14c4c"}
            timestamp_color = "#6a9955"
        else:
            colors = {"info": "#1e1e1e", "success": "#107c10", "warning": "#ca5010", "error": "#d13438"}
            timestamp_color = "#107c10"

        color = colors.get(level, colors["info"])
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")

        html = f'<span style="color: {timestamp_color};">[{timestamp}]</span> <span style="color: {color};">{message}</span><br>'
        cursor = self.log_view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_view.setTextCursor(cursor)
        self.log_view.insertHtml(html)
        self.log_view.ensureCursorVisible()

    def _clear_logs(self):
        self.log_view.clear()

    def _on_finished(self, success: bool, message: str):
        self.deploy_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.indeterminate_progress.stop()
        self.indeterminate_progress.setVisible(False)
        self.progress_label.setText("Complete" if success else "Failed")

        if success:
            InfoBar.success("Deployment Complete", message, parent=self, position=InfoBarPosition.TOP, duration=5000)
            self._log(message, "success")
        else:
            InfoBar.error("Deployment Failed", message, parent=self, position=InfoBarPosition.TOP, duration=8000)
            self._log(message, "error")

        self.worker = None


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

        self.worker = ReleaseWorker(operation, params, script_dir.parent)
        self.worker.signals.log_message.connect(self._on_log)
        self.worker.signals.operation_finished.connect(self._on_finished)
        self.worker.start()

    def _on_cancel(self):
        """Cancel current operation"""
        if self.worker:
            self.worker.cancel()
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
        """Add message to log view"""
        dark = isDarkTheme()

        if dark:
            colors = {
                "info": "#d4d4d4",
                "success": "#4ec9b0",
                "warning": "#dcdcaa",
                "error": "#f14c4c"
            }
            timestamp_color = "#6a9955"
        else:
            colors = {
                "info": "#1e1e1e",
                "success": "#107c10",
                "warning": "#ca5010",
                "error": "#d13438"
            }
            timestamp_color = "#107c10"

        color = colors.get(level, colors["info"])

        # Add timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")

        html = f'<span style="color: {timestamp_color};">[{timestamp}]</span> <span style="color: {color};">{message}</span><br>'

        cursor = self.log_view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_view.setTextCursor(cursor)
        self.log_view.insertHtml(html)
        self.log_view.ensureCursorVisible()

    def _clear_logs(self):
        """Clear log view"""
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

        self.worker = None

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
        self.prod_deploy_page = ProdDeployPage(self)
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

    def _init_navigation(self):
        """Initialize navigation sidebar"""
        # Add pages to stacked widget
        self.addSubInterface(self.release_page, FIF.PLAY, "Release")
        self.addSubInterface(self.prod_deploy_page, FIF.SEND, "Update PROD")
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
