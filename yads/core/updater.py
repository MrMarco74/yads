"""
One-Click Update System

Handles in-app updates by:
1. Checking for new Docker image versions
2. Pausing the scan queue gracefully
3. Waiting for active tasks to complete
4. Pulling the latest Docker image
5. Triggering a graceful container restart
"""

import os
import subprocess
import logging
import json
import time
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

import requests

logger = logging.getLogger("yads.core.updater")


class UpdateStatus(str, Enum):
    """Status of the update process."""
    IDLE = "idle"
    CHECKING = "checking"
    AVAILABLE = "available"
    UP_TO_DATE = "up_to_date"
    DOWNLOADING = "downloading"
    PREPARING = "preparing"
    RESTARTING = "restarting"
    FAILED = "failed"
    COMPLETED = "completed"


class ReleaseChannel(str, Enum):
    """Release channel for updates."""
    STABLE = "stable"
    BETA = "beta"


@dataclass
class VersionInfo:
    """Information about a YADS version."""
    version: str
    release_date: str
    changelog: List[str]
    docker_tag: str
    channel: str = "stable"
    is_current: bool = False


@dataclass
class UpdateState:
    """Current state of the update process."""
    status: UpdateStatus
    current_version: str
    current_channel: str = "stable"
    # Stable channel info
    stable_version: Optional[str] = None
    stable_changelog: List[str] = None
    stable_available: bool = False
    # Beta channel info
    beta_version: Optional[str] = None
    beta_changelog: List[str] = None
    beta_available: bool = False
    # Selected update target
    target_channel: Optional[str] = None
    latest_version: Optional[str] = None  # Kept for backwards compatibility
    progress: int = 0
    message: str = ""
    error: Optional[str] = None
    started_at: Optional[str] = None
    changelog: List[str] = None  # Kept for backwards compatibility

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "current_version": self.current_version,
            "current_channel": self.current_channel,
            # Stable channel
            "stable_version": self.stable_version,
            "stable_changelog": self.stable_changelog or [],
            "stable_available": self.stable_available,
            # Beta channel
            "beta_version": self.beta_version,
            "beta_changelog": self.beta_changelog or [],
            "beta_available": self.beta_available,
            # Target
            "target_channel": self.target_channel,
            # Legacy fields for backwards compatibility
            "latest_version": self.latest_version,
            "changelog": self.changelog or [],
            # Progress
            "progress": self.progress,
            "message": self.message,
            "error": self.error,
            "started_at": self.started_at,
        }


class UpdateManager:
    """
    Manages the one-click update process for YADS.

    The update process:
    1. Check for updates (compare current vs latest version)
    2. Pause the scan queue
    3. Wait for active tasks to drain
    4. Pull the new Docker image
    5. Signal for graceful restart

    The actual restart is handled by Docker Compose or orchestrator.
    """

    # Version file inside the container
    VERSION_FILE = "/app/VERSION"

    # Update manifest URLs (can be overridden via environment)
    DEFAULT_MANIFEST_URL = "https://yads.io/api/updates/manifest.json"
    DEFAULT_STABLE_VERSION_URL = "https://yads-security.com/releases/version.json"
    DEFAULT_BETA_VERSION_URL = "https://yads-security.com/releases/version-beta.json"

    # Docker image name
    DOCKER_IMAGE = os.getenv("YADS_DOCKER_IMAGE", "yads/yads")

    # Maximum wait time for tasks to drain (seconds)
    MAX_DRAIN_WAIT = 300  # 5 minutes

    # Restart signal file (watched by entrypoint script)
    RESTART_SIGNAL_FILE = "/app/.restart_requested"

    def __init__(self):
        self._state = UpdateState(
            status=UpdateStatus.IDLE,
            current_version=self._get_current_version(),
            current_channel=self._get_current_channel()
        )
        self._manifest_url = os.getenv("YADS_UPDATE_MANIFEST_URL", self.DEFAULT_MANIFEST_URL)
        self._stable_version_url = os.getenv("YADS_STABLE_VERSION_URL", self.DEFAULT_STABLE_VERSION_URL)
        self._beta_version_url = os.getenv("YADS_BETA_VERSION_URL", self.DEFAULT_BETA_VERSION_URL)

    def _get_current_version(self) -> str:
        """Get the current YADS version."""
        try:
            if os.path.exists(self.VERSION_FILE):
                with open(self.VERSION_FILE, "r") as f:
                    return f.read().strip()
        except Exception as e:
            logger.warning(f"Could not read version file: {e}")

        # Fallback to environment or default
        return os.getenv("YADS_VERSION", "1.15.0")

    def _get_current_channel(self) -> str:
        """Get the current YADS release channel."""
        # Check for channel file
        channel_file = "/app/CHANNEL"
        try:
            if os.path.exists(channel_file):
                with open(channel_file, "r") as f:
                    return f.read().strip().lower()
        except Exception:
            pass

        # Fallback to environment or default
        return os.getenv("YADS_CHANNEL", "stable")

    @property
    def state(self) -> UpdateState:
        """Get the current update state."""
        return self._state

    def get_state_dict(self) -> Dict[str, Any]:
        """Get the current state as a dictionary."""
        return self._state.to_dict()

    def check_for_updates(self, force_check: bool = False) -> Tuple[bool, Optional[VersionInfo]]:
        """
        Check if updates are available on both stable and beta channels.

        Args:
            force_check: Skip cache and always check remote.

        Returns:
            Tuple of (updates_available, version_info for primary channel)
        """
        self._state.status = UpdateStatus.CHECKING
        self._state.message = "Checking for updates..."
        self._state.error = None

        # Reset availability flags
        self._state.stable_available = False
        self._state.beta_available = False

        try:
            # Check stable channel
            stable_info = self._fetch_channel_version(self._stable_version_url, "stable")
            if stable_info:
                self._state.stable_version = stable_info.version
                self._state.stable_changelog = stable_info.changelog
                if self._compare_versions(stable_info.version, self._state.current_version) > 0:
                    self._state.stable_available = True
                    logger.info(f"Stable update available: {self._state.current_version} -> {stable_info.version}")

            # Check beta channel
            beta_info = self._fetch_channel_version(self._beta_version_url, "beta")
            if beta_info:
                self._state.beta_version = beta_info.version
                self._state.beta_changelog = beta_info.changelog
                if self._compare_versions(beta_info.version, self._state.current_version) > 0:
                    self._state.beta_available = True
                    logger.info(f"Beta update available: {self._state.current_version} -> {beta_info.version}")

            # Determine overall status and set legacy fields for backwards compatibility
            any_available = self._state.stable_available or self._state.beta_available

            if any_available:
                self._state.status = UpdateStatus.AVAILABLE
                # Prefer stable for legacy fields, but show beta if that's all that's available
                if self._state.stable_available:
                    self._state.latest_version = self._state.stable_version
                    self._state.changelog = self._state.stable_changelog
                    self._state.message = f"Stable update available: {self._state.stable_version}"
                else:
                    self._state.latest_version = self._state.beta_version
                    self._state.changelog = self._state.beta_changelog
                    self._state.message = f"Beta update available: {self._state.beta_version}"

                return True, stable_info or beta_info
            else:
                self._state.status = UpdateStatus.UP_TO_DATE
                self._state.message = "YADS is up to date"
                self._state.latest_version = self._state.current_version
                logger.info("YADS is up to date")
                return False, stable_info

        except Exception as e:
            self._state.status = UpdateStatus.FAILED
            self._state.error = str(e)
            self._state.message = f"Update check failed: {e}"
            logger.error(f"Update check failed: {e}")
            return False, None

    def _fetch_channel_version(self, url: str, channel: str) -> Optional[VersionInfo]:
        """
        Fetch version info from a channel's version.json file.

        Args:
            url: URL to the version.json file
            channel: Channel name ('stable' or 'beta')

        Returns:
            VersionInfo if successful, None otherwise
        """
        try:
            response = requests.get(
                url,
                timeout=10,
                headers={"User-Agent": f"YADS-Updater/{self._state.current_version}"}
            )

            if response.status_code == 200:
                data = response.json()
                version = data.get("version", "")
                changelog_text = data.get("text", "")

                # Parse changelog text into list
                changelog = [changelog_text] if changelog_text else []

                return VersionInfo(
                    version=version,
                    release_date="",
                    changelog=changelog,
                    docker_tag=f"v{version}",
                    channel=channel,
                    is_current=(version == self._state.current_version)
                )

            elif response.status_code == 404:
                logger.debug(f"No {channel} version file found at {url}")
                return None
            else:
                logger.warning(f"Unexpected response from {channel} channel: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not fetch {channel} version: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {channel} version: {e}")
            return None

    def _check_local_updates(self) -> Tuple[bool, Optional[VersionInfo]]:
        """
        Check for updates using local Docker image tags.
        This is a fallback when the update server is unreachable.
        """
        try:
            # Try to pull latest tag metadata without downloading
            result = subprocess.run(
                ["docker", "image", "inspect", f"{self.DOCKER_IMAGE}:latest"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Image exists locally, check labels
                image_info = json.loads(result.stdout)
                if image_info:
                    labels = image_info[0].get("Config", {}).get("Labels", {})
                    image_version = labels.get("org.opencontainers.image.version", "")

                    if image_version and self._compare_versions(image_version, self._state.current_version) > 0:
                        self._state.status = UpdateStatus.AVAILABLE
                        self._state.latest_version = image_version
                        self._state.message = f"Local update available: {image_version}"
                        return True, VersionInfo(
                            version=image_version,
                            release_date="",
                            changelog=[],
                            docker_tag="latest"
                        )

            self._state.status = UpdateStatus.UP_TO_DATE
            self._state.message = "No local updates found"
            return False, None

        except Exception as e:
            logger.warning(f"Local update check failed: {e}")
            self._state.status = UpdateStatus.UP_TO_DATE
            self._state.message = "Could not check for updates (offline)"
            return False, None

    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two semantic version strings.

        Returns:
            1 if v1 > v2, -1 if v1 < v2, 0 if equal
        """
        def parse_version(v: str) -> List[int]:
            # Remove 'v' prefix if present
            v = v.lstrip('v')
            # Split and convert to integers
            parts = []
            for part in v.split('.'):
                # Handle pre-release suffixes like 1.15.0-beta1
                num = ''.join(c for c in part if c.isdigit())
                parts.append(int(num) if num else 0)
            return parts

        p1, p2 = parse_version(v1), parse_version(v2)

        # Pad shorter version with zeros
        max_len = max(len(p1), len(p2))
        p1.extend([0] * (max_len - len(p1)))
        p2.extend([0] * (max_len - len(p2)))

        for a, b in zip(p1, p2):
            if a > b:
                return 1
            elif a < b:
                return -1
        return 0

    def start_update(self, session=None, target_channel: str = None) -> bool:
        """
        Start the update process.

        This will:
        1. Pause the scan queue
        2. Wait for active tasks to complete
        3. Pull the new Docker image
        4. Signal for restart

        Args:
            session: Database session for queue management.
            target_channel: Target channel to update to ('stable' or 'beta').
                           If None, uses the current channel or stable if update available.

        Returns:
            True if update started successfully, False otherwise.
        """
        if self._state.status not in [UpdateStatus.AVAILABLE, UpdateStatus.IDLE, UpdateStatus.FAILED]:
            logger.warning(f"Cannot start update in state: {self._state.status}")
            return False

        # Determine target channel and version
        if target_channel == "beta":
            if not self._state.beta_available and not self._state.beta_version:
                logger.error("No beta version available")
                return False
            self._state.target_channel = "beta"
            self._state.latest_version = self._state.beta_version
            self._state.changelog = self._state.beta_changelog
            logger.info(f"Targeting BETA channel: {self._state.beta_version}")
        elif target_channel == "stable":
            if not self._state.stable_available and not self._state.stable_version:
                logger.error("No stable version available")
                return False
            self._state.target_channel = "stable"
            self._state.latest_version = self._state.stable_version
            self._state.changelog = self._state.stable_changelog
            logger.info(f"Targeting STABLE channel: {self._state.stable_version}")
        else:
            # Default: prefer stable if available, otherwise beta
            if self._state.stable_available:
                self._state.target_channel = "stable"
                self._state.latest_version = self._state.stable_version
            elif self._state.beta_available:
                self._state.target_channel = "beta"
                self._state.latest_version = self._state.beta_version
            else:
                logger.warning("No update available on any channel")
                return False

        self._state.status = UpdateStatus.PREPARING
        self._state.started_at = datetime.utcnow().isoformat()
        self._state.progress = 0
        self._state.error = None

        try:
            # Step 1: Pause the queue
            self._state.message = "Pausing scan queue..."
            self._state.progress = 10
            if session:
                self._pause_queue(session)

            # Step 2: Wait for active tasks
            self._state.message = "Waiting for active scans to complete..."
            self._state.progress = 20
            self._wait_for_tasks_to_drain()

            # Step 3: Pull new image
            self._state.status = UpdateStatus.DOWNLOADING
            self._state.message = "Downloading update..."
            self._state.progress = 40
            if not self._pull_docker_image():
                raise Exception("Failed to pull Docker image")

            self._state.progress = 80

            # Step 4: Signal restart
            self._state.status = UpdateStatus.RESTARTING
            self._state.message = "Restarting services..."
            self._state.progress = 90
            self._signal_restart()

            self._state.status = UpdateStatus.COMPLETED
            self._state.message = "Update complete. Restarting..."
            self._state.progress = 100

            logger.info("Update process completed successfully")
            return True

        except Exception as e:
            self._state.status = UpdateStatus.FAILED
            self._state.error = str(e)
            self._state.message = f"Update failed: {e}"
            logger.error(f"Update failed: {e}")

            # Try to resume queue on failure
            if session:
                try:
                    self._resume_queue(session)
                except Exception:
                    pass

            return False

    def _pause_queue(self, session):
        """Pause the scan queue."""
        from yads.models import SystemConfig
        from sqlmodel import select

        conf = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
        if conf:
            conf.value = "false"
        else:
            conf = SystemConfig(key="QUEUE_ACTIVE", value="false")
        session.add(conf)
        session.commit()

        # Also cancel Celery consumer
        try:
            from yads.worker import celery_app
            celery_app.control.cancel_consumer('celery', reply=True)
        except Exception as e:
            logger.warning(f"Could not cancel Celery consumer: {e}")

        logger.info("Scan queue paused")

    def _resume_queue(self, session):
        """Resume the scan queue."""
        from yads.models import SystemConfig
        from sqlmodel import select

        conf = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
        if conf:
            conf.value = "true"
            session.add(conf)
            session.commit()

        try:
            from yads.worker import celery_app
            celery_app.control.add_consumer('celery', reply=True)
        except Exception:
            pass

        logger.info("Scan queue resumed")

    def _wait_for_tasks_to_drain(self):
        """Wait for active Celery tasks to complete."""
        try:
            from yads.worker import celery_app

            start_time = time.time()

            while time.time() - start_time < self.MAX_DRAIN_WAIT:
                inspector = celery_app.control.inspect()
                active = inspector.active() or {}
                reserved = inspector.reserved() or {}

                total_tasks = sum(len(tasks) for tasks in active.values())
                total_tasks += sum(len(tasks) for tasks in reserved.values())

                if total_tasks == 0:
                    logger.info("All tasks drained")
                    return

                self._state.message = f"Waiting for {total_tasks} task(s) to complete..."
                logger.info(f"Waiting for {total_tasks} tasks to drain...")
                time.sleep(5)

            logger.warning("Drain timeout reached, proceeding with update")

        except Exception as e:
            logger.warning(f"Could not check task status: {e}")

    def _pull_docker_image(self) -> bool:
        """Pull the latest Docker image."""
        docker_tag = f"{self.DOCKER_IMAGE}:latest"

        if self._state.latest_version:
            docker_tag = f"{self.DOCKER_IMAGE}:v{self._state.latest_version}"

        logger.info(f"Pulling Docker image: {docker_tag}")

        try:
            result = subprocess.run(
                ["docker", "pull", docker_tag],
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )

            if result.returncode == 0:
                logger.info(f"Successfully pulled {docker_tag}")
                return True
            else:
                logger.error(f"Docker pull failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Docker pull timed out")
            return False
        except FileNotFoundError:
            logger.error("Docker command not found")
            return False
        except Exception as e:
            logger.error(f"Docker pull error: {e}")
            return False

    def _signal_restart(self):
        """
        Signal that a restart is requested.

        This creates a signal file that the entrypoint script watches,
        or directly triggers docker-compose restart if available.
        """
        # Method 1: Create signal file for entrypoint script
        try:
            with open(self.RESTART_SIGNAL_FILE, "w") as f:
                f.write(datetime.utcnow().isoformat())
            logger.info(f"Created restart signal file: {self.RESTART_SIGNAL_FILE}")
        except Exception as e:
            logger.warning(f"Could not create signal file: {e}")

        # Method 2: Try docker-compose restart (if we have access)
        try:
            # Check if we're in a docker-compose environment
            compose_file = os.getenv("COMPOSE_FILE", "/app/docker-compose.yml")

            if os.path.exists(compose_file) or os.path.exists("/var/run/docker.sock"):
                # Schedule a restart in the background
                subprocess.Popen(
                    ["docker-compose", "-f", compose_file, "up", "-d", "--force-recreate"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
                logger.info("Triggered docker-compose restart")
        except Exception as e:
            logger.warning(f"Could not trigger docker-compose restart: {e}")

    def cancel_update(self, session=None) -> bool:
        """
        Cancel an in-progress update.

        Args:
            session: Database session for queue management.

        Returns:
            True if cancelled successfully.
        """
        if self._state.status not in [UpdateStatus.PREPARING, UpdateStatus.DOWNLOADING]:
            return False

        self._state.status = UpdateStatus.IDLE
        self._state.message = "Update cancelled"
        self._state.progress = 0

        # Resume queue
        if session:
            try:
                self._resume_queue(session)
            except Exception:
                pass

        logger.info("Update cancelled")
        return True


# Global singleton instance
_update_manager: Optional[UpdateManager] = None


def get_update_manager() -> UpdateManager:
    """Get the global UpdateManager instance."""
    global _update_manager
    if _update_manager is None:
        _update_manager = UpdateManager()
    return _update_manager
