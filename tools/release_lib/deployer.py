"""
Production Deployer
====================
Deploys a new YADS release to production via Portainer API and/or SSH.

Supported methods:
  portainer   — Portainer REST API stack redeploy (primary)
  ssh         — Direct SSH + docker commands (fallback)

Portainer API auth:
  Set PORTAINER_API_KEY env var  (recommended)
  OR username/password in config (less secure)
"""

import os
import subprocess
import time
from typing import Dict, Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


class DeployError(Exception):
    pass


class ProductionDeployer:
    """Handles deployment to Frischkorn-Prod via Portainer and/or SSH."""

    def __init__(self, config: Dict):
        """
        Args:
            config: Parsed deploy section from release.yaml
                    Expected keys under 'deploy':
                      portainer.url, portainer.api_key, portainer.stack_name
                      ssh.host, ssh.user, ssh.key_file, ssh.port
                      migrations.enabled, migrations.command
        """
        self.portainer_cfg = config.get("portainer", {})
        self.ssh_cfg = config.get("ssh", {})
        self.migrations_cfg = config.get("migrations", {})

    # ─── Portainer ──────────────────────────────────────────────────────────

    def _portainer_headers(self) -> Dict[str, str]:
        api_key = (
            self.portainer_cfg.get("api_key")
            or os.environ.get("PORTAINER_API_KEY", "")
        )
        if not api_key:
            raise DeployError(
                "Portainer API key not set. "
                "Set PORTAINER_API_KEY env var or deploy.portainer.api_key in release.yaml"
            )
        return {"X-API-Key": api_key, "Content-Type": "application/json"}

    def _portainer_find_stack(self, stack_name: str) -> Optional[Dict]:
        """Find a Portainer stack by name. Returns stack dict or None."""
        url = self.portainer_cfg.get("url", "").rstrip("/")
        resp = _requests.get(
            f"{url}/api/stacks",
            headers=self._portainer_headers(),
            verify=self.portainer_cfg.get("verify_ssl", True),
            timeout=15,
        )
        resp.raise_for_status()
        stacks = resp.json()
        for s in stacks:
            if s.get("Name") == stack_name:
                return s
        return None

    def _portainer_redeploy(self, stack: Dict, dry_run: bool = False) -> bool:
        """Trigger Portainer stack redeploy (pull + recreate)."""
        url = self.portainer_cfg.get("url", "").rstrip("/")
        stack_id = stack["Id"]
        endpoint_id = stack.get("EndpointId", 1)
        stack_name = stack["Name"]

        print(f"  🔄 Portainer: redeploying stack '{stack_name}' (ID {stack_id}) ...")
        if dry_run:
            print(f"  [DRY RUN] Would POST {url}/api/stacks/{stack_id}/redeploy")
            return True

        resp = _requests.post(
            f"{url}/api/stacks/{stack_id}/redeploy",
            headers=self._portainer_headers(),
            json={"pullImage": True, "endpointId": endpoint_id},
            verify=self.portainer_cfg.get("verify_ssl", True),
            timeout=120,
        )

        if resp.status_code in (200, 204):
            print("  ✅ Portainer redeploy triggered.")
            return True
        else:
            raise DeployError(
                f"Portainer redeploy failed: HTTP {resp.status_code} — {resp.text[:200]}"
            )

    # ─── SSH helpers ─────────────────────────────────────────────────────────

    def _ssh_cmd(self) -> list:
        """Build base SSH command list."""
        host = self.ssh_cfg.get("host", "")
        user = self.ssh_cfg.get("user", "root")
        port = str(self.ssh_cfg.get("port", 22))
        key_file = os.path.expanduser(self.ssh_cfg.get("key_file", "~/.ssh/id_rsa"))
        return [
            "ssh",
            "-i", key_file,
            "-p", port,
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            f"{user}@{host}",
        ]

    def _ssh_run(self, remote_cmd: str, dry_run: bool = False) -> bool:
        """Run a command on the remote host via SSH."""
        cmd = self._ssh_cmd() + [remote_cmd]
        if dry_run:
            print(f"  [DRY RUN] SSH: {remote_cmd}")
            return True
        result = subprocess.run(cmd, capture_output=False, text=True)
        return result.returncode == 0

    def _ssh_check_connectivity(self) -> bool:
        """Ping the remote host via SSH."""
        cmd = self._ssh_cmd() + ["echo OK"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.returncode == 0 and "OK" in result.stdout

    # ─── Migrations ──────────────────────────────────────────────────────────

    def _run_migrations(self, dry_run: bool = False) -> bool:
        """Run DB migrations on prod via SSH."""
        if not self.migrations_cfg.get("enabled", False):
            return True
        cmd = self.migrations_cfg.get(
            "command",
            "docker exec yads_yads-api python scripts/maintenance/migrate_db.py"
        )
        print(f"\n  🗄  Running migrations: {cmd}")
        return self._ssh_run(cmd, dry_run=dry_run)

    # ─── Cleanup ─────────────────────────────────────────────────────────────

    def cleanup(self, dry_run: bool = False) -> bool:
        """Run docker system prune -af on prod via SSH to free up space."""
        print(f"\n  🧹 Cleaning up production disk space (docker system prune)...")
        # -a prunes all unused images, not just dangling ones
        # -f forces without confirmation
        cmd = "docker system prune -af"
        return self._ssh_run(cmd, dry_run=dry_run)

    # ─── Public API ──────────────────────────────────────────────────────────

    def deploy(self, version: str, dry_run: bool = False) -> bool:
        """
        Full deploy flow:
          1. Pre-flight connectivity checks
          2. Portainer stack redeploy (or SSH docker commands)
          3. Wait for services to stabilize
          4. Optional: DB migrations via SSH
          5. Health check

        Returns True on success.
        """
        print("\n" + "=" * 60)
        print(f"  STEP: Deploy v{version} → Production")
        print("=" * 60 + "\n")

        portainer_url = self.portainer_cfg.get("url", "")
        stack_name = self.portainer_cfg.get("stack_name", "yads")
        ssh_host = self.ssh_cfg.get("host", "")

        if not portainer_url and not ssh_host:
            raise DeployError("No deploy target configured (portainer.url or ssh.host required).")

        # --- Step 1: Connectivity ---
        print("  🔍 Pre-flight: checking connectivity...\n")

        portainer_ok = False
        if portainer_url and _HAS_REQUESTS:
            try:
                resp = _requests.get(
                    f"{portainer_url}/api/status",
                    headers=self._portainer_headers(),
                    verify=self.portainer_cfg.get("verify_ssl", True),
                    timeout=10,
                )
                portainer_ok = resp.status_code == 200
                print(f"  {'✅' if portainer_ok else '❌'} Portainer API: {portainer_url}")
            except Exception as e:
                print(f"  ⚠️  Portainer unreachable: {e}")

        ssh_ok = False
        if ssh_host:
            try:
                ssh_ok = self._ssh_check_connectivity()
                print(f"  {'✅' if ssh_ok else '❌'} SSH: {ssh_host}")
            except Exception as e:
                print(f"  ⚠️  SSH unreachable: {e}")

        if not portainer_ok and not ssh_ok:
            raise DeployError("No deploy path available — both Portainer and SSH failed connectivity check.")

        # --- Step 2: Redeploy ---
        print()
        deployed = False
        if portainer_ok:
            print("  📦 Deploying via Portainer API...")
            try:
                stack = self._portainer_find_stack(stack_name)
                if not stack:
                    raise DeployError(f"Stack '{stack_name}' not found in Portainer.")
                deployed = self._portainer_redeploy(stack, dry_run=dry_run)
            except DeployError:
                raise
            except Exception as e:
                print(f"  ⚠️  Portainer deploy failed: {e}")
                if ssh_ok:
                    print("  🔄 Falling back to SSH deploy...")

        if not deployed and ssh_ok:
            print("  📦 Deploying via SSH...")
            if dry_run:
                print(f"  [DRY RUN] Would pull + redeploy stack '{stack_name}' via docker CLI")
                deployed = True
            else:
                pull_ok = self._ssh_run(
                    f"docker service update --with-registry-auth --image $(docker service inspect {stack_name}_yads-api "
                    f"--format '{{{{.Spec.TaskTemplate.ContainerSpec.Image}}}}' | cut -d: -f1):{version} "
                    f"{stack_name}_yads-api"
                )
                if pull_ok:
                    print("  ✅ SSH redeploy triggered.")
                    deployed = True
                else:
                    raise DeployError("SSH redeploy command failed.")

        if not deployed:
            raise DeployError("Deploy failed — no method succeeded.")

        # --- Step 3: Wait for stabilization ---
        if not dry_run:
            print("\n  ⏳ Waiting 15s for services to stabilize...")
            time.sleep(15)

        # --- Step 4: Migrations ---
        if self.migrations_cfg.get("enabled", False):
            print()
            ok = self._run_migrations(dry_run=dry_run)
            if not ok:
                print("  ⚠️  Migration command failed — check prod manually.")
            else:
                print("  ✅ Migrations complete.")

        # --- Step 5: Health check ---
        health_url = self.portainer_cfg.get("health_url") or (
            f"https://{ssh_host}/api/health" if ssh_host else None
        )
        if health_url and _HAS_REQUESTS and not dry_run:
            print(f"\n  🩺 Health check: {health_url}")
            try:
                r = _requests.get(health_url, timeout=10, verify=False)
                if r.status_code < 400:
                    print(f"  ✅ App is up (HTTP {r.status_code})")
                else:
                    print(f"  ⚠️  Health check returned HTTP {r.status_code}")
            except Exception as e:
                print(f"  ⚠️  Health check failed: {e}")
        elif dry_run:
            print(f"\n  [DRY RUN] Would health-check: {health_url}")

        # --- Step 6: Cleanup (Optional but enabled by default) ---
        if self.ssh_cfg.get("cleanup_enabled", True):
            self.cleanup(dry_run=dry_run)

        print(f"\n  🎉 Deploy v{version} completed!\n")
        return True
