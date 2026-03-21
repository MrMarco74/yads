#!/usr/bin/env python3
import os
import subprocess
import secrets
import shutil
from datetime import datetime
from pathlib import Path

# --- Constants (Copied from gui.py) ---
REGISTRY_URL = "registry.yads-security.com"
REGISTRY_USER = "yads-push"
REGISTRY_TOKEN = "REDACTED"
COMPOSE_FILE = "docker-compose.yml"
NGINX_TEMPLATE = "release_assets/yads_installer/nginx.conf.template"
CUSTOMER_COMPOSE = "release_assets/yads_installer/docker-compose.customer.yml"

class HeadlessInstallationManager:
    def __init__(self, data):
        self.data = data
        self.secrets = {}

    def log(self, msg, level="info"):
        print(f"[{level.upper()}] {msg}")

    def run_install(self):
        try:
            self.log("Starting headless installation...")
            self.shutdown_existing()
            self.login_registry()
            self.generate_secrets()
            self.prepare_installation_files()
            self.write_env()
            
            self.log("Pulling docker images...")
            self.run_docker(["compose", "pull"])
            
            self.log("Starting containers...")
            self.run_docker(["compose", "up", "-d"])
            
            self.log("Installation finished successfully!")
            return True
        except Exception as e:
            self.log(f"FATAL ERROR: {str(e)}", "error")
            return False

    def shutdown_existing(self):
        self.log("Stopping existing services...")
        if os.path.exists(COMPOSE_FILE):
            if self.data.get('install_mode') == 'reinstall':
                self.run_docker(["compose", "down", "-v", "--remove-orphans"])
            else:
                self.run_docker(["compose", "down", "--remove-orphans"])
        
        containers = ["yads-proxy", "yads-api", "yads-worker", "yads-db", "yads-redis"]
        for c in containers:
            subprocess.run(["docker", "rm", "-f", c], capture_output=True)

    def login_registry(self):
        self.log(f"Logging into {REGISTRY_URL}...")
        login_process = subprocess.Popen(
            ["docker", "login", REGISTRY_URL, "-u", REGISTRY_USER, "--password-stdin"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = login_process.communicate(input=REGISTRY_TOKEN)
        if login_process.returncode != 0:
            raise RuntimeError(f"Registry Login failed: {stderr.strip()}")
        self.log("Registry Login successful.")

    def generate_secrets(self):
        self.log("Generating/Reusing secrets...")
        existing_secrets = {}
        if self.data.get('install_mode') == 'upgrade' and os.path.exists(".env"):
            self.log("Upgrade mode: attempting to reuse secrets from .env")
            with open(".env", "r") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        if k in ['POSTGRES_PASSWORD', 'REDIS_PASSWORD', 'SECRET_KEY', 'SIGNING_KEY', 'REFRESH_SECRET', 'YADS_ENCRYPTION_KEY']:
                            existing_secrets[k] = v
        
        self.secrets = {
            'POSTGRES_PASSWORD': existing_secrets.get('POSTGRES_PASSWORD', secrets.token_urlsafe(16)),
            'REDIS_PASSWORD': existing_secrets.get('REDIS_PASSWORD', secrets.token_urlsafe(16)),
            'SECRET_KEY': existing_secrets.get('SECRET_KEY', secrets.token_urlsafe(32)),
            'SIGNING_KEY': existing_secrets.get('SIGNING_KEY', secrets.token_urlsafe(32)),
            'REFRESH_SECRET': existing_secrets.get('REFRESH_SECRET', secrets.token_urlsafe(32)),
            'YADS_ENCRYPTION_KEY': existing_secrets.get('YADS_ENCRYPTION_KEY', secrets.token_urlsafe(32)),
        }

    def prepare_installation_files(self):
        self.log("Preparing installation files...")
        if os.path.exists(CUSTOMER_COMPOSE):
            with open(CUSTOMER_COMPOSE, "r") as f:
                content = f.read()
            
            # Make DB user dynamic in connection string and DB service
            db_user = self.data.get('db_user', 'yads')
            content = content.replace("postgresql://yads:", f"postgresql://${{POSTGRES_USER:-{db_user}}}:")
            content = content.replace("POSTGRES_USER=yads", f"POSTGRES_USER=${{POSTGRES_USER:-{db_user}}}")
            
            with open(COMPOSE_FILE, "w") as f:
                f.write(content)
        else:
            raise RuntimeError(f"Source compose file not found: {CUSTOMER_COMPOSE}")
            
        if os.path.exists(NGINX_TEMPLATE):
            dest_dir = os.path.join(os.getcwd(), "nginx")
            os.makedirs(dest_dir, exist_ok=True)
            with open(NGINX_TEMPLATE, "r") as f:
                content = f.read()
            
            content = content.replace("{{PORT}}", str(self.data.get('api_port', 8085)))
            content = content.replace("{{SERVER_NAME}}", self.data.get('host', 'localhost'))
            content = content.replace("{{CLIENT_MAX_BODY_SIZE}}", "100M")
            content = content.replace("{{PROXY_READ_TIMEOUT}}", "300s")
            
            with open(os.path.join(dest_dir, "nginx.conf"), "w") as f:
                f.write(content)
        else:
            self.log("Nginx template not found, skipping nginx config.", "warning")

    def write_env(self):
        self.log("Writing .env file...")
        lines = [
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

    def run_docker(self, args):
        cmd = ["docker"] + args
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(f"  [DOCKER] {line.strip()}")
        process.wait()
        if process.returncode != 0:
            raise RuntimeError(f"Docker command failed with code {process.returncode}")

if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python3 run_installer_headless.py '<json_data>'")
        sys.exit(1)
        
    data = json.loads(sys.argv[1])
    manager = HeadlessInstallationManager(data)
    success = manager.run_install()
    sys.exit(0 if success else 1)
