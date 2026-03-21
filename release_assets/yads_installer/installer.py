import subprocess
import socket
import os
import shutil
import platform
import re

class DependencyChecker:
    @staticmethod
    def check_docker():
        return shutil.which("docker") is not None

    @staticmethod
    def check_docker_compose():
        try:
            result = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    @staticmethod
    def check_docker_daemon():
        try:
            # Running 'docker version' requires daemon access. 
            # We specifically check for permission errors to suggest sudo.
            result = subprocess.run(["docker", "version"], capture_output=True, text=True)
            if result.returncode == 0:
                return True, "ok"
            err = (result.stderr + result.stdout).lower()
            if "permission denied" in err or "connect" in err:
                return False, "permission_denied"
            return False, "error"
        except Exception:
            return False, "not_installed"

    @staticmethod
    def check_openssl():
        return shutil.which("openssl") is not None

    @staticmethod
    def install_dependencies():
        """Attempts to install missing dependencies on Debian/Ubuntu systems."""
        if platform.system() != "Linux":
            return False, "Auto-installation only supported on Linux."
        
        # Check if apt is available
        if not shutil.which("apt"):
            return False, "apt-get not found. Please install dependencies manually."

        commands = [
            ["sudo", "apt", "update"],
            ["sudo", "apt", "install", "-y", "ca-certificates", "curl", "gnupg"],
            ["sudo", "install", "-m", "0755", "-d", "/etc/apt/keyrings"],
            ["curl", "-fsSL", "https://download.docker.com/linux/ubuntu/gpg", "-o", "/tmp/docker.asc"],
            ["sudo", "mv", "/tmp/docker.asc", "/etc/apt/keyrings/docker.asc"],
            ["sudo", "chmod", "a+r", "/etc/apt/keyrings/docker.asc"]
        ]
        
        # Add docker repository
        arch = subprocess.check_output(["dpkg", "--print-architecture"]).decode().strip()
        codename = subprocess.check_output(["sh", "-c", ". /etc/os-release && echo $UBUNTU_CODENAME"]).decode().strip()
        repo_line = f"deb [arch={arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu {codename} stable"
        
        commands.append(["sh", "-c", f"echo '{repo_line}' | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null"])
        commands.append(["sudo", "apt", "update"])
        commands.append(["sudo", "apt", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"])

        for cmd in commands:
            try:
                subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as e:
                return False, f"Command failed: {' '.join(cmd)}\nError: {str(e)}"
        
        return True, "Dependencies installed successfully."

class NetworkTools:
    @staticmethod
    def ping(host):
        if not host:
            return False, "No host provided"
        try:
            # -c 1 for 1 packet, -W 2 for 2 seconds timeout
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-W', '2', host]
            result = subprocess.run(command, capture_output=True, text=True)
            return result.returncode == 0, result.stdout
        except Exception as e:
            return False, str(e)

    @staticmethod
    def _real_ip():
        """Return the first non-loopback IPv4 address of this machine."""
        # Try UDP connect trick — picks the outbound interface IP without sending packets
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
            if not ip.startswith("127."):
                return ip
        except Exception:
            pass
        # Fallback: iterate all addresses and skip loopback
        try:
            hostname = socket.gethostname()
            for addr in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = addr[4][0]
                if not ip.startswith("127."):
                    return ip
        except Exception:
            pass
        return None

    @staticmethod
    def resolve(host_or_ip):
        if not host_or_ip:
            return None, None
        try:
            # Check if it's an IP
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host_or_ip):
                if host_or_ip.startswith("127."):
                    # Loopback — resolve real IP and real hostname instead
                    real_ip = NetworkTools._real_ip()
                    try:
                        real_hostname = socket.gethostname()
                    except Exception:
                        real_hostname = host_or_ip
                    return real_ip or host_or_ip, real_hostname
                hostname = socket.gethostbyaddr(host_or_ip)[0]
                return host_or_ip, hostname
            else:
                ip = socket.gethostbyname(host_or_ip)
                if ip.startswith("127."):
                    # Hostname resolves to loopback — get real outbound IP
                    real_ip = NetworkTools._real_ip()
                    return real_ip or ip, host_or_ip
                return ip, host_or_ip
        except Exception:
            return None, None

class ConfigGenerator:
    def __init__(self, data):
        self.data = data

    def generate_env(self, target_path=".env"):
        lines = [
            "# Generated by YADS Installer",
            f"POSTGRES_PASSWORD={self.data.get('db_pass')}",
            f"SECRET_KEY={self.data.get('secret_key')}",
            f"YADS_ENCRYPTION_KEY={self.secrets.get('YADS_ENCRYPTION_KEY')}",
            f"API_PORT={self.data.get('api_port', 80)}",
            "YADS_VERSION=latest",
            f"HAS_NGINX={'true' if self.data.get('use_nginx') else 'false'}",
            f"DISABLE_HTTPS_ONLY={'true' if not self.data.get('use_ssl', False) else 'false'}"
        ]
        if self.data.get('auth_mode') == 'oidc':
            lines.extend([
                "AUTH_MODE=oidc",
                f"OIDC_SERVER_URL={self.data.get('oidc_url')}",
                f"OIDC_CLIENT_ID={self.data.get('oidc_id')}",
                f"OIDC_CLIENT_SECRET={self.data.get('oidc_secret')}"
            ])
        else:
            lines.append("AUTH_MODE=local")
            
        with open(target_path, "w") as f:
            f.write("\n".join(lines) + "\n")

    def generate_nginx(self, template_path, target_path):
        if not os.path.exists(template_path):
            return False
        with open(template_path, "r") as f:
            content = f.read()
        
        content = content.replace("{{PORT}}", str(self.data.get('api_port', 80)))
        
        with open(target_path, "w") as f:
            f.write(content)
        return True

if __name__ == "__main__":
    # Basic CLI test
    print("YADS Installer Logic Loaded.")
    print(f"Docker: {DependencyChecker.check_docker()}")
    print(f"Compose v2: {DependencyChecker.check_docker_compose()}")
