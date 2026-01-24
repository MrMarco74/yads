"""
Configuration Management

Handles loading and validation of release automation configuration.
"""

import os
import re
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class ReleaseConfig:
    """Manage release automation configuration"""

    DEFAULT_CONFIG_PATH = Path.home() / ".yads" / "release.yaml"

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_path: Path to config file (default: ~/.yads/release.yaml)
        """
        self.config_path = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        self.config: Dict[str, Any] = {}

        if self.config_path.exists():
            self.load()

    def load(self) -> None:
        """
        Load configuration from YAML file.

        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid YAML
        """
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}\n"
                f"Run 'release.py init-config' to create a template."
            )

        with open(self.config_path, 'r') as f:
            raw_config = yaml.safe_load(f)

        # Expand environment variables
        self.config = self._expand_env_vars(raw_config)

    def _expand_env_vars(self, obj: Any) -> Any:
        """
        Recursively expand environment variables in config.

        Environment variables are referenced as ${VAR_NAME}.

        Args:
            obj: Config object (dict, list, str, etc.)

        Returns:
            Object with expanded environment variables
        """
        if isinstance(obj, dict):
            return {k: self._expand_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._expand_env_vars(item) for item in obj]
        elif isinstance(obj, str):
            # Replace ${VAR_NAME} with environment variable value
            def replace_env_var(match):
                var_name = match.group(1)
                value = os.getenv(var_name)
                return value if value is not None else f"${{{var_name}}}"

            return re.sub(r'\$\{([^}]+)\}', replace_env_var, obj)
        else:
            return obj

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            key_path: Dot-separated key path (e.g., "upload.ssh.host")
            default: Default value if key not found

        Returns:
            Configuration value or default

        Examples:
            >>> config.get("upload.method")
            'ssh'
            >>> config.get("upload.ssh.port", 22)
            22
        """
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def validate(self) -> bool:
        """
        Validate configuration structure.

        Returns:
            True if valid

        Raises:
            ValueError: If configuration is invalid
        """
        errors = []

        # Check required sections
        required_sections = ['upload', 'translation']
        for section in required_sections:
            if section not in self.config:
                errors.append(f"Missing required section: '{section}'")

        # Validate upload configuration
        upload_method = self.get('upload.method')
        if upload_method not in ['ssh', 'ftp']:
            errors.append(
                f"Invalid upload.method: '{upload_method}'. "
                f"Expected 'ssh' or 'ftp'"
            )

        if upload_method == 'ssh':
            ssh_config = self.get('upload.ssh', {})
            required_ssh = ['host', 'user', 'key_file']
            for key in required_ssh:
                if key not in ssh_config:
                    errors.append(f"Missing upload.ssh.{key}")

        if upload_method == 'ftp' or self.get('upload.fallback', False):
            ftp_config = self.get('upload.ftp', {})
            required_ftp = ['host', 'user', 'password']
            for key in required_ftp:
                if key not in ftp_config:
                    errors.append(f"Missing upload.ftp.{key}")

        # Validate paths
        paths = self.get('upload.paths', {})
        required_paths = ['releases', 'homepage_en', 'homepage_de']
        for path_key in required_paths:
            if path_key not in paths:
                errors.append(f"Missing upload.paths.{path_key}")

        # Validate translation (Warnings only, as translator provides manual fallback)
        translation_service = self.get('translation.service')
        if translation_service == 'gemini':
            if not self.get('translation.api_key'):
                print("⚠️  Warning: Missing translation.api_key for Gemini. Fallback to manual translation will be used.")
        elif translation_service == 'vertexai':
            if not self.get('translation.project_id'):
                print("⚠️  Warning: Missing translation.project_id for Vertex AI. Fallback to manual translation will be used.")

        if errors:
            raise ValueError(
                "Configuration validation failed:\n  - " +
                "\n  - ".join(errors)
            )

        return True

    @staticmethod
    def create_template(output_path: Optional[str] = None) -> Path:
        """
        Create example configuration file template.

        Args:
            output_path: Where to save template (default: ~/.yads/release.yaml)

        Returns:
            Path to created template file
        """
        template_path = Path(output_path) if output_path else ReleaseConfig.DEFAULT_CONFIG_PATH

        # Create parent directory if needed
        template_path.parent.mkdir(parents=True, exist_ok=True)

        template_content = """# YADS Release Automation Configuration

# Upload settings
upload:
  method: ssh  # Primary method: 'ssh' or 'ftp'
  fallback: true  # Fallback to FTP if SSH fails

  ssh:
    host: yads-security.com
    user: deploy
    key_file: ~/.ssh/yads_deploy_key
    port: 22

  ftp:
    host: yads-security.com
    user: ftpuser
    password: ${YADS_FTP_PASSWORD}  # From environment variable
    port: 21

  paths:
    releases: /var/www/releases
    homepage_en: /var/www/html/en
    homepage_de: /var/www/html/de

# Translation settings (also used for AI-powered changelog generation)
translation:
  service: gemini  # 'gemini', 'vertexai', or 'manual'
  api_key: ${GEMINI_API_KEY}  # For 'gemini' service
  model: gemini-2.0-flash  # AI model for translation and changelog generation
  # For Vertex AI:
  # project_id: my-gcp-project
  # location: us-central1
  source_lang: EN
  target_lang: DE

# Git settings
git:
  auto_commit: true
  auto_tag: true
  push_after_release: false  # Manual push recommended

# Release settings
release:
  changelog_mode: interactive  # 'interactive' or 'editor'
  dry_run_default: true  # Always preview before execution
"""

        with open(template_path, 'w') as f:
            f.write(template_content)

        # Set secure permissions (owner read/write only)
        template_path.chmod(0o600)

        return template_path
