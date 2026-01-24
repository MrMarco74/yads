"""
Upload System

Handles uploading release files via SSH/rsync or FTP with automatic fallback.
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple


class ReleaseUploader:
    """Multi-protocol uploader with automatic fallback"""

    def __init__(self, config: Dict, project_root: str):
        """
        Initialize uploader.

        Args:
            config: Configuration dictionary
            project_root: Root directory of project
        """
        self.config = config
        self.project_root = Path(project_root)

    def upload_release(self, version: str, dry_run: bool = False) -> bool:
        """
        Upload release files with fallback.

        Args:
            version: Version string (e.g., "1.13.4")
            dry_run: If True, only show what would be uploaded

        Returns:
            True if successful

        Raises:
            Exception: If all upload methods fail
        """
        files_to_upload = self._get_upload_files(version)

        # Verify all files exist
        missing_files = []
        for local_file, _ in files_to_upload:
            full_path = self.project_root / local_file
            if not full_path.exists():
                missing_files.append(local_file)

        if missing_files:
            raise FileNotFoundError(
                f"Missing files to upload:\n  - " +
                "\n  - ".join(missing_files)
            )

        if dry_run:
            print("\n--- Upload Preview (Dry Run) ---\n")
            for local_file, remote_path in files_to_upload:
                print(f"  {local_file}")
                print(f"  → {remote_path}\n")
            return True

        # Try primary upload method
        upload_method = self.config.get('upload', {}).get('method', 'ssh')

        try:
            if upload_method == 'ssh':
                return self._upload_ssh(files_to_upload, version)
            elif upload_method == 'ftp':
                return self._upload_ftp(files_to_upload, version)
            else:
                raise ValueError(f"Invalid upload method: {upload_method}")

        except Exception as ssh_error:
            print(f"\n⚠️  {upload_method.upper()} upload failed: {ssh_error}")

            # Try fallback if enabled
            if self.config.get('upload', {}).get('fallback', False):
                fallback_method = 'ftp' if upload_method == 'ssh' else 'ssh'
                print(f"📡 Attempting {fallback_method.upper()} fallback...\n")

                try:
                    if fallback_method == 'ftp':
                        return self._upload_ftp(files_to_upload, version)
                    else:
                        return self._upload_ssh(files_to_upload, version)
                except Exception as fallback_error:
                    print(f"\n❌ {fallback_method.upper()} fallback also failed: {fallback_error}")
                    raise

            else:
                raise

    def _get_upload_files(self, version: str) -> List[Tuple[str, str]]:
        """
        Get list of files to upload.

        Args:
            version: Version string

        Returns:
            List of (local_path, remote_path) tuples
        """
        paths = self.config.get('upload', {}).get('paths', {})

        files = [
            # Release package and metadata
            (
                f'releases/yads_v{version}_customer_pkg.zip',
                paths.get('releases', '/var/www/releases/')
            ),
            (
                'releases/version.json',
                paths.get('releases', '/var/www/releases/')
            ),

            # Homepage files (EN)
            (
                'yads-homepage/en/support.html',
                paths.get('homepage_en', '/var/www/html/en/')
            ),
            (
                'yads-homepage/en/changes.html',
                paths.get('homepage_en', '/var/www/html/en/')
            ),
            (
                'yads-homepage/en/docs.html',
                paths.get('homepage_en', '/var/www/html/en/')
            ),

            # Homepage files (DE)
            (
                'yads-homepage/de/support.html',
                paths.get('homepage_de', '/var/www/html/de/')
            ),
            (
                'yads-homepage/de/changes.html',
                paths.get('homepage_de', '/var/www/html/de/')
            ),
            (
                'yads-homepage/de/docs.html',
                paths.get('homepage_de', '/var/www/html/de/')
            ),
        ]

        return files

    def _upload_ssh(self, files: List[Tuple[str, str]], version: str) -> bool:
        """
        Upload via rsync over SSH.

        Args:
            files: List of (local_path, remote_path) tuples
            version: Version string

        Returns:
            True if successful
        """
        ssh_config = self.config.get('upload', {}).get('ssh', {})

        host = ssh_config.get('host')
        user = ssh_config.get('user')
        key_file = ssh_config.get('key_file', '~/.ssh/id_rsa')
        port = ssh_config.get('port', 22)

        # Expand ~ in key_file path
        key_file = os.path.expanduser(key_file)

        print(f"\n📤 Uploading via SSH to {user}@{host}...\n")

        for local_file, remote_path in files:
            local_full_path = self.project_root / local_file

            # Ensure remote path ends with /
            if not remote_path.endswith('/'):
                remote_path += '/'

            # Build rsync command
            cmd = [
                'rsync',
                '-avz',
                '--progress',
                '-e', f'ssh -i {key_file} -p {port} -o StrictHostKeyChecking=no',
                str(local_full_path),
                f'{user}@{host}:{remote_path}'
            ]

            print(f"  📁 {local_file}")
            print(f"     → {remote_path}")

            try:
                result = subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True
                )

                # Show progress output
                if result.stdout:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            print(f"     {line}")

                print(f"     ✅ Uploaded\n")

            except subprocess.CalledProcessError as e:
                print(f"     ❌ Failed: {e.stderr}\n")
                raise

        print(f"✅ All files uploaded successfully via SSH\n")
        return True

    def _upload_ftp(self, files: List[Tuple[str, str]], version: str) -> bool:
        """
        Upload via FTP/FTPS.

        Args:
            files: List of (local_path, remote_path) tuples
            version: Version string

        Returns:
            True if successful
        """
        import ftplib
        import ssl
        import time

        ftp_config = self.config.get('upload', {}).get('ftp', {})

        host = ftp_config.get('host')
        user = ftp_config.get('user')
        password = ftp_config.get('password')
        port = ftp_config.get('port', 21)
        use_tls = ftp_config.get('tls', True)  # Default to TLS
        verify_ssl = ftp_config.get('verify_ssl', True)
        ca_cert = ftp_config.get('ca_cert')  # Path to CA certificate bundle

        print(f"\n📤 Uploading via {'FTPS' if use_tls else 'FTP'} to {host}...\n")

        try:
            if use_tls:
                # Create SSL context
                ssl_context = ssl.create_default_context()

                if not verify_ssl:
                    print("  ⚠️  SSL certificate verification disabled")
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                elif ca_cert:
                    # Use custom CA certificate
                    ca_cert_path = os.path.expanduser(ca_cert)
                    if os.path.exists(ca_cert_path):
                        ssl_context.load_verify_locations(ca_cert_path)
                        print(f"  🔐 Using CA certificate: {ca_cert_path}")
                    else:
                        print(f"  ⚠️  CA certificate not found: {ca_cert_path}")
                        print("      Falling back to system certificates")

                # Connect with TLS
                ftp = ftplib.FTP_TLS(context=ssl_context)
                ftp.connect(host, port, timeout=30)
                ftp.login(user, password)

                # Switch to secure data connection
                ftp.prot_p()
                print("  🔒 TLS connection established\n")
            else:
                # Plain FTP (not recommended)
                print("  ⚠️  Using unencrypted FTP connection\n")
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=30)
                ftp.login(user, password)

            for local_file, remote_path in files:
                local_full_path = self.project_root / local_file
                remote_filename = os.path.basename(local_file)

                # Ensure remote directory exists
                self._ensure_ftp_directory(ftp, remote_path)

                # Change to remote directory
                ftp.cwd(remote_path)

                print(f"  📁 {local_file}")
                print(f"     → {remote_path}{remote_filename}")

                # Upload file with progress
                with open(local_full_path, 'rb') as f:
                    file_size = os.path.getsize(local_full_path)

                    def callback(data):
                        # Simple progress indicator
                        print('.', end='', flush=True)

                    ftp.storbinary(f'STOR {remote_filename}', f, callback=callback)

                print(f"\n     ✅ Uploaded\n")

            ftp.quit()
            print(f"✅ All files uploaded successfully via FTP\n")
            return True

        except ftplib.error_perm as e:
            error_msg = str(e)
            if '530' in error_msg:
                print(f"\n❌ FTP authentication failed: {e}")
                print("   Check username and password in config")
            elif '550' in error_msg:
                print(f"\n❌ FTP permission denied: {e}")
                print("   Check file/directory permissions on server")
            else:
                print(f"\n❌ FTP permission error: {e}")
            raise

        except ftplib.error_temp as e:
            print(f"\n❌ FTP temporary error: {e}")
            print("   Server may be busy or you may be rate-limited")
            print("   Wait a few minutes before retrying")
            raise

        except ssl.SSLCertVerificationError as e:
            print(f"\n❌ SSL certificate verification failed: {e}")
            print("\n   Possible solutions:")
            print("   1. Set 'verify_ssl: false' in config (not recommended)")
            print("   2. Add server's CA cert to 'ca_cert' in config")
            print("   3. Install server's CA cert system-wide")
            raise

        except ConnectionRefusedError as e:
            print(f"\n❌ FTP connection refused: {e}")
            print("   Your IP may be blocked due to too many failed attempts")
            print("   Contact your hosting provider to unblock your IP")
            raise

        except Exception as e:
            print(f"\n❌ FTP upload failed: {e}\n")
            raise

    def _ensure_ftp_directory(self, ftp, remote_path: str) -> None:
        """
        Ensure FTP directory exists (create if needed).

        Args:
            ftp: FTP connection
            remote_path: Remote directory path
        """
        # Split path into parts
        parts = remote_path.strip('/').split('/')

        # Navigate/create each part
        current_path = ''
        for part in parts:
            if not part:
                continue

            current_path += '/' + part

            try:
                ftp.cwd(current_path)
            except:
                # Directory doesn't exist, create it
                try:
                    ftp.mkd(current_path)
                    ftp.cwd(current_path)
                except:
                    # Maybe we don't have permission, continue anyway
                    pass

    def verify_upload(self, version: str) -> Dict[str, bool]:
        """
        Verify uploaded files are accessible.

        Args:
            version: Version string

        Returns:
            Dictionary mapping file paths to verification status
        """
        # This could be implemented to check file existence/size
        # For now, just return placeholder
        print("\n🔍 Upload verification not yet implemented")
        return {}
