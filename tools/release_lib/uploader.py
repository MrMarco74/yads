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
        self.current_process = None  # For cancellation support

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def _check_sshpass(self) -> bool:
        """Check if sshpass is installed"""
        try:
            subprocess.run(['which', 'sshpass'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def upload_release(self, version: str, channel: str = 'stable', dry_run: bool = False) -> bool:
        """
        Upload release files with fallback.

        Args:
            version: Version string (e.g., "1.13.4")
            channel: Release channel ('stable' or 'beta')
            dry_run: If True, only show what would be uploaded

        Returns:
            True if successful

        Raises:
            Exception: If all upload methods fail
        """
        files_to_upload = self._get_upload_files(version, channel)

        # Display channel info
        channel_display = "🔷 BETA" if channel == 'beta' else "🟢 STABLE"
        print(f"\n📦 Release Channel: {channel_display}\n")

        # Verify all files/directories exist
        missing_files = []
        for local_file, _ in files_to_upload:
            full_path = self.project_root / local_file.rstrip('/')
            if not full_path.exists():
                missing_files.append(local_file)

        if missing_files:
            raise FileNotFoundError(
                f"Missing files to upload:\n  - " +
                "\n  - ".join(missing_files)
            )

        if dry_run:
            upload_method = self.config.get('upload', {}).get('method', 'ssh')
            ssh_config = self.config.get('upload', {}).get('ssh', {})
            ftp_config = self.config.get('upload', {}).get('ftp', {})

            print("\n" + "="*60)
            print("  DRY RUN - UPLOAD PREVIEW")
            print("="*60 + "\n")

            # Show connection info
            if upload_method == 'ssh':
                host = ssh_config.get('host', 'N/A')
                user = ssh_config.get('user', 'N/A')
                port = ssh_config.get('port', 22)
                print(f"  Method:  SSH/RSYNC")
                print(f"  Server:  {user}@{host}:{port}")
            else:
                host = ftp_config.get('host', 'N/A')
                user = ftp_config.get('user', 'N/A')
                port = ftp_config.get('port', 21)
                tls = ftp_config.get('tls', True)
                print(f"  Method:  {'FTPS' if tls else 'FTP'}")
                print(f"  Server:  {user}@{host}:{port}")

            print("\n" + "-"*60)
            print("  FILES TO UPLOAD:")
            print("-"*60 + "\n")

            total_size = 0
            for local_file, remote_path in files_to_upload:
                is_dir = local_file.endswith('/')
                full_path = self.project_root / local_file.rstrip('/')
                if full_path.exists():
                    if is_dir:
                        size = sum(f.stat().st_size for f in full_path.rglob('*') if f.is_file())
                        n = sum(1 for f in full_path.rglob('*') if f.is_file())
                        size_str = f"{self._format_size(size)} ({n} files)"
                    else:
                        size = full_path.stat().st_size
                        size_str = self._format_size(size)
                    total_size += size
                else:
                    size_str = "MISSING!"

                icon = "📂" if is_dir else "📁"
                full_remote = remote_path if is_dir else remote_path.rstrip('/') + '/' + os.path.basename(local_file)
                print(f"  {icon} {local_file}")
                print(f"     Size: {size_str}")
                print(f"     → {full_remote}")
                print()

            print("-"*60)
            print(f"  Total: {len(files_to_upload)} files, {self._format_size(total_size)}")
            print("="*60 + "\n")

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

    def _get_upload_files(self, version: str, channel: str = 'stable') -> List[Tuple[str, str]]:
        """
        Get list of files to upload.

        Args:
            version: Version string
            channel: Release channel ('stable' or 'beta')

        Returns:
            List of (local_path, remote_path) tuples
        """
        paths = self.config.get('upload', {}).get('paths', {})

        # stable -> version.json (backwards compatible), beta -> version-beta.json
        version_json_file = 'releases/version-beta.json' if channel == 'beta' else 'releases/version.json'

        en = paths.get('homepage_en', '/public_html/yads-security/en/').rstrip('/') + '/'
        de = paths.get('homepage_de', '/public_html/yads-security/de/').rstrip('/') + '/'
        rel = paths.get('releases', '/public_html/yads-security/en/releases/').rstrip('/') + '/'

        if channel == 'beta':
            # Beta: only upload the changelog pages + version-beta.json
            # No Docker images were built, so no zip/BOM/assets to upload
            return [
                (version_json_file, rel),
                ('yads-homepage/en/changes.html', en),
                ('yads-homepage/de/changes.html', de),
            ]

        files = [
            # Release package
            (f'releases/yads_v{version}_customer_pkg.zip', rel),
            (version_json_file, rel),
            ('releases/sbom.json', rel),
            ('releases/sbom.xml', rel),
            ('releases/cbom.json', rel),
            ('releases/cbom.xml', rel),

            # Homepage HTML (EN) — yads-security.com/en/
            ('yads-homepage/en/index.html',   en),
            ('yads-homepage/en/changes.html', en),
            ('yads-homepage/en/docs.html',    en),
            ('yads-homepage/en/support.html', en),
            ('yads-homepage/en/bom.html',     en),

            # Homepage assets (EN canonical — DE site loads these cross-origin from .com)
            # Entries ending with '/' are treated as directories (rsync/FTP recursive)
            ('yads-homepage/en/css/',     en + 'css/'),
            ('yads-homepage/en/scripts/', en + 'scripts/'),
            ('yads-homepage/en/fonts/',   en + 'fonts/'),
            ('yads-homepage/en/images/',  en + 'images/'),

            # Homepage HTML (DE) — yads-security.de (same FTP, different path)
            ('yads-homepage/de/index.html',            de),
            ('yads-homepage/de/changes.html',          de),
            ('yads-homepage/de/docs.html',             de),
            ('yads-homepage/de/docs-advanced.html',    de),
            ('yads-homepage/de/support.html',          de),
            ('yads-homepage/de/bom.html',              de),
            ('yads-homepage/de/about.html',            de),
            ('yads-homepage/de/contact.html',          de),
            ('yads-homepage/de/editions.html',         de),
            ('yads-homepage/de/product.html',          de),
            ('yads-homepage/de/roadmap.html',          de),
            ('yads-homepage/de/story.html',            de),
            ('yads-homepage/de/datenschutz.html',      de),
            ('yads-homepage/de/haftungsausschluss.html', de),
            ('yads-homepage/de/impressum.html',        de),
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
        password = ssh_config.get('password', '')
        key_file = ssh_config.get('key_file', '~/.ssh/id_rsa')
        port = ssh_config.get('port', 22)

        # Expand ~ in key_file path
        key_file = os.path.expanduser(key_file)
        key_file_exists = key_file and os.path.exists(key_file)

        # Determine auth method: prefer password if provided and key doesn't exist
        # If password is set and key file doesn't exist -> use password
        # If password is set and key file exists -> use key (more secure)
        # If no password -> use key
        use_password = bool(password) and not key_file_exists

        if use_password and not self._check_sshpass():
            print("⚠️  sshpass not installed. Install with: sudo apt install sshpass")
            print("   Falling back to key-based auth...")
            use_password = False

        if use_password:
            print(f"\n📤 Uploading via SSH (password) to {user}@{host}:{port}...\n")
        else:
            print(f"\n📤 Uploading via SSH (key: {key_file}) to {user}@{host}:{port}...")
            if not key_file_exists:
                print(f"   ⚠️  Key file not found! Set a password or create the key file.\n")
            else:
                print()

        # Calculate totals for progress display
        def _path_size(p: Path) -> int:
            if p.is_dir():
                return sum(f.stat().st_size for f in p.rglob('*') if f.is_file())
            return p.stat().st_size if p.exists() else 0

        total_files = len(files)
        total_bytes = sum(_path_size(self.project_root / f[0].rstrip('/')) for f in files)
        uploaded_bytes = 0

        print(f"  📊 Total: {total_files} entries, {self._format_size(total_bytes)}\n")

        for file_idx, (local_file, remote_path) in enumerate(files, 1):
            is_dir = local_file.endswith('/')
            local_full_path = self.project_root / local_file.rstrip('/')

            # Ensure remote path ends with /
            if not remote_path.endswith('/'):
                remote_path += '/'

            # For directories: rsync source_dir/ remote_dir/ (trailing slash = sync contents)
            rsync_source = str(local_full_path) + ('/' if is_dir else '')

            ssh_opts = (
                f'ssh -p {port} -o StrictHostKeyChecking=no -o PubkeyAuthentication=no'
                if use_password else
                f'ssh -i {key_file} -p {port} -o StrictHostKeyChecking=no'
            )
            rsync_base = ['sshpass', '-p', password, 'rsync'] if use_password else ['rsync']
            cmd = rsync_base + ['-avz', '--progress', '-e', ssh_opts,
                                 rsync_source, f'{user}@{host}:{remote_path}']

            entry_size = _path_size(local_full_path)
            icon = "📂" if is_dir else "📁"
            dest = remote_path if is_dir else f"{remote_path}{os.path.basename(local_file)}"
            print(f"  [{file_idx}/{total_files}] {icon} {local_file}")
            print(f"          Size: {self._format_size(entry_size)}")
            print(f"          → {dest}")

            try:
                import time
                start_time = time.time()

                # Use Popen for cancellation support
                self.current_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                stdout, stderr = self.current_process.communicate(timeout=600)  # 10 min timeout

                if self.current_process.returncode != 0:
                    raise subprocess.CalledProcessError(
                        self.current_process.returncode, cmd, stdout, stderr
                    )

                # Calculate speed
                elapsed = time.time() - start_time
                speed = entry_size / elapsed if elapsed > 0 else 0

                uploaded_bytes += entry_size
                overall_percent = int((uploaded_bytes / total_bytes) * 100) if total_bytes > 0 else 100

                print(f"          ✅ Done in {elapsed:.1f}s ({self._format_size(speed)}/s)")
                print(f"          Overall: {overall_percent}% ({self._format_size(uploaded_bytes)}/{self._format_size(total_bytes)})\n")

                self.current_process = None

            except subprocess.TimeoutExpired:
                self.current_process.kill()
                self.current_process = None
                print(f"     ❌ Timeout (10 min exceeded)\n")
                raise Exception("Upload timeout")

            except subprocess.CalledProcessError as e:
                print(f"     ❌ Failed: {e.stderr}\n")
                raise

        print(f"✅ All {total_files} files ({self._format_size(total_bytes)}) uploaded successfully via SSH\n")
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

            def _ftp_upload_file(ftp_conn, local_path: Path, remote_dir: str) -> int:
                """Upload a single file via FTP. Returns bytes uploaded."""
                self._ensure_ftp_directory(ftp_conn, remote_dir)
                ftp_conn.cwd(remote_dir)
                fsize = local_path.stat().st_size
                with open(local_path, 'rb') as f:
                    ftp_conn.storbinary(f'STOR {local_path.name}', f)
                return fsize

            def _ftp_upload_dir(ftp_conn, local_dir: Path, remote_base: str) -> int:
                """Recursively upload a directory via FTP. Returns bytes uploaded."""
                total = 0
                for item in sorted(local_dir.rglob('*')):
                    if item.is_file():
                        rel = item.relative_to(local_dir)
                        remote_dir = remote_base.rstrip('/') + '/' + str(rel.parent).replace('\\', '/')
                        if str(rel.parent) == '.':
                            remote_dir = remote_base
                        total += _ftp_upload_file(ftp_conn, item, remote_dir)
                        print(f"          ↳ {item.name}")
                return total

            # Calculate totals for progress display
            def _entry_size(p: Path) -> int:
                if p.is_dir():
                    return sum(f.stat().st_size for f in p.rglob('*') if f.is_file())
                return p.stat().st_size if p.exists() else 0

            total_files = len(files)
            total_bytes = sum(_entry_size(self.project_root / f[0].rstrip('/')) for f in files)
            uploaded_bytes = 0

            print(f"  📊 Total: {total_files} entries, {self._format_size(total_bytes)}\n")

            for file_idx, (local_file, remote_path) in enumerate(files, 1):
                is_dir = local_file.endswith('/')
                local_full_path = self.project_root / local_file.rstrip('/')
                entry_size = _entry_size(local_full_path)
                icon = "📂" if is_dir else "📁"

                print(f"  [{file_idx}/{total_files}] {icon} {local_file}")
                print(f"          Size: {self._format_size(entry_size)}")
                print(f"          → {remote_path}")

                start_time = time.time()
                if is_dir:
                    bytes_done = _ftp_upload_dir(ftp, local_full_path, remote_path)
                else:
                    bytes_done = _ftp_upload_file(ftp, local_full_path, remote_path)

                uploaded_bytes += bytes_done
                elapsed = time.time() - start_time
                speed = bytes_done / elapsed if elapsed > 0 else 0
                overall_percent = int((uploaded_bytes / total_bytes) * 100) if total_bytes > 0 else 100
                print(f"          ✅ Done in {elapsed:.1f}s ({self._format_size(speed)}/s)")
                print(f"          Overall: {overall_percent}% ({self._format_size(uploaded_bytes)}/{self._format_size(total_bytes)})\n")

            ftp.quit()
            print(f"✅ All {total_files} files uploaded successfully via FTP\n")
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
