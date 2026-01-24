"""
File Update Engine

Handles atomic updates to all release-related files with rollback support.
"""

import os
import re
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime


class FileUpdater:
    """Atomically update files with rollback support"""

    def __init__(self, project_root: str):
        """
        Initialize file updater.

        Args:
            project_root: Root directory of YADS project
        """
        self.project_root = Path(project_root)
        self.backup_files: List[Tuple[Path, Path]] = []  # (original, backup)

    def update_version_in_config(
        self,
        new_version: str,
        dry_run: bool = False
    ) -> Dict[str, any]:
        """
        Update version in yads/config.py.

        Args:
            new_version: New version string (e.g., "1.13.4")
            dry_run: If True, only show what would be changed

        Returns:
            Dictionary with update results
        """
        file_path = self.project_root / "yads" / "config.py"

        with open(file_path, 'r') as f:
            content = f.read()

        # Pattern: VERSION: str = "X.Y.Z"
        pattern = r'(VERSION:\s*str\s*=\s*["\'])(\d+\.\d+\.\d+)(["\'])'

        def replacement(match):
            return f"{match.group(1)}{new_version}{match.group(3)}"

        new_content, count = re.subn(pattern, replacement, content)

        if count == 0:
            raise ValueError(f"Could not find VERSION pattern in {file_path}")

        result = {
            'file': str(file_path),
            'matches': count,
            'changed': content != new_content
        }

        if not dry_run and result['changed']:
            self._backup_and_write(file_path, new_content)

        return result

    def update_user_guide(
        self,
        new_version: str,
        dry_run: bool = False
    ) -> Dict[str, any]:
        """
        Update version and date in docs/USER_GUIDE.md.

        Args:
            new_version: New version string
            dry_run: If True, only show what would be changed

        Returns:
            Dictionary with update results
        """
        file_path = self.project_root / "docs" / "USER_GUIDE.md"

        with open(file_path, 'r') as f:
            lines = f.readlines()

        # Update line 2: Version X.Y.Z
        # Update line 3: Last Updated: YYYY-MM-DD
        current_date = datetime.now().strftime("%Y-%m-%d")

        changes = 0
        if len(lines) > 1:
            # Line 2 (index 1): Version line
            version_pattern = r'Version \d+\.\d+\.\d+'
            new_line_2 = re.sub(version_pattern, f'Version {new_version}', lines[1])
            if new_line_2 != lines[1]:
                lines[1] = new_line_2
                changes += 1

        if len(lines) > 2:
            # Line 3 (index 2): Date line
            date_pattern = r'Last Updated: \d{4}-\d{2}-\d{2}'
            new_line_3 = re.sub(date_pattern, f'Last Updated: {current_date}', lines[2])
            if new_line_3 != lines[2]:
                lines[2] = new_line_3
                changes += 1

        new_content = ''.join(lines)

        result = {
            'file': str(file_path),
            'matches': changes,
            'changed': changes > 0
        }

        if not dry_run and result['changed']:
            self._backup_and_write(file_path, new_content)

        return result

    def update_docs_html(
        self,
        new_version: str,
        language: str,
        dry_run: bool = False
    ) -> Dict[str, any]:
        """
        Update version references in docs.html (EN or DE).

        Args:
            new_version: New version string
            language: 'en' or 'de'
            dry_run: If True, only show what would be changed

        Returns:
            Dictionary with update results
        """
        file_path = self.project_root / "yads-homepage" / language / "docs.html"

        with open(file_path, 'r') as f:
            content = f.read()

        # Replace version references (lines 75 and 493 typically have version info)
        # Pattern: v1.13.3 or Version 1.13.3
        patterns = [
            (r'v\d+\.\d+\.\d+', f'v{new_version}'),
            (r'Version \d+\.\d+\.\d+', f'Version {new_version}'),
            (r'version \d+\.\d+\.\d+', f'version {new_version}'),
        ]

        new_content = content
        total_changes = 0

        for pattern, replacement in patterns:
            new_content, count = re.subn(pattern, replacement, new_content)
            total_changes += count

        result = {
            'file': str(file_path),
            'matches': total_changes,
            'changed': content != new_content
        }

        if not dry_run and result['changed']:
            self._backup_and_write(file_path, new_content)

        return result

    def insert_changelog_in_seeding(
        self,
        version: str,
        changelog_code: str,
        notification_code: str,
        dry_run: bool = False
    ) -> Dict[str, any]:
        """
        Insert changelog entry and update notification in seeding.py.

        Args:
            version: Version string
            changelog_code: Python code for ChangelogEntry
            notification_code: Python code for Notification
            dry_run: If True, only show what would be changed

        Returns:
            Dictionary with update results
        """
        file_path = self.project_root / "yads" / "core" / "seeding.py"

        with open(file_path, 'r') as f:
            content = f.read()

        # Find the session.commit() line to insert before it
        commit_pattern = r'(\s*)(session\.commit\(\))'
        match = re.search(commit_pattern, content)

        if not match:
            raise ValueError(f"Could not find session.commit() in {file_path}")

        # Insert changelog entry before commit
        indent = match.group(1)
        insert_pos = match.start()

        # Add changelog entry with proper indentation
        changelog_lines = changelog_code.strip().split('\n')
        indented_changelog = '\n'.join(indent + line if line.strip() else ''
                                       for line in changelog_lines)

        new_content = (
            content[:insert_pos] +
            indented_changelog + '\n\n' +
            content[insert_pos:]
        )

        # Update notification if provided
        if notification_code:
            # Find and replace the latest update notification
            # Pattern: Find the Notification block for updates
            notification_pattern = r'(if not session\.query\(Notification\)\.where.*?notification_update.*?session\.add\(notification_update\))'

            if re.search(notification_pattern, new_content, re.DOTALL):
                # Replace with new notification
                new_content = re.sub(
                    notification_pattern,
                    notification_code.strip(),
                    new_content,
                    flags=re.DOTALL
                )

        result = {
            'file': str(file_path),
            'matches': 1,
            'changed': content != new_content
        }

        if not dry_run and result['changed']:
            self._backup_and_write(file_path, new_content)

        return result

    def insert_changelog_in_html(
        self,
        version: str,
        changelog_html: str,
        language: str,
        dry_run: bool = False
    ) -> Dict[str, any]:
        """
        Insert changelog HTML in changes.html.

        Args:
            version: Version string
            changelog_html: HTML content for changelog
            language: 'en' or 'de'
            dry_run: If True, only show what would be changed

        Returns:
            Dictionary with update results
        """
        file_path = self.project_root / "yads-homepage" / language / "changes.html"

        with open(file_path, 'r') as f:
            content = f.read()

        # Find the timeline div opening to insert after it
        timeline_pattern = r'(<div class="timeline">)'
        match = re.search(timeline_pattern, content)

        if not match:
            raise ValueError(f"Could not find timeline div in {file_path}")

        insert_pos = match.end()

        # Insert changelog HTML after timeline opening
        new_content = (
            content[:insert_pos] +
            '\n' + changelog_html + '\n' +
            content[insert_pos:]
        )

        result = {
            'file': str(file_path),
            'matches': 1,
            'changed': content != new_content
        }

        if not dry_run and result['changed']:
            self._backup_and_write(file_path, new_content)

        return result

    def _backup_and_write(self, file_path: Path, content: str) -> None:
        """
        Create backup and write new content atomically.

        Args:
            file_path: Path to file to update
            content: New content to write
        """
        backup_path = file_path.with_suffix(file_path.suffix + '.bak')

        # Create backup
        shutil.copy2(file_path, backup_path)
        self.backup_files.append((file_path, backup_path))

        # Write new content
        with open(file_path, 'w') as f:
            f.write(content)

    def rollback(self) -> None:
        """Restore all backed up files"""
        for original, backup in reversed(self.backup_files):
            if backup.exists():
                shutil.copy2(backup, original)
                backup.unlink()

        self.backup_files.clear()

    def cleanup_backups(self) -> None:
        """Remove all backup files after successful completion"""
        for _, backup in self.backup_files:
            if backup.exists():
                backup.unlink()

        self.backup_files.clear()

    def finalize_checksum(self, version: str, checksum: str, dry_run: bool = False) -> List[Dict[str, any]]:
        """
        Replace checksum placeholders with actual hash.

        Args:
            version: Version string
            checksum: Real SHA256 hash
            dry_run: If True, only preview

        Returns:
            List of update results
        """
        results = []
        placeholder = "[SHA256_HASH_TBD]"
        
        files_to_patch = [
            self.project_root / "yads" / "core" / "seeding.py",
            self.project_root / "yads-homepage" / "en" / "changes.html",
            self.project_root / "yads-homepage" / "de" / "changes.html"
        ]
        
        for file_path in files_to_patch:
            if not file_path.exists():
                continue
                
            with open(file_path, 'r') as f:
                content = f.read()
            
            if placeholder in content:
                new_content = content.replace(placeholder, checksum)
                
                result = {
                    'file': str(file_path),
                    'matches': content.count(placeholder),
                    'changed': True
                }
                
                if not dry_run:
                    self._backup_and_write(file_path, new_content)
                
                results.append(result)
        
        return results

    def update_all_files(
        self,
        version: str,
        changelog_code: str,
        changelog_html_en: str,
        changelog_html_de: str,
        notification_code: Optional[str] = None,
        dry_run: bool = False
    ) -> List[Dict[str, any]]:
        """
        Update all files for a release.

        Args:
            version: New version string
            changelog_code: Python code for seeding.py
            changelog_html_en: English HTML for changes.html
            changelog_html_de: German HTML for changes.html
            notification_code: Optional notification code
            dry_run: If True, only preview changes

        Returns:
            List of update results for each file
        """
        results = []

        try:
            # Update version in config.py
            results.append(self.update_version_in_config(version, dry_run))

            # Update USER_GUIDE.md
            results.append(self.update_user_guide(version, dry_run))

            # Update docs.html (EN and DE)
            results.append(self.update_docs_html(version, 'en', dry_run))
            results.append(self.update_docs_html(version, 'de', dry_run))

            # Update seeding.py
            results.append(self.insert_changelog_in_seeding(
                version, changelog_code, notification_code or '', dry_run
            ))

            # Update changes.html (EN and DE)
            results.append(self.insert_changelog_in_html(
                version, changelog_html_en, 'en', dry_run
            ))
            results.append(self.insert_changelog_in_html(
                version, changelog_html_de, 'de', dry_run
            ))

            return results

        except Exception as e:
            if not dry_run:
                self.rollback()
            raise
