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


# ---------------------------------------------------------------------------
# Module-level helpers for changelog archive maintenance
# ---------------------------------------------------------------------------

def _parse_ver(v_str: str) -> tuple:
    try:
        return tuple(int(x) for x in v_str.strip().split('.'))
    except Exception:
        return (0, 0, 0)


def _strip_archive_wrapper(html: str) -> str:
    """Remove <details class="change-archive"> wrapper, keeping only the entry blocks."""
    # Remove opening preamble: <details ...> ... <div class="archive-body">
    html = re.sub(
        r'\s*<details class="change-archive">.*?<div class="archive-body">\s*',
        '\n',
        html,
        flags=re.DOTALL,
    )
    # Remove closing </div> + </details> of the archive
    html = re.sub(r'\s*</div>\s*\n\s*</details>', '', html)
    return html


def _extract_entry_html(block: str) -> str:
    """
    From a raw block (comment + div + content + trailing junk), extract only the
    <!-- Version --> comment + balanced <div class="change-entry">...</div>.
    """
    comment_match = re.search(r'<!--.*?-->', block, re.DOTALL)
    comment_start = comment_match.start() if comment_match else 0

    div_start = re.search(r'<div class="change-entry[^"]*">', block)
    if not div_start:
        return block[comment_start:]

    pos = div_start.end()
    depth = 1
    while pos < len(block) and depth > 0:
        next_open = block.find('<div', pos)
        next_close = block.find('</div>', pos)
        if next_open == -1 and next_close == -1:
            break
        elif next_open == -1 or (next_close != -1 and next_close < next_open):
            depth -= 1
            pos = next_close + len('</div>')
        else:
            depth += 1
            pos = next_open + 4  # len('<div')

    return block[comment_start:pos]


def _split_into_entries(html: str) -> list:
    """Split flat timeline HTML into a list of entry dicts."""
    pattern = re.compile(
        r'<!--\s*Version\s+(\d+\.\d+\.\d+)\s+\((\w+)\)\s*-->',
        re.IGNORECASE,
    )
    matches = list(pattern.finditer(html))
    entries = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(html)
        block = _extract_entry_html(html[start:end])
        entries.append({
            'version': _parse_ver(m.group(1)),
            'channel': m.group(2),
            'html': block,
        })
    return entries


def _set_patch_class(html: str, is_patch: bool) -> str:
    """Add or remove `change-entry-patch` CSS class from an entry block."""
    html = re.sub(
        r'<div class="change-entry change-entry-patch">',
        '<div class="change-entry">',
        html,
    )
    if is_patch:
        html = html.replace(
            '<div class="change-entry">',
            '<div class="change-entry change-entry-patch">',
            1,
        )
    return html


def _build_archive_block(archive_entries: list, language: str) -> str:
    """Build the <details class="change-archive"> block for older entries."""
    if not archive_entries:
        return ''
    first_ver = archive_entries[0]['version']
    minor_str = f"v{first_ver[0]}.{first_ver[1]}.x"
    if language == 'de':
        summary_text = f"Ältere Versionen anzeigen ({minor_str} und früher)"
    else:
        summary_text = f"Show older releases ({minor_str} and earlier)"

    inner = '\n'.join(e['html'] for e in archive_entries)
    chevron = (
        '<svg class="archive-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">'
        '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>'
        '</svg>'
    )
    return (
        '        <details class="change-archive">\n'
        '            <summary>\n'
        f'                {chevron}\n'
        f'                {summary_text}\n'
        '            </summary>\n'
        '            <div class="archive-body">\n'
        f'\n{inner}\n'
        '            </div>\n'
        '        </details>\n'
    )


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

        # Replace version references and date
        today = datetime.now().strftime("%Y-%m-%d")
        patterns = [
            (r'v\d+\.\d+\.\d+', f'v{new_version}'),
            (r'Version \d+\.\d+\.\d+', f'Version {new_version}'),
            (r'version \d+\.\d+\.\d+', f'version {new_version}'),
            # Update "Last Updated" / "Zuletzt aktualisiert" date
            (r'(Last Updated:</strong>\s*)\d{4}-\d{2}-\d{2}', rf'\g<1>{today}'),
            (r'(Zuletzt aktualisiert:</strong>\s*)\d{4}-\d{2}-\d{2}', rf'\g<1>{today}'),
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

    def update_index_html_badge(
        self,
        new_version: str,
        language: str,
        dry_run: bool = False
    ) -> Dict[str, any]:
        """Update version badge in index.html (e.g. 'v1.42 STABLE' → 'v1.45.3 STABLE')."""
        file_path = self.project_root / "yads-homepage" / language / "index.html"

        with open(file_path, 'r') as f:
            content = f.read()

        # Match e.g. v1.42 STABLE or v1.45.2 STABLE
        major_minor = '.'.join(new_version.split('.')[:2])
        pattern = r'v\d+\.\d+(?:\.\d+)? STABLE'
        replacement = f'v{major_minor} STABLE'
        new_content, count = re.subn(pattern, replacement, content)

        result = {
            'file': str(file_path),
            'matches': count,
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

    def maintain_changelog_archive(
        self,
        language: str = 'en',
        keep_minor_series: int = 2,
        dry_run: bool = False,
    ) -> Dict:
        """
        Maintain the archive structure in changes.html after a new entry was inserted.

        - Keeps the last `keep_minor_series` minor version series fully visible
          (default: 2, e.g. v1.51.x + v1.50.x)
        - Marks patch releases (x.y.z, z > 0) in the visible range with
          `change-entry-patch` CSS class (compact display)
        - Wraps all older entries in a <details class="change-archive"> block
          (collapsed by default, labelled with the oldest visible minor)

        Called automatically by update_all_files / update_beta_files.
        """
        file_path = self.project_root / "yads-homepage" / language / "changes.html"
        if not file_path.exists():
            return {'file': str(file_path), 'changed': False, 'matches': 0, 'error': 'file not found'}

        content = file_path.read_text(encoding='utf-8')

        TIMELINE_OPEN = '<div class="timeline">'
        FOOTER_ANCHOR = '\n    <footer'

        idx_open = content.find(TIMELINE_OPEN)
        idx_footer = content.find(FOOTER_ANCHOR)

        if idx_open == -1 or idx_footer == -1:
            return {'file': str(file_path), 'changed': False, 'matches': 0, 'error': 'timeline/footer marker not found'}

        head = content[:idx_open + len(TIMELINE_OPEN)]
        tail = content[idx_footer:]  # starts with \n    <footer...
        timeline_body = content[idx_open + len(TIMELINE_OPEN):idx_footer]

        # 1. Flatten: remove existing archive wrapper
        flat = _strip_archive_wrapper(timeline_body)

        # 2. Split into individual entry dicts
        entries = _split_into_entries(flat)
        if not entries:
            return {'file': str(file_path), 'changed': False, 'matches': 0, 'error': 'no entries found'}

        # 3. Determine which minor series to keep visible
        all_minors = sorted(
            set((e['version'][0], e['version'][1]) for e in entries),
            reverse=True,
        )
        keep_minors = set(all_minors[:keep_minor_series])

        visible = [e for e in entries if (e['version'][0], e['version'][1]) in keep_minors]
        archive = [e for e in entries if (e['version'][0], e['version'][1]) not in keep_minors]

        # 4. Apply / remove patch CSS class for visible entries
        for e in visible:
            e['html'] = _set_patch_class(e['html'], e['version'][2] > 0)

        # 5. Rebuild timeline body
        new_body = '\n' + '\n'.join(e['html'] for e in visible) + '\n'
        if archive:
            new_body += _build_archive_block(archive, language)
        new_body += '\n    </div>\n'  # close timeline/container

        new_content = head + new_body + tail

        result = {
            'file': str(file_path),
            'changed': content != new_content,
            'matches': len(visible) + len(archive),
            'visible_entries': len(visible),
            'archived_entries': len(archive),
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
        dry_run: bool = False,
        channel: str = 'stable'
    ) -> List[Dict[str, any]]:
        """
        Update all files for a release.

        For beta channel: only updates changes.html (EN+DE) — skips config.py,
        USER_GUIDE.md, docs.html, and seeding.py since betas are preview-only.

        Args:
            version: New version string
            changelog_code: Python code for seeding.py
            changelog_html_en: English HTML for changes.html
            changelog_html_de: German HTML for changes.html
            notification_code: Optional notification code
            dry_run: If True, only preview changes
            channel: Release channel ('stable' or 'beta')

        Returns:
            List of update results for each file
        """
        results = []

        try:
            if channel == 'beta':
                # Beta: only announce on the homepage changelog, nothing else
                results.append(self.insert_changelog_in_html(
                    version, changelog_html_en, 'en', dry_run
                ))
                results.append(self.insert_changelog_in_html(
                    version, changelog_html_de, 'de', dry_run
                ))
                # Maintain archive structure after insert
                results.append(self.maintain_changelog_archive('en', dry_run=dry_run))
                results.append(self.maintain_changelog_archive('de', dry_run=dry_run))
                return results

            # Stable release: update all files
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

            # Maintain archive structure (patch class + <details> cutoff)
            results.append(self.maintain_changelog_archive('en', dry_run=dry_run))
            results.append(self.maintain_changelog_archive('de', dry_run=dry_run))

            # Update version badge in index.html (EN and DE)
            results.append(self.update_index_html_badge(version, 'en', dry_run))
            results.append(self.update_index_html_badge(version, 'de', dry_run))

            return results

        except Exception as e:
            if not dry_run:
                self.rollback()
            raise
