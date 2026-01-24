"""
Changelog Management

Handles interactive changelog collection and code generation.
"""

import subprocess
import tempfile
from typing import Dict, List, Optional
from datetime import datetime


class ChangelogManager:
    """Manage changelog creation and formatting"""

    SECTION_EMOJIS = {
        'features': '🚀 New Features',
        'improvements': '⚡ Improvements',
        'fixes': '🐛 Bug Fixes',
        'security': '🔒 Security',
        'performance': '📈 Performance',
        'documentation': '📚 Documentation',
        'breaking': '💥 Breaking Changes',
    }

    def __init__(self):
        """Initialize changelog manager"""
        self.changelog_data: Optional[Dict] = None

    def collect_interactive(self, version: str, interactive: bool = True) -> Dict:
        """
        Collect changelog entries.

        Args:
            version: Version string for this release
            interactive: If False, use default title and empty sections.

        Returns:
            Dictionary with changelog data
        """
        print(f"\n{'='*60}")
        print(f"  Changelog Collection for v{version}")
        print(f"{'='*60}\n")

        if not interactive:
            print("Non-interactive mode: using defaults.")
            title = f"Release {version}"
            sections = []
        else:
            # Collect release title
            title = input("Release title (e.g., 'Performance Improvements'): ").strip()
            if not title:
                title = f"Release {version}"
            
            # (Rest of interactive collection)

            # Collect sections
            sections = []

            print("\n--- Available sections ---")
            for idx, (key, label) in enumerate(self.SECTION_EMOJIS.items(), 1):
                print(f"{idx}. {label}")
            print("0. Done adding sections\n")

            while True:
                section_choice = input("Select section (number) or 0 when done: ").strip()

                if section_choice == '0':
                    break

                try:
                    section_idx = int(section_choice) - 1
                    section_keys = list(self.SECTION_EMOJIS.keys())

                    if 0 <= section_idx < len(section_keys):
                        section_key = section_keys[section_idx]
                        section_name = self.SECTION_EMOJIS[section_key]

                        # Collect items for this section
                        items = self._collect_section_items(section_name)

                        if items:
                            sections.append({
                                'key': section_key,
                                'name': section_name,
                                'items': items
                            })
                    else:
                        print("Invalid section number. Try again.")
                except ValueError:
                    print("Please enter a number.")

        if not sections:
            print("\nWarning: No changelog sections added!")

        self.changelog_data = {
            'version': version,
            'title': title,
            'sections': sections
        }

        return self.changelog_data

    def _collect_section_items(self, section_name: str) -> List[str]:
        """
        Collect items for a changelog section.

        Args:
            section_name: Name of the section

        Returns:
            List of item strings
        """
        print(f"\n--- {section_name} ---")
        print("Enter items (one per line). Empty line when done.\n")

        items = []
        while True:
            item = input(f"  • ").strip()
            if not item:
                break
            items.append(item)

        return items

    def collect_from_editor(self, version: str) -> Dict:
        """
        Collect changelog using text editor (YAML format).

        Args:
            version: Version string

        Returns:
            Dictionary with changelog data
        """
        import yaml

        template = f"""# Changelog for v{version}
# Edit sections and items below, then save and close

title: "Release Title Here"

sections:
  - name: "🚀 New Features"
    items:
      - "Feature item 1"
      - "Feature item 2"

  - name: "🐛 Bug Fixes"
    items:
      - "Fix item 1"

# Remove sections you don't need
# Available section names:
#   - 🚀 New Features
#   - ⚡ Improvements
#   - 🐛 Bug Fixes
#   - 🔒 Security
#   - 📈 Performance
#   - 📚 Documentation
#   - 💥 Breaking Changes
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(template)
            temp_path = f.name

        # Open in editor
        editor = subprocess.os.getenv('EDITOR', 'nano')
        subprocess.run([editor, temp_path])

        # Parse YAML
        with open(temp_path, 'r') as f:
            data = yaml.safe_load(f)

        # Clean up
        subprocess.os.unlink(temp_path)

        self.changelog_data = {
            'version': version,
            'title': data.get('title', f'Release {version}'),
            'sections': data.get('sections', [])
        }

        return self.changelog_data

    def generate_python_code(self, changelog_data: Dict, language: str = 'en', checksum: Optional[str] = None) -> str:
        """
        Generate Python code for seeding.py ChangelogEntry.

        Args:
            changelog_data: Changelog data dictionary
            language: 'en' or 'de'
            checksum: Optional SHA256 checksum

        Returns:
            Python code string
        """
        version = changelog_data['version']
        version_var = version.replace('.', '')  # 1.13.4 -> 1134
        title = changelog_data['title']

        # Generate HTML content
        html_parts = []
        for section in changelog_data['sections']:
            section_name = section['name']
            items = section['items']

            html_parts.append(f"        <h3>{section_name}</h3>")
            html_parts.append("        <ul>")
            for item in items:
                # Escape quotes in item text
                item_escaped = item.replace('"', '\\"')
                html_parts.append(f'            <li>{item_escaped}</li>')
            html_parts.append("        </ul>")

        if checksum:
            html_parts.append(f'<p style=\\\"margin-top: 1rem; font-family: monospace; font-size: 0.8rem; color: #888;\\\">SHA256: {checksum}</p>')

        html_content = '\n'.join(html_parts)

        # Escape title for Python string
        title_escaped = title.replace('"', '\\"')

        code = f'''if not session.query(ChangelogEntry).where(ChangelogEntry.version == "{version}").first():
    entry_{version_var} = ChangelogEntry(
        title="YADS v{version}: {title_escaped}",
        version="{version}",
        content="""
{html_content}
        """
    )
    session.add(entry_{version_var})
'''

        return code

    def generate_notification_code(self, changelog_data: Dict, language: str = 'en') -> str:
        """
        Generate Python code for update notification in seeding.py.

        Args:
            changelog_data: Changelog data dictionary
            language: 'en' or 'de'

        Returns:
            Python code string
        """
        version = changelog_data['version']
        title = changelog_data['title']

        # Create brief message from first section
        message_parts = []
        if changelog_data['sections']:
            first_section = changelog_data['sections'][0]
            section_name = first_section['name']
            items = first_section['items'][:2]  # Take first 2 items

            if language == 'de':
                message_parts.append(f"Version {version} ist verfügbar: {title}")
            else:
                message_parts.append(f"Version {version} is available: {title}")

            if items:
                message_parts.append("Highlights: " + ", ".join(items))

        message = " ".join(message_parts)
        message_escaped = message.replace('"', '\\"')

        code = f'''if not session.query(Notification).where(
        Notification.notification_type == NotificationType.UPDATE,
        Notification.title.contains("{version}")
    ).first():
    notification_update = Notification(
        title="Update Available: v{version}",
        message="{message_escaped}",
        notification_type=NotificationType.UPDATE,
        severity=NotificationSeverity.INFO
    )
    session.add(notification_update)
'''

        return code

    def generate_html(self, changelog_data: Dict, checksum: Optional[str] = None) -> str:
        """
        Generate HTML for changes.html.

        Args:
            changelog_data: Changelog data dictionary
            checksum: Optional SHA256 checksum

        Returns:
            HTML string
        """
        version = changelog_data['version']
        title = changelog_data['title']

        html_parts = [
            f'        <!-- Version {version} -->',
            '        <div class="change-entry">',
            f'            <span class="version-badge">v{version}</span>',
            '            <div class="change-card">',
            f'                <h2 style="margin-bottom: 1rem; color: #fff;">{title}</h2>',
            ''
        ]

        for section in changelog_data['sections']:
            section_name = section['name']
            items = section['items']

            html_parts.append(f'                <h3>{section_name}</h3>')
            html_parts.append('                <ul>')
            for item in items:
                html_parts.append(f'                    <li>{item}</li>')
            html_parts.append('                </ul>')

        if checksum:
            html_parts.append(f'                <p style="margin-top: 1.5rem; font-family: monospace; font-size: 0.8rem; color: #888; word-break: break-all;">SHA256: {checksum}</p>')

        html_parts.extend([
            '            </div>',
            '        </div>',
        ])

        return '\n'.join(html_parts)

    def preview_changelog(self, changelog_data: Optional[Dict] = None) -> None:
        """
        Display a preview of the changelog.

        Args:
            changelog_data: Optional changelog data (uses stored if not provided)
        """
        data = changelog_data or self.changelog_data

        if not data:
            print("No changelog data to preview.")
            return

        print(f"\n{'='*60}")
        print(f"  Changelog Preview: v{data['version']}")
        print(f"{'='*60}\n")
        print(f"Title: {data['title']}\n")

        for section in data['sections']:
            print(f"{section['name']}")
            for item in section['items']:
                print(f"  • {item}")
            print()
