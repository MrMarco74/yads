"""
Changelog Management

Handles interactive changelog collection and code generation.
Supports AI-powered changelog generation from git commits.
"""

import subprocess
import tempfile
import json
import re
from typing import Dict, List, Optional, Any
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
        'technical': '🔧 Technical Improvements',
    }

    def __init__(self):
        """Initialize changelog manager"""
        self.changelog_data: Optional[Dict] = None
        self._ai_model = None
        self._ai_service: Optional[str] = None

    def set_ai_model(self, model: Any, service: str) -> None:
        """
        Set the AI model for automated changelog generation.

        Args:
            model: The initialized AI model (Gemini or VertexAI)
            service: Service name ('gemini' or 'vertexai')
        """
        self._ai_model = model
        self._ai_service = service

    def _get_git_commits_since_last_tag(self, project_root: str) -> List[Dict[str, str]]:
        """
        Get git commits since the last release tag.

        Args:
            project_root: Path to the git repository root

        Returns:
            List of commit dictionaries with 'hash', 'subject', 'body'
        """
        try:
            # Get the last version tag (vX.Y.Z format)
            result = subprocess.run(
                ['git', 'describe', '--tags', '--abbrev=0', '--match', 'v*'],
                cwd=project_root,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                last_tag = result.stdout.strip()
                commit_range = f"{last_tag}..HEAD"
                print(f"  📋 Fetching commits since {last_tag}")
            else:
                # No tags found, get last 20 commits
                commit_range = "HEAD~20..HEAD"
                print("  📋 No previous tags found, fetching last 20 commits")

            # Get commits with full message
            # Format: hash|||subject|||body (using ||| as delimiter)
            result = subprocess.run(
                ['git', 'log', commit_range, '--pretty=format:%h|||%s|||%b---COMMIT_END---'],
                cwd=project_root,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print(f"  ⚠️  Git log failed: {result.stderr}")
                return []

            commits = []
            raw_commits = result.stdout.split('---COMMIT_END---')

            for raw in raw_commits:
                raw = raw.strip()
                if not raw:
                    continue

                parts = raw.split('|||')
                if len(parts) >= 2:
                    commits.append({
                        'hash': parts[0].strip(),
                        'subject': parts[1].strip(),
                        'body': parts[2].strip() if len(parts) > 2 else ''
                    })

            print(f"  📋 Found {len(commits)} commits to analyze")
            return commits

        except Exception as e:
            print(f"  ⚠️  Error fetching git commits: {e}")
            return []

    def _get_changed_files_summary(self, project_root: str) -> str:
        """
        Get a summary of changed files since last tag.

        Args:
            project_root: Path to the git repository root

        Returns:
            String summary of changed files by category
        """
        try:
            # Get last tag
            result = subprocess.run(
                ['git', 'describe', '--tags', '--abbrev=0', '--match', 'v*'],
                cwd=project_root,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                last_tag = result.stdout.strip()
                commit_range = f"{last_tag}..HEAD"
            else:
                commit_range = "HEAD~20..HEAD"

            # Get changed files
            result = subprocess.run(
                ['git', 'diff', '--name-only', commit_range],
                cwd=project_root,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                return ""

            files = result.stdout.strip().split('\n')

            # Categorize files
            categories = {
                'api': [],
                'core': [],
                'modules': [],
                'templates': [],
                'frontend': [],
                'config': [],
                'scripts': [],
                'other': []
            }

            for f in files:
                if not f:
                    continue
                if 'yads/api/' in f:
                    categories['api'].append(f)
                elif 'yads/core/' in f:
                    categories['core'].append(f)
                elif 'yads/modules/' in f:
                    categories['modules'].append(f)
                elif 'templates/' in f:
                    categories['templates'].append(f)
                elif 'frontend/' in f or '.css' in f:
                    categories['frontend'].append(f)
                elif 'config' in f.lower() or f.endswith('.py') and 'config' in f:
                    categories['config'].append(f)
                elif 'scripts/' in f or 'tools/' in f:
                    categories['scripts'].append(f)
                else:
                    categories['other'].append(f)

            summary_parts = []
            for cat, cat_files in categories.items():
                if cat_files:
                    summary_parts.append(f"{cat}: {len(cat_files)} files ({', '.join(cat_files[:3])}{'...' if len(cat_files) > 3 else ''})")

            return "; ".join(summary_parts)

        except Exception as e:
            return f"Error: {e}"

    def generate_changelog_from_commits(self, version: str, project_root: str) -> Dict:
        """
        Generate changelog from git commits using AI.

        Args:
            version: Version string for this release
            project_root: Path to the git repository root

        Returns:
            Dictionary with changelog data
        """
        if not self._ai_model:
            print("  ⚠️  No AI model configured, cannot auto-generate changelog")
            return self._create_fallback_changelog(version)

        # Fetch commits
        commits = self._get_git_commits_since_last_tag(project_root)

        if not commits:
            print("  ⚠️  No commits found, using fallback changelog")
            return self._create_fallback_changelog(version)

        # Get file change summary for context
        files_summary = self._get_changed_files_summary(project_root)

        # Prepare commit text for AI
        commit_text = "\n".join([
            f"- {c['subject']}" + (f"\n  {c['body']}" if c['body'] else "")
            for c in commits
        ])

        # Build AI prompt
        prompt = f"""Analyze these git commits for YADS (a domain security scanning platform) version {version} and generate a professional changelog.

GIT COMMITS:
{commit_text}

CHANGED FILES SUMMARY:
{files_summary}

Generate a JSON response with this EXACT structure:
{{
    "title": "A short, descriptive title (2-5 words) summarizing the main theme of this release",
    "sections": [
        {{
            "name": "🐛 Bug Fixes",
            "items": ["Clear description of fix 1", "Clear description of fix 2"]
        }},
        {{
            "name": "🚀 New Features",
            "items": ["Description of feature"]
        }}
    ]
}}

RULES:
1. The "title" should be catchy and summarize the main changes (e.g., "Critical Template Fix", "Performance Improvements", "Security Scanner Updates")
2. Only include sections that have actual changes. Available sections:
   - 🚀 New Features (for new functionality)
   - ⚡ Improvements (for enhancements to existing features)
   - 🐛 Bug Fixes (for bug fixes)
   - 🔒 Security (for security-related changes)
   - 📈 Performance (for performance improvements)
   - 🔧 Technical Improvements (for refactoring, code quality, internal changes)
   - 💥 Breaking Changes (for breaking API/behavior changes)
3. Each item should be a clear, user-friendly description (not the raw commit message)
4. Group related commits into single items when appropriate
5. Focus on what changed from the user's perspective
6. Be concise but informative
7. Do NOT include version numbers or dates in section items
8. Return ONLY valid JSON, no markdown formatting or explanation

Generate the changelog JSON:"""

        try:
            source_name = "Vertex AI" if self._ai_service == 'vertexai' else "Gemini"
            print(f"  🤖 {source_name} is generating changelog from {len(commits)} commits...")

            response = self._ai_model.generate_content(prompt)

            # Extract JSON from response
            text = response.text.strip()

            # Handle markdown code blocks
            if text.startswith("```json"):
                text = text[7:]
            elif text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

            # Parse JSON
            changelog_json = json.loads(text)

            # Validate structure
            if 'title' not in changelog_json or 'sections' not in changelog_json:
                raise ValueError("Invalid JSON structure from AI")

            # Build final changelog data
            self.changelog_data = {
                'version': version,
                'title': changelog_json['title'],
                'sections': changelog_json['sections']
            }

            print(f"  ✅ AI generated changelog: \"{changelog_json['title']}\"")
            return self.changelog_data

        except json.JSONDecodeError as e:
            print(f"  ⚠️  AI returned invalid JSON: {e}")
            print(f"  Raw response: {response.text[:200]}...")
            return self._create_fallback_changelog(version)
        except Exception as e:
            print(f"  ⚠️  AI changelog generation failed: {e}")
            return self._create_fallback_changelog(version)

    def _create_fallback_changelog(self, version: str) -> Dict:
        """
        Create a minimal fallback changelog when AI is unavailable.

        Args:
            version: Version string

        Returns:
            Minimal changelog dictionary
        """
        return {
            'version': version,
            'title': f"Release {version}",
            'sections': [{
                'name': '🔧 Technical Improvements',
                'items': ['Various bug fixes and improvements']
            }]
        }

    def collect_interactive(self, version: str, interactive: bool = True, project_root: Optional[str] = None) -> Dict:
        """
        Collect changelog entries.

        Args:
            version: Version string for this release
            interactive: If False, attempt AI-powered generation from git commits.
            project_root: Path to the git repository root (required for AI generation)

        Returns:
            Dictionary with changelog data
        """
        print(f"\n{'='*60}")
        print(f"  Changelog Collection for v{version}")
        print(f"{'='*60}\n")

        if not interactive:
            # In non-interactive mode, try AI-powered changelog generation
            if self._ai_model and project_root:
                print("Non-interactive mode: using AI to generate changelog from git commits...")
                return self.generate_changelog_from_commits(version, project_root)
            else:
                if not self._ai_model:
                    print("⚠️  No AI model configured for changelog generation.")
                if not project_root:
                    print("⚠️  Project root not provided for git commit analysis.")
                print("Falling back to minimal changelog...")
                return self._create_fallback_changelog(version)
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
