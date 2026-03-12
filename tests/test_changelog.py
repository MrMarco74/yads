"""
Unit tests for changelog management
"""

import pytest
import sys
from pathlib import Path

# Add release_lib to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from release_lib.changelog import ChangelogManager


class TestChangelogManager:
    """Test changelog generation and formatting"""

    def test_generate_python_code(self):
        """Test Python code generation for seeding.py"""
        manager = ChangelogManager()

        changelog_data = {
            'version': '1.13.4',
            'title': 'Test Release',
            'sections': [
                {
                    'name': '🚀 New Features',
                    'items': ['Feature 1', 'Feature 2']
                },
                {
                    'name': '🐛 Bug Fixes',
                    'items': ['Fix 1']
                }
            ]
        }

        code = manager.generate_python_code(changelog_data)

        # Verify key elements in generated code
        assert 'entry_1134' in code
        assert 'ChangelogEntry' in code
        assert 'version="1.13.4"' in code
        assert 'YADS v1.13.4: Test Release' in code
        assert '🚀 New Features' in code
        assert 'Feature 1' in code
        assert '🐛 Bug Fixes' in code
        assert 'session.add(entry_1134)' in code

    def test_generate_html(self):
        """Test HTML generation for changes.html"""
        manager = ChangelogManager()

        changelog_data = {
            'version': '1.13.4',
            'title': 'Test Release',
            'sections': [
                {
                    'name': '🚀 New Features',
                    'items': ['Feature 1', 'Feature 2']
                }
            ]
        }

        html = manager.generate_html(changelog_data)

        # Verify HTML structure
        assert 'class="change-entry"' in html
        assert 'class="version-badge"' in html
        assert 'v1.13.4' in html
        assert 'Test Release' in html
        assert '🚀 New Features' in html
        assert '<li>Feature 1</li>' in html
        assert '<li>Feature 2</li>' in html

    def test_generate_notification_code(self):
        """Test notification code generation"""
        manager = ChangelogManager()

        changelog_data = {
            'version': '1.13.4',
            'title': 'Test Release',
            'sections': [
                {
                    'name': '🚀 New Features',
                    'items': ['Feature 1']
                }
            ]
        }

        code = manager.generate_notification_code(changelog_data, 'en')

        # Verify notification code
        assert 'notification_update' in code
        assert 'Notification' in code
        assert '1.13.4' in code
        assert 'NotificationType.UPDATE' in code
        assert 'session.add(notification_update)' in code

    def test_section_emojis(self):
        """Test predefined section emojis"""
        manager = ChangelogManager()

        assert '🚀 New Features' in manager.SECTION_EMOJIS.values()
        assert '🐛 Bug Fixes' in manager.SECTION_EMOJIS.values()
        assert '⚡ Improvements' in manager.SECTION_EMOJIS.values()
        assert '🔒 Security' in manager.SECTION_EMOJIS.values()

    def test_empty_changelog(self):
        """Test handling empty changelog"""
        manager = ChangelogManager()

        changelog_data = {
            'version': '1.13.4',
            'title': 'Empty Release',
            'sections': []
        }

        code = manager.generate_python_code(changelog_data)
        html = manager.generate_html(changelog_data)

        # Should still generate valid code/HTML
        assert 'entry_1134' in code
        assert 'Empty Release' in code
        assert 'v1.13.4' in html
        assert 'Empty Release' in html

    def test_special_characters_escaping(self):
        """Test escaping of special characters in output"""
        manager = ChangelogManager()

        changelog_data = {
            'version': '1.13.4',
            'title': 'Test "Quotes"',
            'sections': [
                {
                    'name': '🚀 Features',
                    'items': ['Item with "quotes"']
                }
            ]
        }

        code = manager.generate_python_code(changelog_data)

        # Quotes should be escaped in Python code
        assert 'Test \\"Quotes\\"' in code or "Test 'Quotes'" in code
        assert 'Item with \\"quotes\\"' in code or "Item with 'quotes'" in code


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
