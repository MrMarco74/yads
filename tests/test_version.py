"""
Unit tests for version management
"""

import pytest
import sys
from pathlib import Path

# Add release_lib to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from release_lib.version import SemanticVersion


class TestSemanticVersion:
    """Test semantic version parsing and manipulation"""

    def test_parse_valid_version(self):
        """Test parsing valid semantic version"""
        v = SemanticVersion("1.13.3")
        assert v.major == 1
        assert v.minor == 13
        assert v.patch == 3
        assert str(v) == "1.13.3"

    def test_parse_invalid_version(self):
        """Test parsing invalid version raises error"""
        with pytest.raises(ValueError):
            SemanticVersion("1.13")

        with pytest.raises(ValueError):
            SemanticVersion("v1.13.3")

        with pytest.raises(ValueError):
            SemanticVersion("1.13.3-beta")

    def test_bump_patch(self):
        """Test patch version bump"""
        v = SemanticVersion("1.13.3")
        assert v.bump('patch') == "1.13.4"

    def test_bump_minor(self):
        """Test minor version bump (resets patch)"""
        v = SemanticVersion("1.13.3")
        assert v.bump('minor') == "1.14.0"

    def test_bump_major(self):
        """Test major version bump (resets minor and patch)"""
        v = SemanticVersion("1.13.3")
        assert v.bump('major') == "2.0.0"

    def test_bump_invalid_type(self):
        """Test invalid bump type raises error"""
        v = SemanticVersion("1.13.3")
        with pytest.raises(ValueError):
            v.bump('invalid')

    def test_version_comparison(self):
        """Test version comparison operators"""
        v1 = SemanticVersion("1.13.3")
        v2 = SemanticVersion("1.13.4")
        v3 = SemanticVersion("1.14.0")
        v4 = SemanticVersion("2.0.0")

        assert v1 < v2
        assert v2 < v3
        assert v3 < v4

        assert v4 > v3
        assert v3 > v2
        assert v2 > v1

        assert v1 == SemanticVersion("1.13.3")
        assert v1 != v2

    def test_version_string_equality(self):
        """Test comparing version with string"""
        v = SemanticVersion("1.13.3")
        assert v == "1.13.3"
        assert v != "1.13.4"

    def test_version_representation(self):
        """Test string representations"""
        v = SemanticVersion("1.13.3")
        assert str(v) == "1.13.3"
        assert repr(v) == "SemanticVersion('1.13.3')"

    def test_bump_from_zero_version(self):
        """Test bumping from 0.0.0"""
        v = SemanticVersion("0.0.0")
        assert v.bump('patch') == "0.0.1"
        assert v.bump('minor') == "0.1.0"
        assert v.bump('major') == "1.0.0"

    def test_bump_with_whitespace(self):
        """Test parsing version with whitespace"""
        v = SemanticVersion("  1.13.3  ")
        assert str(v) == "1.13.3"
        assert v.bump('patch') == "1.13.4"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
