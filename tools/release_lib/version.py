"""
Semantic Version Management

Handles parsing and manipulation of semantic versions (MAJOR.MINOR.PATCH).
"""

import re
from typing import Tuple


class SemanticVersion:
    """Parse and manipulate semantic versions"""

    def __init__(self, version_string: str):
        """
        Initialize a semantic version from a string.

        Args:
            version_string: Version in format "MAJOR.MINOR.PATCH" (e.g., "1.13.3")

        Raises:
            ValueError: If version string is not in valid semantic version format
        """
        match = re.match(r'^(\d+)\.(\d+)\.(\d+)$', version_string.strip())
        if not match:
            raise ValueError(
                f"Invalid version format: '{version_string}'. "
                f"Expected format: MAJOR.MINOR.PATCH (e.g., 1.13.3)"
            )

        self.major, self.minor, self.patch = map(int, match.groups())
        self.original = version_string.strip()

    def bump(self, bump_type: str) -> str:
        """
        Bump version according to type.

        Args:
            bump_type: One of 'major', 'minor', or 'patch'

        Returns:
            New version string

        Raises:
            ValueError: If bump_type is not recognized
        """
        bump_type = bump_type.lower()

        if bump_type == 'major':
            # Major: 1.13.3 → 2.0.0 (breaking changes)
            return f"{self.major + 1}.0.0"
        elif bump_type == 'minor':
            # Minor: 1.13.3 → 1.14.0 (new features, backward compatible)
            return f"{self.major}.{self.minor + 1}.0"
        elif bump_type == 'patch':
            # Patch: 1.13.3 → 1.13.4 (bug fixes)
            return f"{self.major}.{self.minor}.{self.patch + 1}"
        else:
            raise ValueError(
                f"Invalid bump type: '{bump_type}'. "
                f"Expected one of: 'major', 'minor', 'patch'"
            )

    def compare(self, other: 'SemanticVersion') -> int:
        """
        Compare this version to another.

        Args:
            other: Another SemanticVersion instance

        Returns:
            -1 if self < other, 0 if equal, 1 if self > other
        """
        self_tuple = (self.major, self.minor, self.patch)
        other_tuple = (other.major, other.minor, other.patch)

        if self_tuple < other_tuple:
            return -1
        elif self_tuple > other_tuple:
            return 1
        else:
            return 0

    def __str__(self) -> str:
        """String representation"""
        return f"{self.major}.{self.minor}.{self.patch}"

    def __repr__(self) -> str:
        """Developer representation"""
        return f"SemanticVersion('{self}')"

    def __eq__(self, other) -> bool:
        """Equality comparison"""
        if isinstance(other, SemanticVersion):
            return self.compare(other) == 0
        elif isinstance(other, str):
            return str(self) == other
        return False

    def __lt__(self, other: 'SemanticVersion') -> bool:
        """Less than comparison"""
        return self.compare(other) < 0

    def __le__(self, other: 'SemanticVersion') -> bool:
        """Less than or equal comparison"""
        return self.compare(other) <= 0

    def __gt__(self, other: 'SemanticVersion') -> bool:
        """Greater than comparison"""
        return self.compare(other) > 0

    def __ge__(self, other: 'SemanticVersion') -> bool:
        """Greater than or equal comparison"""
        return self.compare(other) >= 0


def extract_version_from_file(file_path: str) -> SemanticVersion:
    """
    Extract version from yads/config.py.

    Args:
        file_path: Path to config.py file

    Returns:
        SemanticVersion instance

    Raises:
        ValueError: If version not found or invalid format
    """
    with open(file_path, 'r') as f:
        content = f.read()

    # Look for VERSION: str = "X.Y.Z" pattern
    match = re.search(r'VERSION:\s*str\s*=\s*["\'](\d+\.\d+\.\d+)["\']', content)
    if not match:
        raise ValueError(f"Could not find VERSION in {file_path}")

    version_string = match.group(1)
    return SemanticVersion(version_string)
