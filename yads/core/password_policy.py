"""
BSI IT-Grundschutz ORP.4.A22 compliant password policy.

Requirements:
- Minimum 12 characters
- At least 3 of 4 character classes: uppercase, lowercase, digits, special characters

Reference: BSI IT-Grundschutz Kompendium ORP.4.A22 (Regelung zur Passwortqualität)
"""
import re
from typing import Optional

MIN_LENGTH = 12


def validate_password(password: str) -> Optional[str]:
    """
    Validate password against BSI ORP.4.A22 policy.
    Returns an error message string, or None if the password is valid.
    """
    if not password or len(password) < MIN_LENGTH:
        return (
            f"Password must be at least {MIN_LENGTH} characters long "
            f"(BSI IT-Grundschutz ORP.4.A22)."
        )

    classes = 0
    if re.search(r'[A-Z]', password):
        classes += 1
    if re.search(r'[a-z]', password):
        classes += 1
    if re.search(r'[0-9]', password):
        classes += 1
    if re.search(r'[^A-Za-z0-9]', password):
        classes += 1

    if classes < 3:
        return (
            "Password must contain characters from at least 3 of these 4 classes: "
            "uppercase letters, lowercase letters, digits, special characters "
            "(BSI IT-Grundschutz ORP.4.A22)."
        )

    return None
