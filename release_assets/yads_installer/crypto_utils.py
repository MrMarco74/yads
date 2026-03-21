import re

def validate_bsi_password(password: str) -> (bool, str):
    """
    Validates password based on BSI CS 050 recommendations.
    Returns (is_valid, error_message).
    """
    if len(password) < 12:
        return False, "Passwort muss mindestens 12 Zeichen lang sein (BSI Empfehlung)."
    
    # Basic check against common patterns
    common_patterns = ["password123456", "yadsadmin2026!", "123456789012"]
    if password.lower() in [p.lower() for p in common_patterns]:
        return False, "Passwort ist zu einfach oder ein bekanntes Muster."

    # Check for categories (at least 3 of 4)
    categories = 0
    if re.search(r"[a-z]", password): categories += 1
    if re.search(r"[A-Z]", password): categories += 1
    if re.search(r"[0-9]", password): categories += 1
    if re.search(r"[^a-zA-Z0-9]", password): categories += 1
    
    if categories < 3:
        return False, "Passwort muss Zeichen aus mindestens 3 Kategorien enthalten (Groß, Klein, Zahlen, Sonderzeichen)."
        
    return True, ""
