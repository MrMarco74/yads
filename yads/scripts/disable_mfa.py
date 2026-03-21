import sys
import os
import argparse

# Add parent directory to path so we can import yads modules
# Assuming script is run as: python yads/scripts/disable_mfa.py admin
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlmodel import Session, select
from yads.database import engine
from yads.models import User

def disable_mfa(username: str):
    """
    Disables MFA for a specific user by resetting mfa_enabled and mfa_secret.
    """
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        results = session.exec(statement)
        user = results.first()

        if not user:
            print(f"[-] Error: User '{username}' not found in database.")
            sys.exit(1)

        if not user.mfa_enabled:
            print(f"[*] Info: MFA is already disabled for user '{username}'.")
            return

        print(f"[*] Disabling MFA for user '{username}'...")
        user.mfa_enabled = False
        user.mfa_secret = None
        user.pending_mfa_secret = None
        
        session.add(user)
        session.commit()
        
        print(f"[+] Success: MFA has been disabled for user '{username}'.")
        print("[!] Advice: Please tell the user to re-enable MFA as soon as they have a new device.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Emergency MFA Reset Utility for YADS")
    parser.add_argument("username", help="Username to disable MFA for")
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    disable_mfa(args.username)
