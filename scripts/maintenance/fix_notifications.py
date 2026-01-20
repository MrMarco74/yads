import sys
import os
# Add project root to sys.path to allow importing 'yads'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from sqlmodel import Session, select
from yads.database import engine
from yads.models import Notification

def fix_notifications():
    with Session(engine) as session:
        # Find broken notifications (icon is just text "sparkles" or similar)
        # We check for those not starting with 'M' (SVG Move)
        # But specifically "sparkles" to fix it nicely.
        
        statement = select(Notification)
        all_notes = session.exec(statement).all()
        
        fixed = 0
        deleted = 0
        
        valid_sparkles = 'M5 3v4 M3 5h4 M6 17v4 m-2-2h4 m5-16 l2.286 6.857 L21 12 l-5.714 2.143 L13 21 l-2.286-6.857 L5 12 l5.714-2.143 L13 3z'
        
        for n in all_notes:
            if not n.icon or not n.icon.strip().upper().startswith('M'):
                print(f"Found invalid icon: '{n.icon}' in Notification {n.id}")
                
                if n.icon == 'sparkles':
                    print(f" -> Fixing 'sparkles' to valid SVG path.")
                    n.icon = valid_sparkles
                    session.add(n)
                    fixed += 1
                else:
                    print(f" -> Deleting garbage notification.")
                    session.delete(n)
                    deleted += 1
        
        session.commit()
        print(f"Done. Fixed: {fixed}, Deleted: {deleted}")

if __name__ == "__main__":
    fix_notifications()
