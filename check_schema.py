import sys
import os
sys.path.append(os.getcwd())

from sqlalchemy import inspect
from yads.database import engine

def check_tags_column():
    inspector = inspect(engine)
    columns = [c['name'] for c in inspector.get_columns('target')]
    print(f"Target table columns: {columns}")
    
    if 'tags' in columns:
        print("Column 'tags' EXISTS.")
    else:
        print("Column 'tags' MISSING.")

if __name__ == "__main__":
    check_tags_column()
