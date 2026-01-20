import sqlite3
import json
import os
from datetime import datetime

DB_FILE = "licenses.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Customers Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Licenses Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            license_key TEXT NOT NULL,
            max_targets INTEGER,
            expires_at INTEGER,
            features TEXT,
            domains TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers (id)
        )
    ''')
    
    # Migrations for new columns (idempotent)
    columns = [
        ("default_max_targets", "INTEGER"),
        ("default_days", "INTEGER"),
        ("default_features", "TEXT"),
        ("default_domains", "TEXT")
    ]
    
    for col_name, col_type in columns:
        try:
            c.execute(f"ALTER TABLE customers ADD COLUMN {col_name} {col_type}")
        except sqlite3.OperationalError:
            pass # Already exists

    conn.commit()
    conn.close()

def get_connection():
    # Helper to resolve absolute path relative to this file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, DB_FILE)
    return sqlite3.connect(db_path)

def add_customer(name, email=None):
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO customers (name, email) VALUES (?, ?)", (name, email))
        conn.commit()
        cid = c.lastrowid
    except sqlite3.IntegrityError:
        # Already exists, get ID
        c.execute("SELECT id FROM customers WHERE name = ?", (name,))
        cid = c.fetchone()[0]
    finally:
        conn.close()
    return cid

def update_customer_defaults(name, max_targets, days, features, domains):
    conn = get_connection()
    c = conn.cursor()
    
    f_json = json.dumps(features) if features else None
    d_json = json.dumps(domains) if domains else None
    
    c.execute('''
        UPDATE customers 
        SET default_max_targets = ?, default_days = ?, default_features = ?, default_domains = ?
        WHERE name = ?
    ''', (max_targets, days, f_json, d_json, name))
    
    conn.commit()
    conn.close()

def get_customer_details(name):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT default_max_targets, default_days, default_features, default_domains FROM customers WHERE name = ?", (name,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return {
            "max_targets": row[0],
            "days": row[1],
            "features": json.loads(row[2]) if row[2] else [],
            "domains": json.loads(row[3]) if row[3] else []
        }
    return None

def get_customers():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, name FROM customers ORDER BY name")
    rows = c.fetchall()
    conn.close()
    return [r[1] for r in rows]

def add_license(customer_id, license_key, max_targets, expires_at, features=None, domains=None):
    conn = get_connection()
    c = conn.cursor()
    
    f_json = json.dumps(features) if features else None
    d_json = json.dumps(domains) if domains else None
    
    c.execute('''
        INSERT INTO licenses (customer_id, license_key, max_targets, expires_at, features, domains)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (customer_id, license_key, max_targets, expires_at, f_json, d_json))
    
    conn.commit()
    conn.close()

def get_all_licenses():
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT l.id, c.name, l.max_targets, l.expires_at, l.created_at, l.license_key
        FROM licenses l
        JOIN customers c ON l.customer_id = c.id
        ORDER BY l.created_at DESC
    ''')
    rows = c.fetchall()
    conn.close()
    
    # Process rows for easier display
    results = []
    for r in rows:
        results.append({
            "id": r[0],
            "customer": r[1],
            "max_targets": r[2],
            "expires_at": datetime.fromtimestamp(r[3]).strftime('%Y-%m-%d'),
            "created_at": r[4],
            "key": r[5]
        })
    return results
