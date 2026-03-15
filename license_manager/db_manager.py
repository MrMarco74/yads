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
            company TEXT,
            address TEXT,
            phone TEXT,
            info_box TEXT,
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
            is_archived INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers (id)
        )
    ''')
    
    # Migrations for new columns (idempotent)
    columns = [
        ("default_max_targets", "INTEGER"),
        ("default_days", "INTEGER"),
        ("default_features", "TEXT"),
        ("default_domains", "TEXT"),
        ("company", "TEXT"),
        ("address", "TEXT"),
        ("phone", "TEXT"),
        ("info_box", "TEXT")
    ]
    
    for col_name, col_type in columns:
        try:
            c.execute(f"ALTER TABLE customers ADD COLUMN {col_name} {col_type}")
        except sqlite3.OperationalError:
            pass # Already exists

    # Migration for licenses table
    try:
        c.execute("ALTER TABLE licenses ADD COLUMN is_archived INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    # Migrations for bug report signing (customer UUID + public key)
    for col_name, col_type in [
        ("customer_uuid", "TEXT"),
        ("report_signing_public_key", "TEXT"),
    ]:
        try:
            c.execute(f"ALTER TABLE customers ADD COLUMN {col_name} {col_type}")
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()

def get_connection():
    # Helper to resolve absolute path relative to this file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, DB_FILE)
    return sqlite3.connect(db_path)

def add_customer(name, email=None, company=None, address=None, phone=None, info_box=None):
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO customers (name, email, company, address, phone, info_box) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, email, company, address, phone, info_box))
        conn.commit()
        cid = c.lastrowid
    except sqlite3.IntegrityError:
        # Already exists, get ID
        c.execute("SELECT id FROM customers WHERE name = ?", (name,))
        cid = c.fetchone()[0]
        # Update existing info if provided? For now, we rely on save_defaults/update
    finally:
        conn.close()
    return cid

def update_customer_defaults(name, max_targets, days, features, domains, 
                             email=None, company=None, address=None, phone=None, info_box=None):
    conn = get_connection()
    c = conn.cursor()
    
    f_json = json.dumps(features) if features else None
    d_json = json.dumps(domains) if domains else None
    
    c.execute('''
        UPDATE customers 
        SET default_max_targets = ?, default_days = ?, default_features = ?, default_domains = ?,
            email = ?, company = ?, address = ?, phone = ?, info_box = ?
        WHERE name = ?
    ''', (max_targets, days, f_json, d_json, email, company, address, phone, info_box, name))
    
    conn.commit()
    conn.close()

def get_customer_details(name):
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        SELECT default_max_targets, default_days, default_features, default_domains,
               email, company, address, phone, info_box
        FROM customers WHERE name = ?
    ''', (name,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return {
            "max_targets": row[0],
            "days": row[1],
            "features": json.loads(row[2]) if row[2] else [],
            "domains": json.loads(row[3]) if row[3] else [],
            "email": row[4],
            "company": row[5],
            "address": row[6],
            "phone": row[7],
            "info_box": row[8]
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

def toggle_archive_license(license_id, archive=True):
    conn = get_connection()
    c = conn.cursor()
    val = 1 if archive else 0
    c.execute("UPDATE licenses SET is_archived = ? WHERE id = ?", (val, license_id))
    conn.commit()
    conn.close()

def get_all_licenses(archived=False):
    conn = get_connection()
    c = conn.cursor()
    
    query = '''
        SELECT l.id, c.name, l.max_targets, l.expires_at, l.created_at, l.license_key, c.email
        FROM licenses l
        JOIN customers c ON l.customer_id = c.id
        WHERE l.is_archived = ?
        ORDER BY l.created_at DESC
    '''
    
    # Handle legacy definition where None/Null might exist (though default is 0 now)
    # Actually, simpler is just WHERE is_archived = ? or (is_archived IS NULL and ?=0)
    # But for new schema default is 0.
    val = 1 if archived else 0
    c.execute(query, (val,))
    
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
            "key": r[5],
            "email": r[6]
        })
    return results


def save_report_signing_keys(customer_name: str, customer_uuid: str, public_key_b64: str):
    """Store/update the bug-report signing keypair metadata for a customer."""
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "UPDATE customers SET customer_uuid = ?, report_signing_public_key = ? WHERE name = ?",
        (customer_uuid, public_key_b64, customer_name),
    )
    conn.commit()
    conn.close()


def get_customer_by_name(name: str):
    """Return (customer_uuid, report_signing_public_key) for a customer, or (None, None)."""
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT customer_uuid, report_signing_public_key FROM customers WHERE name = ?",
        (name,),
    )
    row = c.fetchone()
    conn.close()
    if row:
        return row[0], row[1]
    return None, None


def delete_customer(name: str) -> str | None:
    """Delete customer and all their licenses. Returns customer_uuid (for portal EOS call) or None."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, customer_uuid FROM customers WHERE name = ?", (name,))
    row = c.fetchone()
    if not row:
        conn.close()
        return None
    cid, customer_uuid = row
    c.execute("DELETE FROM licenses WHERE customer_id = ?", (cid,))
    c.execute("DELETE FROM customers WHERE id = ?", (cid,))
    conn.commit()
    conn.close()
    return customer_uuid


def get_customers_with_report_keys():
    """Return all customers that have a report signing public key registered."""
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT name, customer_uuid, report_signing_public_key FROM customers "
        "WHERE customer_uuid IS NOT NULL AND report_signing_public_key IS NOT NULL "
        "ORDER BY name"
    )
    rows = c.fetchall()
    conn.close()
    return [{"name": r[0], "customer_uuid": r[1], "public_key_b64": r[2]} for r in rows]
