#!/usr/bin/env python3
import sys
import os
import json
import base64
import time
import webbrowser
import urllib.parse
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# Import DB Manager
try:
    import db_manager
except ImportError:
    # Fallback if running from root without proper path/package struct
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    import db_manager

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    import subprocess
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
    except Exception:
        tk.messagebox.showerror("Error", "Cryptography library missing and could not be installed.\nPlease run: pip install cryptography")
        sys.exit(1)

class LicenseManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("YADS License Manager (DB Connected)")
        self.root.geometry("700x750")

        # Init DB
        db_manager.init_db()

        self.private_key = None
        self.public_key = None
        self.private_key_path = "license_private.pem"
        self.public_key_path = "license_public.pem"

        # Tab Setup
        tab_control = ttk.Notebook(root)
        self.tab_issue = ttk.Frame(tab_control)
        self.tab_verify = ttk.Frame(tab_control)
        self.tab_keys = ttk.Frame(tab_control)
        self.tab_history = ttk.Frame(tab_control)

        tab_control.add(self.tab_issue, text='Issue License')
        tab_control.add(self.tab_verify, text='Verify License')
        tab_control.add(self.tab_keys, text='Key Management')
        tab_control.add(self.tab_history, text='License History')
        tab_control.pack(expand=1, fill="both", padx=10, pady=10)

        self.setup_issue_tab()
        self.setup_verify_tab()
        self.setup_keys_tab()
        self.setup_history_tab()

        # Initial Load
        self.try_load_keys()
        self.load_customers()

    def try_load_keys(self):
        if os.path.exists(self.private_key_path):
            try:
                with open(self.private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None)
                # Check directly for label existence or update it later
                # Since setup_keys_tab is called before this, lbl_key_status exists
                if hasattr(self, 'lbl_key_status'):
                    self.lbl_key_status.config(text=f"Loaded: {self.private_key_path}", foreground="green")
            except Exception:
                if hasattr(self, 'lbl_key_status'):
                    self.lbl_key_status.config(text="Error loading private key", foreground="red")
        
        if os.path.exists(self.public_key_path):
            try:
                with open(self.public_key_path, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(f.read())
            except Exception:
                pass


    def load_customers(self):
        customers = db_manager.get_customers()
        self.cmb_customer['values'] = customers

    def setup_keys_tab(self):
        frame = ttk.LabelFrame(self.tab_keys, text="Key Setup")
        frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(frame, text="Generate New Key Pair", command=self.generate_keys).pack(pady=10)
        
        self.lbl_key_status = ttk.Label(frame, text="Checking for keys...", foreground="gray")
        self.lbl_key_status.pack(pady=5)

        ttk.Label(frame, text="Public Key (Base64 for YADS Config):").pack(anchor="w")
        self.txt_pub_export = tk.Text(frame, height=4, width=60)
        self.txt_pub_export.pack(pady=5)

    def generate_keys(self):
        if os.path.exists(self.private_key_path):
            if not messagebox.askyesno("Confirm", "Private key file exists. Overwrite?"):
                return

        try:
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()

            # Save
            with open(self.private_key_path, "wb") as f:
                f.write(priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(self.public_key_path, "wb") as f:
                f.write(pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            self.private_key = priv
            self.public_key = pub
            self.lbl_key_status.config(text="Keys Generated!", foreground="green")
            
            # Export Public Key String
            der = pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            b64 = base64.b64encode(der).decode('utf-8')
            self.txt_pub_export.delete(1.0, tk.END)
            self.txt_pub_export.insert(tk.END, b64)
            
            messagebox.showinfo("Success", "Keys generated and saved locally.")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def setup_issue_tab(self):
        frame = ttk.Frame(self.tab_issue)
        frame.pack(fill="both", padx=10, pady=10)

        # Inputs
        ttk.Label(frame, text="Customer Name / Subject:").pack(anchor="w")
        self.cmb_customer = ttk.Combobox(frame)
        self.cmb_customer.pack(fill="x", pady=2)
        self.cmb_customer.bind("<<ComboboxSelected>>", self.on_customer_selected)

        ttk.Label(frame, text="Max Targets:").pack(anchor="w", pady=(10, 0))
        self.ent_limit = ttk.Entry(frame)
        self.ent_limit.insert(0, "5")
        self.ent_limit.pack(fill="x", pady=2)

        ttk.Label(frame, text="Validity (Days):").pack(anchor="w", pady=(10, 0))
        self.ent_days = ttk.Entry(frame)
        self.ent_days.insert(0, "365")
        self.ent_days.pack(fill="x", pady=2)

        # Advanced
        ttk.Label(frame, text="Allowed Domains (comma sep):").pack(anchor="w", pady=(10, 0))
        self.ent_domains = ttk.Entry(frame)
        self.ent_domains.pack(fill="x", pady=2)

        ttk.Label(frame, text="Features:").pack(anchor="w", pady=(10, 0))
        
        self.feature_vars = {}
        features_list = ["reports", "api", "scheduled_scans", "osint", "webhooks"]
        
        f_frame = ttk.Frame(frame)
        f_frame.pack(fill="x", pady=2)
        
        for f in features_list:
            var = tk.BooleanVar()
            self.feature_vars[f] = var
            chk = ttk.Checkbutton(f_frame, text=f, variable=var)
            chk.pack(anchor="w")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Sign & Generate License", command=self.sign_license).pack(side="left", padx=5)
        self.btn_email = ttk.Button(btn_frame, text="Draft Email", command=self.draft_email, state="disabled")
        self.btn_email.pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Save Customer Defaults", command=self.save_defaults).pack(side="right", padx=5)

        # Output
        ttk.Label(frame, text="Signed License Key:").pack(anchor="w")
        self.txt_license_out = tk.Text(frame, height=6)
        self.txt_license_out.pack(fill="x")

    def on_customer_selected(self, event):
        name = self.cmb_customer.get().strip()
        if not name: return
        
        details = db_manager.get_customer_details(name)
        if details:
            # Update Fields
            if details["max_targets"]:
                self.ent_limit.delete(0, tk.END)
                self.ent_limit.insert(0, str(details["max_targets"]))
            if details["days"]:
                self.ent_days.delete(0, tk.END)
                self.ent_days.insert(0, str(details["days"]))
            
            # Domains
            self.ent_domains.delete(0, tk.END)
            if details["domains"]:
                self.ent_domains.insert(0, ",".join(details["domains"]))
                
            # Features
            # Reset all first
            for var in self.feature_vars.values(): var.set(False)
            
            if details["features"]:
                for f in details["features"]:
                    if f in self.feature_vars:
                        self.feature_vars[f].set(True)

    def save_defaults(self):
        name = self.cmb_customer.get().strip()
        if not name:
            messagebox.showerror("Error", "No customer selected.")
            return

        try:
            limit = int(self.ent_limit.get())
            days = int(self.ent_days.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid numbers for limit or days.")
            return

        # Domains
        d_list = None
        domains = self.ent_domains.get().strip()
        if domains:
            d_list = [d.strip() for d in domains.split(",") if d.strip()]

        # Features
        f_list = []
        for feature, var in self.feature_vars.items():
            if var.get():
                f_list.append(feature)
        
        # Determine ID (add if not exists logic is in db_manager update/add mix, 
        # but update_customer_defaults is strict Update. check add_customer first?)
        # Let's ensure customer exists first.
        db_manager.add_customer(name) # Idempotent add
        
        db_manager.update_customer_defaults(name, limit, days, f_list, d_list)
        messagebox.showinfo("Success", f"Defaults saved for '{name}'.")

    def draft_email(self):
        key = self.txt_license_out.get("1.0", tk.END).strip()
        cust = self.cmb_customer.get().strip()
        if not key or not cust: return
        
        # Load Template
        template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "email_template.txt")
        if os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            # Fallback
            content = "Subject: Your License - {customer_name}\n\nHere is your key:\n{license_key}"
            
        # Parse Subject
        lines = content.split('\n')
        subject = f"Your YADS License Key - {cust}" # Default
        body_start = 0
        
        if lines and lines[0].lower().startswith("subject:"):
            subject = lines[0].split(":", 1)[1].strip()
            # Replace placeholders in subject
            subject = subject.replace("{customer_name}", cust)
            body_start = 1
            
        # Reassemble Body
        body_template = "\n".join(lines[body_start:]).strip()
        
        # Replace Placeholders
        body = body_template.replace("{customer_name}", cust).replace("{license_key}", key)
        
        # Encode
        params = {
            "subject": subject,
            "body": body
        }
        qs = urllib.parse.urlencode(params).replace("+", "%20")
        mailto = f"mailto:?{qs}"
        
        try:
            webbrowser.open(mailto)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open mail client: {e}")

    def sign_license(self):
        if not self.private_key:
            messagebox.showerror("Error", "No private key loaded. Go to 'Key Management' tab.")
            return

        cust = self.cmb_customer.get().strip()
        if not cust:
            messagebox.showerror("Error", "Customer name required.")
            return

        try:
            limit = int(self.ent_limit.get())
            days = int(self.ent_days.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid numbers for limit or days.")
            return

        exp = int(time.time()) + (days * 86400)
        
        # Build Payload
        payload = {
            "sub": cust,
            "max_targets": limit,
            "exp": exp,
            "iat": int(time.time())
        }
        
        d_list = None
        domains = self.ent_domains.get().strip()
        if domains:
            d_list = [d.strip() for d in domains.split(",") if d.strip()]
            if d_list: payload["domains"] = d_list
            
        # Collect Features
        f_list = []
        for feature, var in self.feature_vars.items():
            if var.get():
                f_list.append(feature)
        
        if f_list: 
            payload["features"] = f_list

        # Encode & Sign
        try:
            payload_json = json.dumps(payload).encode('utf-8')
            payload_b64 = base64.urlsafe_b64encode(payload_json).decode('utf-8').rstrip('=')
            
            signature = self.private_key.sign(payload_b64.encode('utf-8'))
            sig_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
            
            license_key = f"{payload_b64}.{sig_b64}"
            
            self.txt_license_out.delete(1.0, tk.END)
            self.txt_license_out.insert(tk.END, license_key)
            
            # --- Save to DB ---
            cid = db_manager.add_customer(cust)
            db_manager.add_license(cid, license_key, limit, exp, features=f_list, domains=d_list)
            self.refresh_history()
            self.load_customers()
            self.btn_email.config(state="normal")
            messagebox.showinfo("Success", "License generated and saved to DB.")
            
        except Exception as e:
            messagebox.showerror("Signing Error", str(e))

    def setup_history_tab(self):
        frame = ttk.Frame(self.tab_history)
        frame.pack(fill="both", padx=10, pady=10)
        
        ttk.Button(frame, text="Refresh List", command=self.refresh_history).pack(anchor="e", pady=5)
        
        cols = ("ID", "Customer", "Limit", "Expires", "Created")
        self.tree = ttk.Treeview(frame, columns=cols, show='headings', height=20)
        
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        
        self.tree.column("ID", width=30)
        self.tree.column("Customer", width=150)
            
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self.on_history_double_click)
        
        self.refresh_history()

    def refresh_history(self):
        # Clear
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        licenses = db_manager.get_all_licenses()
        for lic in licenses:
            self.tree.insert("", "end", values=(
                lic["id"], 
                lic["customer"], 
                lic["max_targets"], 
                lic["expires_at"], 
                lic["created_at"]
            ), tags=(lic["key"],)) # Store full key in tag

    def on_history_double_click(self, event):
        item = self.tree.selection()[0]
        tags = self.tree.item(item, "tags")
        if tags:
            key = tags[0]
            # Copy to clipboard
            self.root.clipboard_clear()
            self.root.clipboard_append(key)
            self.root.update() # Keep clipboard after window closes?
            messagebox.showinfo("Copied", "License Key copied to clipboard!")


    def setup_verify_tab(self):
        frame = ttk.Frame(self.tab_verify)
        frame.pack(fill="both", padx=10, pady=10)

        ttk.Label(frame, text="Paste License Key:").pack(anchor="w")
        self.txt_verify_in = tk.Text(frame, height=6)
        self.txt_verify_in.pack(fill="x", pady=5)

        ttk.Button(frame, text="Verify & Decode", command=self.do_verify).pack(pady=10)

        ttk.Label(frame, text="Result:").pack(anchor="w")
        self.lbl_verify_status = ttk.Label(frame, text="", font=("Arial", 11, "bold"))
        self.lbl_verify_status.pack(pady=5)
        
        self.txt_verify_out = tk.Text(frame, height=10)
        self.txt_verify_out.pack(fill="both", expand=True)

    def do_verify(self):
        key = self.txt_verify_in.get("1.0", tk.END).strip()
        if not key: return

        if not self.public_key:
            if not messagebox.askyesno("Warning", "Public key not loaded. Cannot verify signature.\nDecode only?"):
                return
        
        try:
            parts = key.split('.')
            if len(parts) != 2:
                raise ValueError("Format incorrect (payload.signature)")

            payload_b64 = parts[0]
            sig_b64 = parts[1]

            # Re-pad
            payload_b64_pad = payload_b64 + '=' * (-len(payload_b64) % 4)
            sig_b64_pad = sig_b64 + '=' * (-len(sig_b64) % 4)

            payload_bytes = base64.urlsafe_b64decode(payload_b64_pad)
            
            status_text = "Signature: SKIPPED (No Key)"
            status_color = "orange"

            if self.public_key:
                try:
                    sig_bytes = base64.urlsafe_b64decode(sig_b64_pad)
                    self.public_key.verify(sig_bytes, payload_b64.encode('utf-8'))
                    status_text = "Signature: VALID"
                    status_color = "green"
                except Exception:
                    status_text = "Signature: INVALID"
                    status_color = "red"

            data = json.loads(payload_bytes)
            
            # Check Exp
            exp = data.get("exp", 0)
            if exp < time.time():
                status_text += " | EXPIRED"
                if status_color == "green": status_color = "red"
            else:
                status_text += f" | Expires: {datetime.fromtimestamp(exp)}"

            self.lbl_verify_status.config(text=status_text, foreground=status_color)
            self.txt_verify_out.delete(1.0, tk.END)
            self.txt_verify_out.insert(tk.END, json.dumps(data, indent=2))

        except Exception as e:
            self.lbl_verify_status.config(text="Error", foreground="red")
            self.txt_verify_out.delete(1.0, tk.END)
            self.txt_verify_out.insert(tk.END, str(e))



if __name__ == "__main__":
    root = tk.Tk()
    app = LicenseManagerApp(root)
    root.mainloop()
