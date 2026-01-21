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
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email import encoders
import subprocess
import re
import shutil

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
        self.root.geometry("850x900")

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

        self.tab_archive = ttk.Frame(tab_control)

        tab_control.add(self.tab_issue, text='Issue License')
        tab_control.add(self.tab_verify, text='Verify License')
        tab_control.add(self.tab_keys, text='Key Management')
        tab_control.add(self.tab_history, text='License History')
        tab_control.add(self.tab_archive, text='Archived Licenses')
        tab_control.pack(expand=1, fill="both", padx=10, pady=10)

        self.setup_issue_tab()
        self.setup_verify_tab()
        self.setup_keys_tab()
        self.setup_history_tab()
        self.setup_archive_tab()

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
                
                # Auto-populate display
                pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                b64 = base64.b64encode(pem).decode('utf-8')
                if hasattr(self, 'txt_pub_export'):
                    self.txt_pub_export.delete(1.0, tk.END)
                    self.txt_pub_export.insert(tk.END, b64)
                    
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
        
        ttk.Button(frame, text="Update YADS Config (../yads/config.py)", command=self.update_yads_config).pack(pady=5)

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
            pem = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            b64 = base64.b64encode(pem).decode('utf-8')
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

        # --- Contact Info Section ---
        contact_frame = ttk.LabelFrame(frame, text="Customer Contact Info")
        contact_frame.pack(fill="x", pady=10, padx=2)

        # Row 1: Email & Phone
        r1 = ttk.Frame(contact_frame)
        r1.pack(fill="x", padx=5, pady=2)
        ttk.Label(r1, text="Email:").pack(side="left")
        self.ent_email = ttk.Entry(r1)
        self.ent_email.pack(side="left", fill="x", expand=True, padx=5)
        
        ttk.Label(r1, text="Phone:").pack(side="left")
        self.ent_phone = ttk.Entry(r1)
        self.ent_phone.pack(side="left", fill="x", expand=True, padx=5)

        # Row 2: Company
        r2 = ttk.Frame(contact_frame)
        r2.pack(fill="x", padx=5, pady=2)
        ttk.Label(r2, text="Company:").pack(side="left")
        self.ent_company = ttk.Entry(r2)
        self.ent_company.pack(side="left", fill="x", expand=True, padx=5)

        # Row 3: Address
        r3 = ttk.Frame(contact_frame)
        r3.pack(fill="x", padx=5, pady=2)
        ttk.Label(r3, text="Address:").pack(side="left", anchor="n")
        self.txt_address = tk.Text(r3, height=2)
        self.txt_address.pack(side="left", fill="x", expand=True, padx=5)

        # Row 4: Infobox
        r4 = ttk.Frame(contact_frame)
        r4.pack(fill="x", padx=5, pady=2)
        ttk.Label(r4, text="Infobox:").pack(side="left", anchor="n")
        self.txt_infobox = tk.Text(r4, height=2)
        self.txt_infobox.pack(side="left", fill="x", expand=True, padx=5)
        # ----------------------------

        ttk.Label(frame, text="Features:").pack(anchor="w", pady=(10, 0))
        
        self.feature_vars = {}
        features_list = ["reports", "api", "scheduled_scans", "osint", "webhooks", "tenants", "analytics"]
        
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
        ttk.Label(frame, text="Signed License Key:").pack(anchor="w", pady=(10, 0))
        
        out_frame = ttk.Frame(frame)
        out_frame.pack(fill="both", expand=True, pady=5)
        
        self.txt_license_out = tk.Text(out_frame, height=12)
        self.txt_license_out.pack(side="left", fill="both", expand=True)
        
        ttk.Button(out_frame, text="Copy", command=self.copy_generated_key).pack(side="left", padx=5, anchor="n")

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

            # Contact Info
            self.ent_email.delete(0, tk.END)
            if details.get("email"): self.ent_email.insert(0, details["email"])

            self.ent_company.delete(0, tk.END)
            if details.get("company"): self.ent_company.insert(0, details["company"])

            self.ent_phone.delete(0, tk.END)
            if details.get("phone"): self.ent_phone.insert(0, details["phone"])

            self.txt_address.delete(1.0, tk.END)
            if details.get("address"): self.txt_address.insert(tk.END, details["address"])

            self.txt_infobox.delete(1.0, tk.END)
            if details.get("info_box"): self.txt_infobox.insert(tk.END, details["info_box"])

    def save_defaults(self):
        if self._save_customer_data():
            name = self.cmb_customer.get().strip()
            messagebox.showinfo("Success", f"Defaults saved for '{name}'.")

    def _save_customer_data(self):
        name = self.cmb_customer.get().strip()
        if not name:
            messagebox.showerror("Error", "No customer selected.")
            return False

        try:
            limit = int(self.ent_limit.get())
            days = int(self.ent_days.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid numbers for limit or days.")
            return False

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
        
        # Contact Info
        email = self.ent_email.get().strip()
        phone = self.ent_phone.get().strip()
        company = self.ent_company.get().strip()
        address = self.txt_address.get("1.0", tk.END).strip()
        info_box = self.txt_infobox.get("1.0", tk.END).strip()

        # Ensure customer exists
        db_manager.add_customer(name) # Idempotent add
        
        db_manager.update_customer_defaults(
            name, limit, days, f_list, d_list, 
            email, company, address, phone, info_box
        )
        return True

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
        
    def draft_email(self):
        key = self.txt_license_out.get("1.0", tk.END).strip()
        cust = self.cmb_customer.get().strip()
        # Use field email if available
        email = self.ent_email.get().strip()
        
        self._generate_email_draft(key, cust, email)

    def _generate_email_draft(self, key, cust, recipient_email=None):
        if not key or not cust: return

        # Paths
        base_dir = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(base_dir, "email_template.html")
        logo_path = os.path.join(base_dir, "logo.png")
        output_dir = os.path.join(base_dir, "generated_emails")
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # 1. Load HTML Content
        if os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as f:
                html_content = f.read()
        else:
            messagebox.showerror("Error", "email_template.html not found.")
            return

        # 2. Replace Placeholders
        html_content = html_content.replace("{customer_name}", cust)
        html_content = html_content.replace("{license_key}", key)
        
        # 3. Create MIME Message
        msg = MIMEMultipart('related')
        msg['Subject'] = f"Your YADS License Key - {cust}"
        msg['From'] = "support@yads-security.com"
        
        # Use email from argument if present
        msg['To'] = recipient_email if recipient_email else cust # Fallback if empty (bad but matches orig logic)
        
        msg.preamble = 'This is a multi-part message in MIME format.'

        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msg.attach(msgAlternative)
        
        # Plain text fallback
        msgText = MIMEText(f"Here is your license key:\n{key}\n\nPlease view this email in an HTML-compatible client.", 'plain')
        msgAlternative.attach(msgText)

        # HTML Part
        msgHtml = MIMEText(html_content, 'html')
        msgAlternative.attach(msgHtml)

        # 4. Embed Logo if exists
        if os.path.exists(logo_path):
            with open(logo_path, 'rb') as fp:
                # Explicitly name the image to help clients
                msgImage = MIMEImage(fp.read(), name="logo.png")
            
            # Define the image's ID as referenced above
            msgImage.add_header('Content-ID', '<logo>')
            msgImage.add_header('Content-Disposition', 'inline', filename='logo.png')
            msg.attach(msgImage)

        # 5. Save .eml File
        filename = f"License_{cust.replace(' ', '_')}_{int(time.time())}.eml"
        filepath = os.path.join(output_dir, filename)
        
        try:
            with open(filepath, 'w') as outfile:
                outfile.write(msg.as_string())
            
            # 6. Open File
            if sys.platform.startswith('linux'):
                subprocess.Popen(['xdg-open', filepath])
            else:
                webbrowser.open(filepath)
                
            # Feedback if UI exists (hacky check but safe)
            if hasattr(self, 'lbl_verify_status'):
                self.lbl_verify_status.config(text=f"Draft saved: {filename}", foreground="green")
            else:
                 messagebox.showinfo("Draft Saved", f"Email draft saved to:\n{filepath}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not create/open email draft: {e}\nSaved to: {filepath}")

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
            
            self.txt_license_out.delete(1.0, tk.END)
            self.txt_license_out.insert(tk.END, license_key)
            
            # --- Save to DB ---
            self._save_customer_data() # Ensure contact info & defaults are updated
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
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
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
        self.tree.bind("<Button-3>", self.show_context_menu) # Right click

        self.context_menu = tk.Menu(frame, tearoff=0)
        self.context_menu.add_command(label="Copy Key", command=self.copy_key_from_menu)
        self.context_menu.add_command(label="Resend License Mail", command=self.resend_email_from_history)
        self.context_menu.add_command(label="Archive License", command=self.archive_selected_license)
        
        self.refresh_history()

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def copy_key_from_menu(self):
        self.on_history_double_click(None)

    def resend_email_from_history(self):
        sel = self.tree.selection()
        if not sel: return
        item = sel[0]
        
        # Get Data
        vals = self.tree.item(item, "values")
        tags = self.tree.item(item, "tags")
        
        if not tags: return
        
        key = tags[0]
        customer_name = vals[1]
        
        # Check if email is available in tags [2nd element]
        email = None
        if len(tags) > 1:
            email = tags[1]
            if email == "None" or not email.strip(): email = None
            
        if not email:
            # Fallback: Ask user or warn?
            # User requirement: "use basically the customer email address"
            # If missing, maybe ask? Or just proceed with None (which fallsback to name as To)
            if not messagebox.askyesno("Missing Email", f"No email found for '{customer_name}'.\nDraft without specific recipient?"):
                return

        self._generate_email_draft(key, customer_name, email)

    def archive_selected_license(self):
        sel = self.tree.selection()
        if not sel: return
        item = sel[0]
        # Get ID
        vals = self.tree.item(item, "values")
        lid = vals[0]
        
        if messagebox.askyesno("Archive", f"Archive license for {vals[1]}?"):
            db_manager.toggle_archive_license(lid, archive=True)
            self.refresh_history()
            self.refresh_archive() # Update other tab if possible

    def refresh_history(self):
        # Clear
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        licenses = db_manager.get_all_licenses(archived=False)
        for lic in licenses:
            self.tree.insert("", "end", values=(
                lic["id"], 
                lic["customer"], 
                lic["max_targets"], 
                lic["expires_at"], 
                lic["created_at"]
            ), tags=(lic["key"], str(lic.get("email") or "")))

    def setup_archive_tab(self):
        frame = ttk.Frame(self.tab_archive)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ttk.Button(frame, text="Refresh List", command=self.refresh_archive).pack(anchor="e", pady=5)
        
        cols = ("ID", "Customer", "Limit", "Expires", "Created")
        self.tree_arch = ttk.Treeview(frame, columns=cols, show='headings', height=20)
        
        for col in cols:
            self.tree_arch.heading(col, text=col)
            self.tree_arch.column(col, width=100)
        
        self.tree_arch.column("ID", width=30)
        self.tree_arch.column("Customer", width=150)
            
        self.tree_arch.pack(fill="both", expand=True)
        
        # Context menu for restore
        self.arch_menu = tk.Menu(frame, tearoff=0)
        self.arch_menu.add_command(label="Restore License", command=self.restore_selected_license)
        self.tree_arch.bind("<Button-3>", self.show_arch_menu)

        self.refresh_archive()

    def show_arch_menu(self, event):
        item = self.tree_arch.identify_row(event.y)
        if item:
            self.tree_arch.selection_set(item)
            self.arch_menu.post(event.x_root, event.y_root)

    def restore_selected_license(self):
        sel = self.tree_arch.selection()
        if not sel: return
        item = sel[0]
        vals = self.tree_arch.item(item, "values")
        lid = vals[0]
        
        if messagebox.askyesno("Restore", f"Restore license for {vals[1]}?"):
            db_manager.toggle_archive_license(lid, archive=False)
            self.refresh_history()
            self.refresh_archive()

    def refresh_archive(self):
        # Clear
        for item in self.tree_arch.get_children():
            self.tree_arch.delete(item)
            
        licenses = db_manager.get_all_licenses(archived=True)
        for lic in licenses:
            self.tree_arch.insert("", "end", values=(
                lic["id"], 
                lic["customer"], 
                lic["max_targets"], 
                lic["expires_at"], 
                lic["created_at"]
            ), tags=(lic["key"],))

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



    def copy_generated_key(self):
        key = self.txt_license_out.get("1.0", tk.END).strip()
        if key:
            self.root.clipboard_clear()
            self.root.clipboard_append(key)
            self.root.update()
            messagebox.showinfo("Copied", "License key copied to clipboard.")
        else:
            messagebox.showwarning("Empty", "No key to copy.")

    def update_yads_config(self):
        # 1. Get current public key string
        pub_b64 = self.txt_pub_export.get("1.0", tk.END).strip()
        if not pub_b64:
            messagebox.showerror("Error", "No Public Key to update. Check keys first.")
            return

        # 2. Locate config.py
        # Assume standard structure: yads/license_manager/gui.py -> ../yads/config.py
        # Current file dir
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, "..", "yads", "config.py")
        config_path = os.path.abspath(config_path)

        if not os.path.exists(config_path):
             # Ask user
             config_path = filedialog.askopenfilename(
                 title="Select yads/config.py",
                 filetypes=[("Python Files", "*.py")]
             )
             if not config_path: return

        # 3. Read & Update
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Regex Replace
            # Pattern: LICENSE_PUBLIC_KEY: str = "..."
            pattern = r'LICENSE_PUBLIC_KEY:\s*str\s*=\s*".*?"'
            replacement = f'LICENSE_PUBLIC_KEY: str = "{pub_b64}"'
            
            new_content, count = re.subn(pattern, replacement, content)
            
            if count == 0:
                # Try simpler pattern just in case
                pattern = r'LICENSE_PUBLIC_KEY\s*=\s*".*?"'
                replacement = f'LICENSE_PUBLIC_KEY = "{pub_b64}"'
                new_content, count = re.subn(pattern, replacement, content)
            
            if count == 0:
                 messagebox.showerror("Error", "Could not find LICENSE_PUBLIC_KEY variable in config file.")
                 return

            # Backup
            shutil.copy(config_path, config_path + ".bak")

            with open(config_path, "w", encoding="utf-8") as f:
                f.write(new_content)
                
            messagebox.showinfo("Success", f"Updated {config_path}!\n\nPlease restart the YADS API to apply changes:\ndocker compose restart yads-api")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to update config: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = LicenseManagerApp(root)
    root.mainloop()
