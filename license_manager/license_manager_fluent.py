#!/usr/bin/env python3
"""
YADS License Manager - Modern Fluent UI
Built with PySide6 + QFluentWidgets
"""
import sys
import os
import json
import base64
import time
import uuid
import webbrowser
import urllib.parse
import subprocess
import re
import shutil
import threading
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart

# Add script directory to path
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

from PySide6.QtCore import Qt, Signal, QObject, QThread, QTimer, QSize, QModelIndex, Slot
from PySide6.QtGui import QIcon, QFont, QColor, QClipboard
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QFrame, QFileDialog, QSizePolicy, QSpacerItem, QHeaderView,
    QTableWidgetItem, QAbstractItemView, QMenu
)

from qfluentwidgets import (
    FluentIcon as FIF,
    NavigationInterface, NavigationItemPosition, NavigationWidget,
    MessageBox, InfoBar, InfoBarPosition,
    CardWidget, HeaderCardWidget, PrimaryPushButton, PushButton,
    TransparentPushButton, ToolButton,
    LineEdit, PasswordLineEdit, ComboBox, EditableComboBox, CheckBox,
    TextEdit, BodyLabel, StrongBodyLabel, SubtitleLabel, TitleLabel,
    setTheme, Theme, setThemeColor, isDarkTheme,
    ScrollArea, SmoothScrollArea,
    TableWidget, SpinBox,
    FluentWindow, RoundMenu, Action,
    SwitchButton
)


def detect_system_dark_mode() -> bool:
    """Detect if system is using dark mode"""
    try:
        import darkdetect
        return darkdetect.isDark()
    except:
        pass

    # Fallback: check GTK settings on Linux
    try:
        import subprocess
        result = subprocess.run(
            ['gsettings', 'get', 'org.gnome.desktop.interface', 'color-scheme'],
            capture_output=True, text=True, timeout=2
        )
        if 'dark' in result.stdout.lower():
            return True
    except:
        pass

    # Fallback: check GTK theme name
    try:
        import subprocess
        result = subprocess.run(
            ['gsettings', 'get', 'org.gnome.desktop.interface', 'gtk-theme'],
            capture_output=True, text=True, timeout=2
        )
        if 'dark' in result.stdout.lower():
            return True
    except:
        pass

    return False


def get_code_stylesheet(dark: bool = None) -> str:
    """Get stylesheet for code/log views based on theme"""
    if dark is None:
        dark = isDarkTheme()

    if dark:
        return """
            TextEdit {
                background-color: #1e1e1e;
                color: #4ec9b0;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
                border-radius: 8px;
                padding: 12px;
            }
        """
    else:
        return """
            TextEdit {
                background-color: #f5f5f5;
                color: #107c10;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
                border-radius: 8px;
                padding: 12px;
                border: 1px solid #e0e0e0;
            }
        """


def get_result_stylesheet(dark: bool = None) -> str:
    """Get stylesheet for result/output views based on theme"""
    if dark is None:
        dark = isDarkTheme()

    if dark:
        return """
            TextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                border-radius: 8px;
                padding: 12px;
            }
        """
    else:
        return """
            TextEdit {
                background-color: #f5f5f5;
                color: #1e1e1e;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                border-radius: 8px;
                padding: 12px;
                border: 1px solid #e0e0e0;
            }
        """

# Import DB Manager
try:
    import db_manager
except ImportError:
    sys.path.append(str(script_dir))
    import db_manager

# Import cryptography
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Installing cryptography...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization


def _read_portal_settings() -> dict:
    """Read support portal connection settings from ~/.yads/license_manager_settings.json."""
    try:
        p = Path.home() / ".yads" / "license_manager_settings.json"
        data = json.loads(p.read_text())
        return {
            "url": data.get("support_portal_url", "").strip(),
            "token": data.get("support_admin_token", "").strip(),
            "key_path": data.get("support_admin_key_path", "").strip()
                        or str(Path.home() / ".yads" / "admin_signing_private.key"),
        }
    except Exception:
        return {"url": "", "token": "", "key_path": ""}


def _portal_push_customer(customer_name: str, is_eos: bool = False) -> str | None:
    """
    Sync one customer to the support portal in a background thread.
    Returns None on success, error string on failure.
    Silently skips if customer has no keys or portal settings are missing.
    """
    cfg = _read_portal_settings()
    if not cfg["url"] or not cfg["token"]:
        return None  # Not configured — skip silently

    customer_uuid, pub_key_b64 = db_manager.get_customer_by_name(customer_name)
    if not customer_uuid or not pub_key_b64:
        return None  # No keys yet — skip silently

    import urllib.request, urllib.error

    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
        raw = Path(cfg["key_path"]).expanduser().read_bytes().strip()
        priv = _ed.Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw))
    except Exception as e:
        return f"Admin signing key error: {e}"

    body = json.dumps({
        "customer_id": customer_uuid,
        "public_key_b64": pub_key_b64,
        "customer_name": customer_name,
        "is_eos": is_eos,
    }, sort_keys=True).encode()

    ts = str(time.time())
    sig = base64.b64encode(priv.sign(body)).decode()

    req = urllib.request.Request(
        f"{cfg['url'].rstrip('/')}/api/admin/keys",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cfg['token']}",
            "X-Timestamp": ts,
            "X-Signature": sig,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            resp.read()
        return None
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.read().decode()[:120]}"
    except Exception as e:
        return str(e)


def _portal_mark_eos(customer_uuid: str) -> str | None:
    """
    POST /api/admin/keys/{uuid}/eos to mark a customer as End-of-Support.
    Returns None on success, error string on failure.
    """
    cfg = _read_portal_settings()
    if not cfg["url"] or not cfg["token"]:
        return None

    import urllib.request, urllib.error

    req = urllib.request.Request(
        f"{cfg['url'].rstrip('/')}/api/admin/keys/{customer_uuid}/eos",
        data=b"",
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cfg['token']}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            resp.read()
        return None
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.read().decode()[:120]}"
    except Exception as e:
        return str(e)


class SettingsCard(CardWidget):
    """A card widget for settings sections"""

    def __init__(self, title: str, icon: FIF, parent=None):
        super().__init__(parent)
        self.setObjectName(title.replace(" ", ""))

        self.vBoxLayout = QVBoxLayout(self)
        self.vBoxLayout.setContentsMargins(20, 20, 20, 20)
        self.vBoxLayout.setSpacing(12)

        # Header
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        icon_widget = ToolButton(icon, self)
        icon_widget.setIconSize(QSize(20, 20))
        icon_widget.setEnabled(False)
        header_layout.addWidget(icon_widget)

        title_label = SubtitleLabel(title, self)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        self.vBoxLayout.addLayout(header_layout)

    def addRow(self, label_text: str, widget: QWidget, hint: str = None):
        """Add a labeled row to the card"""
        row_layout = QHBoxLayout()
        row_layout.setSpacing(12)

        label = BodyLabel(label_text, self)
        label.setFixedWidth(140)
        row_layout.addWidget(label)

        widget.setMinimumWidth(250)
        row_layout.addWidget(widget)

        if hint:
            hint_label = BodyLabel(hint, self)
            hint_label.setStyleSheet("color: gray;")
            row_layout.addWidget(hint_label)

        row_layout.addStretch()
        self.vBoxLayout.addLayout(row_layout)
        return widget


class IssueLicensePage(SmoothScrollArea):
    """Page for issuing new licenses"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("issuePage")
        self.setWidgetResizable(True)
        self.parent_window = parent

        self.private_key = None
        self.public_key = None
        self.private_key_path = script_dir / "license_private.pem"
        self.public_key_path = script_dir / "license_public.pem"

        self._setup_ui()
        self._load_keys()
        self._load_customers()

    def _setup_ui(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        # Title
        title = TitleLabel("Issue License", self)
        layout.addWidget(title)

        # Customer Card
        customer_card = SettingsCard("Customer Information", FIF.PEOPLE, self)

        self.cmb_customer = EditableComboBox(self)
        self.cmb_customer.setPlaceholderText("Select or enter customer name")
        self.cmb_customer.currentTextChanged.connect(self._on_customer_selected)
        customer_card.addRow("Customer:", self.cmb_customer)

        self.ent_email = LineEdit(self)
        self.ent_email.setPlaceholderText("customer@example.com")
        customer_card.addRow("Email:", self.ent_email)

        self.ent_company = LineEdit(self)
        self.ent_company.setPlaceholderText("Company name")
        customer_card.addRow("Company:", self.ent_company)

        self.ent_phone = LineEdit(self)
        self.ent_phone.setPlaceholderText("+1 234 567 890")
        customer_card.addRow("Phone:", self.ent_phone)

        self.txt_address = TextEdit(self)
        self.txt_address.setPlaceholderText("Street, City, Country")
        self.txt_address.setMaximumHeight(60)
        customer_card.addRow("Address:", self.txt_address)

        self.txt_infobox = TextEdit(self)
        self.txt_infobox.setPlaceholderText("Additional notes...")
        self.txt_infobox.setMaximumHeight(60)
        customer_card.addRow("Notes:", self.txt_infobox)

        layout.addWidget(customer_card)

        # License Settings Card
        license_card = SettingsCard("License Settings", FIF.CERTIFICATE, self)

        self.spn_targets = SpinBox(self)
        self.spn_targets.setRange(1, 10000)
        self.spn_targets.setValue(5)
        license_card.addRow("Max Targets:", self.spn_targets)

        self.spn_days = SpinBox(self)
        self.spn_days.setRange(1, 3650)
        self.spn_days.setValue(365)
        license_card.addRow("Validity (Days):", self.spn_days)

        self.ent_domains = LineEdit(self)
        self.ent_domains.setPlaceholderText("domain1.com, domain2.com")
        license_card.addRow("Allowed Domains:", self.ent_domains, "(comma separated)")

        layout.addWidget(license_card)

        # Features Card
        features_card = SettingsCard("Features", FIF.CHECKBOX, self)

        self.feature_vars = {}
        features_list = ["reports", "api", "scheduled_scans", "osint", "webhooks", "tenants", "analytics", "support_messaging"]

        features_grid = QHBoxLayout()
        features_grid.setSpacing(20)

        for f in features_list:
            chk = CheckBox(f.replace("_", " ").title(), self)
            self.feature_vars[f] = chk
            features_grid.addWidget(chk)

        features_grid.addStretch()
        features_card.vBoxLayout.addLayout(features_grid)

        layout.addWidget(features_card)

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        self.btn_sign = PrimaryPushButton(FIF.CERTIFICATE, "Sign && Generate License", self)
        self.btn_sign.setFixedWidth(220)
        self.btn_sign.clicked.connect(self._sign_license)
        btn_layout.addWidget(self.btn_sign)

        self.btn_email = PushButton(FIF.MAIL, "Draft Email", self)
        self.btn_email.setEnabled(False)
        self.btn_email.clicked.connect(self._draft_email)
        btn_layout.addWidget(self.btn_email)

        self.btn_save = PushButton(FIF.SAVE, "Save Customer", self)
        self.btn_save.clicked.connect(self._save_defaults)
        btn_layout.addWidget(self.btn_save)

        btn_layout.addStretch()

        self.btn_delete = PushButton(FIF.DELETE, "Delete Customer", self)
        self.btn_delete.clicked.connect(self._delete_customer)
        self.btn_delete.setStyleSheet("color: #ef4444;")
        btn_layout.addWidget(self.btn_delete)

        layout.addLayout(btn_layout)

        # Output Card
        output_card = SettingsCard("Generated License Key", FIF.CODE, self)

        self.txt_license_out = TextEdit(self)
        self.txt_license_out.setReadOnly(True)
        self.txt_license_out.setMinimumHeight(120)
        self.txt_license_out.setStyleSheet(get_code_stylesheet())
        output_card.vBoxLayout.addWidget(self.txt_license_out)

        copy_btn = TransparentPushButton(FIF.COPY, "Copy to Clipboard", self)
        copy_btn.clicked.connect(self._copy_license)
        output_card.vBoxLayout.addWidget(copy_btn, alignment=Qt.AlignmentFlag.AlignRight)

        layout.addWidget(output_card)
        layout.addStretch()

        self.setWidget(container)

    def _load_keys(self):
        """Load existing keys from files"""
        if self.private_key_path.exists():
            try:
                with open(self.private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            except Exception as e:
                print(f"Error loading private key: {e}")

        if self.public_key_path.exists():
            try:
                with open(self.public_key_path, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(f.read())
            except Exception as e:
                print(f"Error loading public key: {e}")

    def _load_customers(self):
        """Load customer list from database"""
        customers = db_manager.get_customers()
        self.cmb_customer.clear()
        for c in customers:
            self.cmb_customer.addItem(c)

    def _on_customer_selected(self, name: str):
        """Load customer details when selected"""
        if not name:
            return

        details = db_manager.get_customer_details(name)
        if details:
            if details["max_targets"]:
                self.spn_targets.setValue(details["max_targets"])
            if details["days"]:
                self.spn_days.setValue(details["days"])

            self.ent_domains.clear()
            if details["domains"]:
                self.ent_domains.setText(",".join(details["domains"]))

            # Reset features
            for chk in self.feature_vars.values():
                chk.setChecked(False)

            if details["features"]:
                for f in details["features"]:
                    if f in self.feature_vars:
                        self.feature_vars[f].setChecked(True)

            # Contact info
            self.ent_email.setText(details.get("email") or "")
            self.ent_company.setText(details.get("company") or "")
            self.ent_phone.setText(details.get("phone") or "")
            self.txt_address.setPlainText(details.get("address") or "")
            self.txt_infobox.setPlainText(details.get("info_box") or "")

    def _save_defaults(self):
        """Save customer defaults and auto-sync to portal if keys exist."""
        if self._save_customer_data():
            name = self.cmb_customer.currentText().strip()
            InfoBar.success(
                "Saved",
                f"Defaults saved for '{name}'",
                parent=self,
                position=InfoBarPosition.TOP,
                duration=3000
            )
            self._load_customers()
            # Auto-sync to support portal in background (silent — only logs on error)
            def _bg_sync():
                err = _portal_push_customer(name)
                if err:
                    QTimer.singleShot(0, lambda: InfoBar.warning(
                        "Portal Sync",
                        f"Auto-sync to portal failed: {err}",
                        parent=self,
                        position=InfoBarPosition.TOP,
                        duration=5000,
                    ))
            threading.Thread(target=_bg_sync, daemon=True).start()

    def _delete_customer(self):
        """Delete customer from local DB and mark EOS on the support portal."""
        name = self.cmb_customer.currentText().strip()
        if not name:
            return

        dialog = MessageBox(
            "Kunden löschen",
            f"Wirklich '{name}' löschen?\n\n"
            "• Alle Lizenzen werden gelöscht\n"
            "• Auf dem Support-Portal wird der Kunde als EOS (End of Support) markiert\n"
            "• Bestehende Bug Reports bleiben erhalten",
            self,
        )
        if not dialog.exec():
            return

        # Get UUID before deletion
        customer_uuid, _ = db_manager.get_customer_by_name(name)

        # Delete from local DB
        db_manager.delete_customer(name)
        self._load_customers()
        InfoBar.success("Gelöscht", f"Kunde '{name}' wurde gelöscht.", parent=self,
                        position=InfoBarPosition.TOP, duration=3000)

        # Mark EOS on portal in background
        if customer_uuid:
            def _bg_eos():
                err = _portal_mark_eos(customer_uuid)
                if err:
                    QTimer.singleShot(0, lambda: InfoBar.warning(
                        "Portal EOS",
                        f"EOS-Markierung fehlgeschlagen: {err}",
                        parent=self,
                        position=InfoBarPosition.TOP,
                        duration=5000,
                    ))
                else:
                    QTimer.singleShot(0, lambda: InfoBar.success(
                        "Portal EOS",
                        f"'{name}' auf Support-Portal als EOS markiert.",
                        parent=self,
                        position=InfoBarPosition.TOP,
                        duration=4000,
                    ))
            threading.Thread(target=_bg_eos, daemon=True).start()

    def _save_customer_data(self) -> bool:
        """Save customer data to database"""
        name = self.cmb_customer.currentText().strip()
        if not name:
            InfoBar.error("Error", "Customer name required", parent=self, position=InfoBarPosition.TOP)
            return False

        limit = self.spn_targets.value()
        days = self.spn_days.value()

        # Domains
        domains = self.ent_domains.text().strip()
        d_list = [d.strip() for d in domains.split(",") if d.strip()] if domains else None

        # Features
        f_list = [f for f, chk in self.feature_vars.items() if chk.isChecked()]

        # Contact info
        email = self.ent_email.text().strip()
        phone = self.ent_phone.text().strip()
        company = self.ent_company.text().strip()
        address = self.txt_address.toPlainText().strip()
        info_box = self.txt_infobox.toPlainText().strip()

        db_manager.add_customer(name)
        db_manager.update_customer_defaults(
            name, limit, days, f_list, d_list,
            email, company, address, phone, info_box
        )
        return True

    def _sign_license(self):
        """Generate and sign a license"""
        if not self.private_key:
            InfoBar.error(
                "No Key",
                "No private key loaded. Go to Key Management tab.",
                parent=self,
                position=InfoBarPosition.TOP
            )
            return

        cust = self.cmb_customer.currentText().strip()
        if not cust:
            InfoBar.error("Error", "Customer name required", parent=self, position=InfoBarPosition.TOP)
            return

        limit = self.spn_targets.value()
        days = self.spn_days.value()
        exp = int(time.time()) + (days * 86400)

        # Build payload
        payload = {
            "sub": cust,
            "max_targets": limit,
            "exp": exp,
            "iat": int(time.time())
        }

        # Domains
        domains = self.ent_domains.text().strip()
        if domains:
            d_list = [d.strip() for d in domains.split(",") if d.strip()]
            if d_list:
                payload["domains"] = d_list
        else:
            d_list = None

        # Features
        f_list = [f for f, chk in self.feature_vars.items() if chk.isChecked()]
        if f_list:
            payload["features"] = f_list

        # Bug-report signing: generate customer UUID + Ed25519 keypair
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
            from cryptography.hazmat.primitives import serialization as _ser
            _report_priv = _ed25519.Ed25519PrivateKey.generate()
            _report_pub = _report_priv.public_key()
            _report_priv_raw = _report_priv.private_bytes(
                _ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption()
            )
            _report_pub_raw = _report_pub.public_bytes(
                _ser.Encoding.Raw, _ser.PublicFormat.Raw
            )
            _report_priv_b64 = base64.b64encode(_report_priv_raw).decode()
            _report_pub_b64 = base64.b64encode(_report_pub_raw).decode()
        except Exception as _e:
            InfoBar.error("Crypto Error", str(_e), parent=self, position=InfoBarPosition.TOP)
            return

        # Reuse existing customer UUID or generate new one
        _existing = db_manager.get_customer_details(cust) or {}
        _cust_uuid = str(uuid.uuid4())  # always fresh per-license generation

        payload["customer_id"] = _cust_uuid
        payload["report_signing_key"] = _report_priv_b64

        try:
            # Encode & sign
            payload_json = json.dumps(payload, sort_keys=True).encode('utf-8')
            payload_b64 = base64.urlsafe_b64encode(payload_json).decode('utf-8').rstrip('=')

            signature = self.private_key.sign(payload_b64.encode('utf-8'))
            sig_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

            license_key = f"{payload_b64}.{sig_b64}"

            self.txt_license_out.setPlainText(license_key)

            # Save to DB
            self._save_customer_data()
            cid = db_manager.add_customer(cust)
            db_manager.add_license(cid, license_key, limit, exp, features=f_list, domains=d_list)

            # Store report signing keys for this customer
            db_manager.save_report_signing_keys(cust, _cust_uuid, _report_pub_b64)

            # Auto-sync new/updated key to support portal
            def _bg_sync_new(name=cust):
                err = _portal_push_customer(name)
                if err:
                    QTimer.singleShot(0, lambda: InfoBar.warning(
                        "Portal Sync",
                        f"Auto-sync to portal failed: {err}",
                        parent=self,
                        position=InfoBarPosition.TOP,
                        duration=5000,
                    ))
            threading.Thread(target=_bg_sync_new, daemon=True).start()

            # Refresh history if available
            if hasattr(self.parent_window, 'history_page'):
                self.parent_window.history_page.refresh_table()

            self._load_customers()
            self.btn_email.setEnabled(True)

            InfoBar.success(
                "Success",
                "License generated and saved!",
                parent=self,
                position=InfoBarPosition.TOP,
                duration=4000
            )

        except Exception as e:
            InfoBar.error("Error", str(e), parent=self, position=InfoBarPosition.TOP)

    def _copy_license(self):
        """Copy license to clipboard"""
        key = self.txt_license_out.toPlainText().strip()
        if key:
            QApplication.clipboard().setText(key)
            InfoBar.success("Copied", "License key copied to clipboard", parent=self, position=InfoBarPosition.TOP, duration=2000)

    def _draft_email(self):
        """Generate email draft"""
        key = self.txt_license_out.toPlainText().strip()
        cust = self.cmb_customer.currentText().strip()
        email = self.ent_email.text().strip()

        if not key or not cust:
            return

        base_dir = script_dir
        template_path = base_dir / "email_template.html"
        logo_path = base_dir / "logo.png"
        output_dir = base_dir / "generated_emails"
        output_dir.mkdir(exist_ok=True)

        if not template_path.exists():
            InfoBar.error("Error", "email_template.html not found", parent=self, position=InfoBarPosition.TOP)
            return

        # Load and process template
        with open(template_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        html_content = html_content.replace("{customer_name}", cust)
        html_content = html_content.replace("{license_key}", key)

        # Create MIME message
        msg = MIMEMultipart('related')
        msg['Subject'] = f"Your YADS License Key - {cust}"
        msg['From'] = "support@yads-security.com"
        msg['To'] = email if email else cust

        msg.preamble = 'This is a multi-part message in MIME format.'

        msgAlternative = MIMEMultipart('alternative')
        msg.attach(msgAlternative)

        msgText = MIMEText(f"Here is your license key:\n{key}\n\nPlease view this email in an HTML-compatible client.", 'plain')
        msgAlternative.attach(msgText)

        msgHtml = MIMEText(html_content, 'html')
        msgAlternative.attach(msgHtml)

        # Embed logo
        if logo_path.exists():
            with open(logo_path, 'rb') as fp:
                msgImage = MIMEImage(fp.read(), name="logo.png")
            msgImage.add_header('Content-ID', '<logo>')
            msgImage.add_header('Content-Disposition', 'inline', filename='logo.png')
            msg.attach(msgImage)

        # Save .eml file
        filename = f"License_{cust.replace(' ', '_')}_{int(time.time())}.eml"
        filepath = output_dir / filename

        try:
            with open(filepath, 'w') as outfile:
                outfile.write(msg.as_string())

            if sys.platform.startswith('linux'):
                subprocess.Popen(['xdg-open', str(filepath)])
            else:
                webbrowser.open(str(filepath))

            InfoBar.success("Draft Created", f"Email saved: {filename}", parent=self, position=InfoBarPosition.TOP, duration=4000)

        except Exception as e:
            InfoBar.error("Error", f"Could not create email: {e}", parent=self, position=InfoBarPosition.TOP)


class VerifyLicensePage(QWidget):
    """Page for verifying licenses"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("verifyPage")
        self.parent_window = parent

        self.public_key = None
        self._load_public_key()
        self._setup_ui()

    def _load_public_key(self):
        public_key_path = script_dir / "license_public.pem"
        if public_key_path.exists():
            try:
                with open(public_key_path, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(f.read())
            except Exception:
                pass

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        title = TitleLabel("Verify License", self)
        layout.addWidget(title)

        # Input Card
        input_card = SettingsCard("License Key", FIF.PASTE, self)

        self.txt_input = TextEdit(self)
        self.txt_input.setPlaceholderText("Paste license key here...")
        self.txt_input.setMinimumHeight(100)
        input_card.vBoxLayout.addWidget(self.txt_input)

        btn_verify = PrimaryPushButton(FIF.SEARCH, "Verify && Decode", self)
        btn_verify.clicked.connect(self._verify)
        input_card.vBoxLayout.addWidget(btn_verify, alignment=Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(input_card)

        # Result Card
        result_card = SettingsCard("Verification Result", FIF.ACCEPT, self)

        self.lbl_status = SubtitleLabel("", self)
        result_card.vBoxLayout.addWidget(self.lbl_status)

        self.txt_result = TextEdit(self)
        self.txt_result.setReadOnly(True)
        self.txt_result.setMinimumHeight(200)
        self.txt_result.setStyleSheet(get_result_stylesheet())
        result_card.vBoxLayout.addWidget(self.txt_result)

        layout.addWidget(result_card)
        layout.addStretch()

    def _verify(self):
        """Verify and decode a license key"""
        key = self.txt_input.toPlainText().strip()
        if not key:
            return

        if not self.public_key:
            box = MessageBox(
                "Warning",
                "Public key not loaded. Cannot verify signature.\nDecode only?",
                self
            )
            if not box.exec():
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
            status_color = "#dcdcaa"  # Yellow

            if self.public_key:
                try:
                    sig_bytes = base64.urlsafe_b64decode(sig_b64_pad)
                    self.public_key.verify(sig_bytes, payload_b64.encode('utf-8'))
                    status_text = "Signature: VALID"
                    status_color = "#4ec9b0"  # Green
                except Exception:
                    status_text = "Signature: INVALID"
                    status_color = "#f14c4c"  # Red

            data = json.loads(payload_bytes)

            # Check expiration
            exp = data.get("exp", 0)
            if exp < time.time():
                status_text += " | EXPIRED"
                status_color = "#f14c4c"
            else:
                status_text += f" | Expires: {datetime.fromtimestamp(exp).strftime('%Y-%m-%d %H:%M')}"

            self.lbl_status.setText(status_text)
            self.lbl_status.setStyleSheet(f"color: {status_color};")
            self.txt_result.setPlainText(json.dumps(data, indent=2))

        except Exception as e:
            self.lbl_status.setText("Error")
            self.lbl_status.setStyleSheet("color: #f14c4c;")
            self.txt_result.setPlainText(str(e))


class KeyManagementPage(QWidget):
    """Page for managing cryptographic keys"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("keysPage")
        self.parent_window = parent

        self.private_key = None
        self.public_key = None
        self.private_key_path = script_dir / "license_private.pem"
        self.public_key_path = script_dir / "license_public.pem"

        self._setup_ui()
        self._load_keys()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        title = TitleLabel("Key Management", self)
        layout.addWidget(title)

        # Key Status Card
        status_card = SettingsCard("Key Status", FIF.VPN, self)

        self.lbl_status = BodyLabel("Checking for keys...", self)
        status_card.vBoxLayout.addWidget(self.lbl_status)

        btn_generate = PrimaryPushButton(FIF.ADD, "Generate New Key Pair", self)
        btn_generate.clicked.connect(self._generate_keys)
        status_card.vBoxLayout.addWidget(btn_generate, alignment=Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(status_card)

        # Public Key Export Card
        export_card = SettingsCard("Public Key (Base64)", FIF.SHARE, self)

        self.txt_pub_export = TextEdit(self)
        self.txt_pub_export.setReadOnly(True)
        self.txt_pub_export.setMinimumHeight(80)
        self.txt_pub_export.setStyleSheet(get_code_stylesheet())
        export_card.vBoxLayout.addWidget(self.txt_pub_export)

        btn_update = PushButton(FIF.SYNC, "Update YADS Config", self)
        btn_update.clicked.connect(self._update_yads_config)
        export_card.vBoxLayout.addWidget(btn_update, alignment=Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(export_card)

        # ---- Activation Key Pair ----
        act_title = SubtitleLabel("Activation Keys", self)
        act_title.setContentsMargins(0, 8, 0, 0)
        layout.addWidget(act_title)
        act_sub = BodyLabel(
            "Separates Schlüsselpaar für sign_activation.py. "
            "Der Private Key signiert Aktivierungscodes, der Public Key wird in YADS als ACTIVATION_PUBLIC_KEY eingetragen.",
            self,
        )
        act_sub.setWordWrap(True)
        layout.addWidget(act_sub)

        act_status_card = SettingsCard("Activation Key Status", FIF.CERTIFICATE, self)
        self.lbl_act_status = BodyLabel("Checking for activation keys...", self)
        act_status_card.vBoxLayout.addWidget(self.lbl_act_status)
        btn_gen_act = PrimaryPushButton(FIF.ADD, "Generate Activation Key Pair", self)
        btn_gen_act.clicked.connect(self._generate_activation_keys)
        act_status_card.vBoxLayout.addWidget(btn_gen_act, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(act_status_card)

        act_export_card = SettingsCard("Activation Public Key (ACTIVATION_PUBLIC_KEY)", FIF.SHARE, self)
        self.txt_act_pub_export = TextEdit(self)
        self.txt_act_pub_export.setReadOnly(True)
        self.txt_act_pub_export.setMinimumHeight(80)
        self.txt_act_pub_export.setStyleSheet(get_code_stylesheet())
        act_export_card.vBoxLayout.addWidget(self.txt_act_pub_export)
        btn_act_update = PushButton(FIF.SYNC, "Update YADS Config (ACTIVATION_PUBLIC_KEY)", self)
        btn_act_update.clicked.connect(self._update_yads_config_activation)
        act_export_card.vBoxLayout.addWidget(btn_act_update, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(act_export_card)

        layout.addStretch()

    def _load_keys(self):
        """Load existing license keys"""
        if self.private_key_path.exists():
            try:
                with open(self.private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None)
                self.lbl_status.setText(f"Loaded: {self.private_key_path.name}")
                self.lbl_status.setStyleSheet("color: #4ec9b0;")
            except Exception:
                self.lbl_status.setText("Error loading private key")
                self.lbl_status.setStyleSheet("color: #f14c4c;")

        if self.public_key_path.exists():
            try:
                with open(self.public_key_path, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(f.read())
                pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                self.txt_pub_export.setPlainText(base64.b64encode(pem).decode('utf-8'))
            except Exception:
                pass

        # Load activation keys
        act_priv_path = script_dir / "activation_private.pem"
        act_pub_path = script_dir / "activation_public.pem"
        if act_priv_path.exists():
            self.lbl_act_status.setText(f"Loaded: {act_priv_path.name}")
            self.lbl_act_status.setStyleSheet("color: #4ec9b0;")
        else:
            self.lbl_act_status.setText("No activation key found — generate one below.")
            self.lbl_act_status.setStyleSheet("color: #f59e0b;")
        if act_pub_path.exists():
            try:
                with open(act_pub_path, "rb") as f:
                    act_pub = serialization.load_pem_public_key(f.read())
                pem = act_pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                self.txt_act_pub_export.setPlainText(base64.b64encode(pem).decode('utf-8'))
            except Exception:
                pass

    def _generate_keys(self):
        """Generate new key pair"""
        if self.private_key_path.exists():
            box = MessageBox("Confirm", "Private key exists. Overwrite?", self)
            if not box.exec():
                return

        try:
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()

            # Save private key
            with open(self.private_key_path, "wb") as f:
                f.write(priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Save public key
            with open(self.public_key_path, "wb") as f:
                f.write(pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            self.private_key = priv
            self.public_key = pub

            self.lbl_status.setText("Keys Generated!")
            self.lbl_status.setStyleSheet("color: #4ec9b0;")

            # Update export display
            pem = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            b64 = base64.b64encode(pem).decode('utf-8')
            self.txt_pub_export.setPlainText(b64)

            # Update issue page keys
            if hasattr(self.parent_window, 'issue_page'):
                self.parent_window.issue_page.private_key = priv
                self.parent_window.issue_page.public_key = pub

            InfoBar.success("Success", "Keys generated and saved!", parent=self, position=InfoBarPosition.TOP)

        except Exception as e:
            InfoBar.error("Error", str(e), parent=self, position=InfoBarPosition.TOP)

    def _update_yads_config(self):
        """Update YADS config with public key"""
        pub_b64 = self.txt_pub_export.toPlainText().strip()
        if not pub_b64:
            InfoBar.error("Error", "No public key to update", parent=self, position=InfoBarPosition.TOP)
            return

        config_path = script_dir.parent / "yads" / "config.py"

        if not config_path.exists():
            config_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select yads/config.py",
                str(script_dir.parent),
                "Python Files (*.py)"
            )
            if not config_path:
                return
            config_path = Path(config_path)

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()

            pattern = r'LICENSE_PUBLIC_KEY:\s*str\s*=\s*".*?"'
            replacement = f'LICENSE_PUBLIC_KEY: str = "{pub_b64}"'

            new_content, count = re.subn(pattern, replacement, content)

            if count == 0:
                pattern = r'LICENSE_PUBLIC_KEY\s*=\s*".*?"'
                replacement = f'LICENSE_PUBLIC_KEY = "{pub_b64}"'
                new_content, count = re.subn(pattern, replacement, content)

            if count == 0:
                InfoBar.error("Error", "Could not find LICENSE_PUBLIC_KEY in config", parent=self, position=InfoBarPosition.TOP)
                return

            # Backup
            shutil.copy(config_path, str(config_path) + ".bak")

            with open(config_path, "w", encoding="utf-8") as f:
                f.write(new_content)

            InfoBar.success(
                "Updated",
                "Config updated! Restart YADS API to apply.",
                parent=self,
                position=InfoBarPosition.TOP,
                duration=5000
            )

        except Exception as e:
            InfoBar.error("Error", str(e), parent=self, position=InfoBarPosition.TOP)

    def _generate_activation_keys(self):
        """Generate new Ed25519 keypair for activation code signing."""
        act_priv_path = script_dir / "activation_private.pem"
        if act_priv_path.exists():
            box = MessageBox("Confirm", "Activation private key exists. Overwrite?", self)
            if not box.exec():
                return

        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization as _ser

            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()

            act_pub_path = script_dir / "activation_public.pem"

            with open(act_priv_path, "wb") as f:
                f.write(priv.private_bytes(
                    encoding=_ser.Encoding.PEM,
                    format=_ser.PrivateFormat.PKCS8,
                    encryption_algorithm=_ser.NoEncryption()
                ))

            with open(act_pub_path, "wb") as f:
                f.write(pub.public_bytes(
                    encoding=_ser.Encoding.PEM,
                    format=_ser.PublicFormat.SubjectPublicKeyInfo
                ))

            self.lbl_act_status.setText(f"Loaded: {act_priv_path.name}")
            self.lbl_act_status.setStyleSheet("color: #4ec9b0;")

            pem = pub.public_bytes(
                encoding=_ser.Encoding.PEM,
                format=_ser.PublicFormat.SubjectPublicKeyInfo
            )
            self.txt_act_pub_export.setPlainText(base64.b64encode(pem).decode('utf-8'))

            InfoBar.success("Success", "Activation keys generated and saved!", parent=self, position=InfoBarPosition.TOP)

        except Exception as e:
            InfoBar.error("Error", str(e), parent=self, position=InfoBarPosition.TOP)

    def _update_yads_config_activation(self):
        """Write ACTIVATION_PUBLIC_KEY into yads/config.py."""
        pub_b64 = self.txt_act_pub_export.toPlainText().strip()
        if not pub_b64:
            InfoBar.error("Error", "No activation public key to update", parent=self, position=InfoBarPosition.TOP)
            return

        config_path = script_dir.parent / "yads" / "config.py"

        if not config_path.exists():
            config_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select yads/config.py",
                str(script_dir.parent),
                "Python Files (*.py)"
            )
            if not config_path:
                return
            config_path = Path(config_path)

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Try typed annotation form first
            pattern = r'ACTIVATION_PUBLIC_KEY:\s*Optional\[str\]\s*=\s*(?:None|".*?")'
            replacement = f'ACTIVATION_PUBLIC_KEY: Optional[str] = "{pub_b64}"'
            new_content, count = re.subn(pattern, replacement, content)

            if count == 0:
                pattern = r'ACTIVATION_PUBLIC_KEY\s*=\s*(?:None|".*?")'
                replacement = f'ACTIVATION_PUBLIC_KEY = "{pub_b64}"'
                new_content, count = re.subn(pattern, replacement, content)

            if count == 0:
                InfoBar.error("Error", "Could not find ACTIVATION_PUBLIC_KEY in config.py", parent=self, position=InfoBarPosition.TOP)
                return

            shutil.copy(config_path, str(config_path) + ".bak")

            with open(config_path, "w", encoding="utf-8") as f:
                f.write(new_content)

            InfoBar.success(
                "Updated",
                "ACTIVATION_PUBLIC_KEY written to config.py. Restart YADS API to apply.",
                parent=self,
                position=InfoBarPosition.TOP,
                duration=5000
            )

        except Exception as e:
            InfoBar.error("Error", str(e), parent=self, position=InfoBarPosition.TOP)


class HistoryPage(QWidget):
    """Page for license history"""

    def __init__(self, parent=None, archived=False):
        super().__init__(parent)
        self.archived = archived
        self.setObjectName("archivePage" if archived else "historyPage")
        self.parent_window = parent

        self._setup_ui()
        self.refresh_table()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        title_text = "Archived Licenses" if self.archived else "License History"
        title = TitleLabel(title_text, self)
        layout.addWidget(title)

        # Toolbar
        toolbar = QHBoxLayout()
        refresh_btn = PushButton(FIF.SYNC, "Refresh", self)
        refresh_btn.clicked.connect(self.refresh_table)
        toolbar.addWidget(refresh_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Table
        self.table = TableWidget(self)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "Customer", "Max Targets", "Expires", "Created"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 50)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.doubleClicked.connect(self._on_double_click)

        layout.addWidget(self.table)

        # Store license data
        self.license_data = []

    def refresh_table(self):
        """Refresh the table data"""
        self.table.setRowCount(0)
        self.license_data = db_manager.get_all_licenses(archived=self.archived)

        for lic in self.license_data:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(lic["id"])))
            self.table.setItem(row, 1, QTableWidgetItem(lic["customer"]))
            self.table.setItem(row, 2, QTableWidgetItem(str(lic["max_targets"])))
            self.table.setItem(row, 3, QTableWidgetItem(lic["expires_at"]))
            self.table.setItem(row, 4, QTableWidgetItem(lic["created_at"]))

    def _show_context_menu(self, pos):
        """Show right-click context menu"""
        row = self.table.rowAt(pos.y())
        if row < 0:
            return

        menu = RoundMenu(parent=self)

        copy_action = Action(FIF.COPY, "Copy Key", self)
        copy_action.triggered.connect(lambda: self._copy_key(row))
        menu.addAction(copy_action)

        if not self.archived:
            email_action = Action(FIF.MAIL, "Resend Email", self)
            email_action.triggered.connect(lambda: self._resend_email(row))
            menu.addAction(email_action)

            archive_action = Action(FIF.DELETE, "Archive", self)
            archive_action.triggered.connect(lambda: self._archive_license(row))
            menu.addAction(archive_action)
        else:
            restore_action = Action(FIF.HISTORY, "Restore", self)
            restore_action.triggered.connect(lambda: self._restore_license(row))
            menu.addAction(restore_action)

        menu.exec(self.table.mapToGlobal(pos))

    def _on_double_click(self, index: QModelIndex):
        """Copy key on double click"""
        self._copy_key(index.row())

    def _copy_key(self, row: int):
        """Copy license key to clipboard"""
        if 0 <= row < len(self.license_data):
            key = self.license_data[row]["key"]
            QApplication.clipboard().setText(key)
            InfoBar.success("Copied", "License key copied to clipboard", parent=self, position=InfoBarPosition.TOP, duration=2000)

    def _resend_email(self, row: int):
        """Resend license email"""
        if 0 <= row < len(self.license_data):
            lic = self.license_data[row]
            key = lic["key"]
            customer = lic["customer"]
            email = lic.get("email")

            # Use issue page's email function
            if hasattr(self.parent_window, 'issue_page'):
                self.parent_window.issue_page.txt_license_out.setPlainText(key)
                self.parent_window.issue_page.cmb_customer.setCurrentText(customer)
                if email:
                    self.parent_window.issue_page.ent_email.setText(email)
                self.parent_window.issue_page._draft_email()

    def _archive_license(self, row: int):
        """Archive a license"""
        if 0 <= row < len(self.license_data):
            lic = self.license_data[row]
            box = MessageBox("Archive", f"Archive license for {lic['customer']}?", self)
            if box.exec():
                db_manager.toggle_archive_license(lic["id"], archive=True)
                self.refresh_table()
                if hasattr(self.parent_window, 'archive_page'):
                    self.parent_window.archive_page.refresh_table()

    def _restore_license(self, row: int):
        """Restore an archived license"""
        if 0 <= row < len(self.license_data):
            lic = self.license_data[row]
            box = MessageBox("Restore", f"Restore license for {lic['customer']}?", self)
            if box.exec():
                db_manager.toggle_archive_license(lic["id"], archive=False)
                self.refresh_table()
                if hasattr(self.parent_window, 'history_page'):
                    self.parent_window.history_page.refresh_table()


class ThemeToggleWidget(NavigationWidget):
    """Widget for theme toggle in navigation sidebar"""

    themeChanged = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(isSelectable=False, parent=parent)
        self.setFixedHeight(40)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 4, 16, 4)
        layout.setSpacing(8)

        # Sun/Moon icon
        self.icon_label = BodyLabel("", self)
        self._update_icon()
        layout.addWidget(self.icon_label)

        layout.addStretch()

        # Switch
        self.switch = SwitchButton(self)
        self.switch.setChecked(isDarkTheme())
        self.switch.checkedChanged.connect(self._on_toggle)
        layout.addWidget(self.switch)

    def _update_icon(self):
        if isDarkTheme():
            self.icon_label.setText("🌙 Dark")
        else:
            self.icon_label.setText("☀️ Light")

    def _on_toggle(self, is_dark: bool):
        if is_dark:
            setTheme(Theme.DARK)
        else:
            setTheme(Theme.LIGHT)

        self._update_icon()

        # Save preference
        config_file = Path.home() / ".yads" / "license_manager_settings.json"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump({"dark_mode": is_dark}, f)

        self.themeChanged.emit(is_dark)


class AboutPage(QWidget):
    """About page with app info"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("aboutPage")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        # Title
        title = TitleLabel("About", self)
        layout.addWidget(title)

        # Info Card
        info_card = CardWidget(self)
        info_layout = QVBoxLayout(info_card)
        info_layout.setContentsMargins(30, 30, 30, 30)
        info_layout.setSpacing(16)

        app_title = TitleLabel("YADS License Manager", self)
        app_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_layout.addWidget(app_title)

        version_label = SubtitleLabel("Version 2.0 - Fluent UI Edition", self)
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_layout.addWidget(version_label)

        desc = BodyLabel(
            "A modern license management tool for YADS.\n\n"
            "Features:\n"
            "• Ed25519 digital signature licensing\n"
            "• Customer database with contact info\n"
            "• License history and archiving\n"
            "• Email draft generation\n"
            "• Public key export for YADS config\n\n"
            "Built with PySide6 and QFluentWidgets",
            self
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_layout.addWidget(desc)

        info_layout.addStretch()
        layout.addWidget(info_card)
        layout.addStretch()


class BugReportKeysPage(SmoothScrollArea):
    """Sync bug-report Ed25519 public keys to the Support Portal."""

    _log_signal = Signal(str)
    _done_signal = Signal(int, int)  # ok_count, total

    def __init__(self, parent=None):
        super().__init__(parent)
        self._log_signal.connect(self._log)
        self._done_signal.connect(self._on_sync_done)
        self.setObjectName("bugReportKeysPage")
        self.setWidgetResizable(True)

        container = QWidget()
        self.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        title = TitleLabel("Bug Report Keys", self)
        layout.addWidget(title)

        sub = BodyLabel(
            "Sync each customer's Ed25519 public key to the Support Portal. "
            "The portal uses this key to verify incoming encrypted bug reports.",
            self,
        )
        sub.setWordWrap(True)
        layout.addWidget(sub)

        # --- Settings card ---
        cfg_card = SettingsCard("Portal Connection", FIF.VPN, self)

        self.ent_portal_url = LineEdit(self)
        self.ent_portal_url.setPlaceholderText("https://support.yads-security.com")
        cfg_card.addRow("Support Portal URL", self.ent_portal_url, "Base URL of the support portal")

        self.ent_admin_token = PasswordLineEdit(self)
        self.ent_admin_token.setPlaceholderText("ADMIN_TOKEN secret")
        cfg_card.addRow("Admin Token", self.ent_admin_token, "Bearer token for /api/admin/keys")

        self.ent_admin_key_path = LineEdit(self)
        self.ent_admin_key_path.setPlaceholderText(str(Path.home() / ".yads" / "admin_signing_private.key"))
        cfg_card.addRow("Admin Signing Key", self.ent_admin_key_path, "Path to Ed25519 private key for request signing")

        btn_save_cfg = PushButton(FIF.SAVE, "Save Settings", self)
        btn_save_cfg.clicked.connect(self._save_settings)
        cfg_card.addRow("", btn_save_cfg)

        layout.addWidget(cfg_card)

        # --- Customer table ---
        tbl_card = SettingsCard("Customers with Report Keys", FIF.PEOPLE, self)
        tbl_layout = QVBoxLayout()

        self.table = TableWidget(self)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Customer", "Customer UUID", "Public Key (Ed25519)"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(200)

        tbl_layout.addWidget(self.table)
        tbl_card.vBoxLayout.addLayout(tbl_layout)

        btn_row = QHBoxLayout()
        btn_refresh = PushButton(FIF.SYNC, "Refresh", self)
        btn_refresh.clicked.connect(self._load_table)
        self.btn_sync_all = PrimaryPushButton(FIF.SEND, "Sync All to Portal", self)
        self.btn_sync_all.clicked.connect(self._sync_all)
        btn_row.addWidget(btn_refresh)
        btn_row.addStretch()
        btn_row.addWidget(self.btn_sync_all)
        tbl_card.vBoxLayout.addLayout(btn_row)

        layout.addWidget(tbl_card)

        # --- Status output ---
        self.txt_status = TextEdit(self)
        self.txt_status.setReadOnly(True)
        self.txt_status.setMaximumHeight(160)
        self.txt_status.setPlaceholderText("Sync results appear here…")
        layout.addWidget(self.txt_status)

        layout.addStretch()

        self._load_settings()
        self._load_table()

    # ------------------------------------------------------------------
    def _settings_path(self) -> Path:
        return Path.home() / ".yads" / "license_manager_settings.json"

    def _load_settings(self):
        try:
            data = json.loads(self._settings_path().read_text())
            self.ent_portal_url.setText(data.get("support_portal_url", ""))
            self.ent_admin_token.setText(data.get("support_admin_token", ""))
            self.ent_admin_key_path.setText(data.get("support_admin_key_path", ""))
        except Exception:
            pass

    def _save_settings(self):
        path = self._settings_path()
        try:
            data = json.loads(path.read_text()) if path.exists() else {}
        except Exception:
            data = {}
        data["support_portal_url"] = self.ent_portal_url.text().strip()
        data["support_admin_token"] = self.ent_admin_token.text().strip()
        data["support_admin_key_path"] = self.ent_admin_key_path.text().strip()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2))
        InfoBar.success("Saved", "Portal settings saved.", parent=self, position=InfoBarPosition.TOP, duration=2500)

    def _load_table(self):
        rows = db_manager.get_customers_with_report_keys()
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(r["name"]))
            self.table.setItem(i, 1, QTableWidgetItem(r["customer_uuid"]))
            self.table.setItem(i, 2, QTableWidgetItem(r["public_key_b64"]))
        self.table.resizeColumnsToContents()

    def _log(self, msg: str):
        self.txt_status.append(msg)

    def _sync_all(self):
        rows = db_manager.get_customers_with_report_keys()
        if not rows:
            InfoBar.warning("No Keys", "No customers with report signing keys found.", parent=self, position=InfoBarPosition.TOP)
            return

        portal_url = self.ent_portal_url.text().strip() or "https://support.yads-security.com"
        admin_token = self.ent_admin_token.text().strip()
        key_path = self.ent_admin_key_path.text().strip() or str(Path.home() / ".yads" / "admin_signing_private.key")

        if not admin_token:
            InfoBar.error("Missing", "Admin Token is required.", parent=self, position=InfoBarPosition.TOP)
            return

        # Load signing key
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
            raw_b64 = Path(key_path).read_text().strip()
            _priv = _ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw_b64))
        except Exception as e:
            InfoBar.error("Key Error", str(e), parent=self, position=InfoBarPosition.TOP)
            return

        self.txt_status.clear()
        self.btn_sync_all.setEnabled(False)

        def _do_sync():
            import urllib.request
            import urllib.error
            ok_count = 0
            for r in rows:
                body = json.dumps({
                    "customer_id": r["customer_uuid"],
                    "public_key_b64": r["public_key_b64"],
                    "customer_name": r["name"],
                }, sort_keys=True).encode()
                ts = str(time.time())
                sig = base64.b64encode(_priv.sign(body)).decode()
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {admin_token}",
                    "X-Timestamp": ts,
                    "X-Signature": sig,
                }
                req = urllib.request.Request(f"{portal_url}/api/admin/keys", data=body, headers=headers)
                try:
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        result = json.loads(resp.read())
                        self._log_signal.emit(f"✓ {r['name']} ({r['customer_uuid'][:8]}…) → {result.get('status','ok')}")
                        ok_count += 1
                except urllib.error.HTTPError as he:
                    self._log_signal.emit(f"✗ {r['name']}: HTTP {he.code} — {he.read().decode()[:120]}")
                except Exception as ex:
                    self._log_signal.emit(f"✗ {r['name']}: {ex}")

            self._done_signal.emit(ok_count, len(rows))

        threading.Thread(target=_do_sync, daemon=True).start()

    @Slot(int, int)
    def _on_sync_done(self, ok_count: int, total: int):
        self.btn_sync_all.setEnabled(True)
        if ok_count == total:
            InfoBar.success("Done", f"All {ok_count} keys synced.", parent=self, position=InfoBarPosition.TOP, duration=4000)
        else:
            InfoBar.warning("Partial", f"{ok_count}/{total} keys synced.", parent=self, position=InfoBarPosition.TOP)


def _load_ed25519_key(b64: str):
    """Load an Ed25519 private key from base64 string.
    Supports both raw 32-byte keys and base64-encoded PEM files."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    raw = base64.b64decode(b64)
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        return serialization.load_pem_private_key(raw, password=None)


class ActivationRequestsPage(SmoothScrollArea):
    """Fetch pending activation requests from the support portal, sign and submit them."""

    _refresh_signal = Signal(list)   # list of request dicts
    _log_signal     = Signal(str)
    _done_signal    = Signal(int, int)  # signed, total

    def __init__(self, parent=None):
        super().__init__(parent)
        self._refresh_signal.connect(self._populate_table)
        self._log_signal.connect(self._log)
        self._done_signal.connect(self._on_sign_done)
        self.setObjectName("activationRequestsPage")
        self.setWidgetResizable(True)

        container = QWidget()
        self.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 20, 36, 20)
        layout.setSpacing(20)

        layout.addWidget(TitleLabel("Activation Requests", self))
        sub = BodyLabel(
            "Ausstehende Aktivierungsanfragen vom Support-Portal abrufen, "
            "mit dem License-Key signieren und automatisch zurücksenden.",
            self,
        )
        sub.setWordWrap(True)
        layout.addWidget(sub)

        # --- Settings ---
        cfg_card = SettingsCard("Signatur-Einstellungen", FIF.VPN, self)

        self.spin_valid_days = SpinBox(self)
        self.spin_valid_days.setRange(30, 3650)
        self.spin_valid_days.setValue(365)
        cfg_card.addRow("Gültigkeitsdauer (Tage)", self.spin_valid_days,
                        "Wie lange die Aktivierung gültig sein soll (Standard: 365)")

        self.spin_install_index = SpinBox(self)
        self.spin_install_index.setRange(1, 999)
        self.spin_install_index.setValue(1)
        cfg_card.addRow("Install-Index", self.spin_install_index,
                        "Laufende Nummer der Installation beim Kunden (Standard: 1)")

        layout.addWidget(cfg_card)

        # --- Pre-Approve ---
        pre_card = SettingsCard("Pre-Approve (manuell)", FIF.EDIT, self)

        self._pre_uuid = LineEdit(self)
        self._pre_uuid.setPlaceholderText("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
        pre_card.addRow("Instance UUID", self._pre_uuid, "UUID der Ziel-Instanz")

        self._pre_customer = LineEdit(self)
        self._pre_customer.setPlaceholderText("CUSTOMER-ID")
        pre_card.addRow("Customer ID", self._pre_customer, "customer_id aus der Lizenzdatenbank")

        pre_btn_row = QHBoxLayout()
        self._btn_pre_copy = PushButton(FIF.COPY, "Code generieren & kopieren", self)
        self._btn_pre_copy.clicked.connect(self._do_preapprove_copy)
        self._btn_pre_submit = PrimaryPushButton(FIF.SEND, "Generieren & ans Portal senden", self)
        self._btn_pre_submit.clicked.connect(self._do_preapprove_submit)
        pre_btn_row.addWidget(self._btn_pre_copy)
        pre_btn_row.addWidget(self._btn_pre_submit)
        pre_btn_row.addStretch()
        pre_card.vBoxLayout.addLayout(pre_btn_row)

        layout.addWidget(pre_card)

        # --- Table ---
        tbl_card = SettingsCard("Ausstehende Anfragen", FIF.CERTIFICATE, self)

        self._table = TableWidget(self)
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(
            ["Customer", "Instance UUID", "Eingegangen", "Typ", "Aktion"]
        )
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setMinimumHeight(220)
        tbl_card.vBoxLayout.addWidget(self._table)

        btn_row = QHBoxLayout()
        self._btn_refresh = PushButton(FIF.SYNC, "Aktualisieren", self)
        self._btn_refresh.clicked.connect(self._fetch_requests)
        self._btn_sign_all = PrimaryPushButton(FIF.SEND, "Alle signieren & senden", self)
        self._btn_sign_all.clicked.connect(self._sign_all)
        btn_row.addWidget(self._btn_refresh)
        btn_row.addStretch()
        btn_row.addWidget(self._btn_sign_all)
        tbl_card.vBoxLayout.addLayout(btn_row)

        layout.addWidget(tbl_card)

        # --- Status log ---
        self._txt_log = TextEdit(self)
        self._txt_log.setReadOnly(True)
        self._txt_log.setMaximumHeight(180)
        self._txt_log.setPlaceholderText("Ergebnisse erscheinen hier…")
        layout.addWidget(self._txt_log)
        layout.addStretch()

        self._requests: list[dict] = []
        # Don't auto-fetch on init — user clicks "Aktualisieren"

    # ------------------------------------------------------------------
    def _log(self, msg: str):
        self._txt_log.append(msg)

    def _cfg(self) -> dict:
        cfg = _read_portal_settings()
        # Fallback: read live from BugReportKeysPage if settings not yet saved to file
        mw = self.window()
        if hasattr(mw, "bug_report_keys_page"):
            brkp = mw.bug_report_keys_page
            if not cfg["url"]:
                cfg["url"] = brkp.ent_portal_url.text().strip()
            if not cfg["token"]:
                cfg["token"] = brkp.ent_admin_token.text().strip()
            if not cfg["key_path"] and hasattr(brkp, "ent_admin_key_path"):
                cfg["key_path"] = brkp.ent_admin_key_path.text().strip()
        return cfg

    def _fetch_requests(self):
        cfg = self._cfg()
        if not cfg["url"] or not cfg["token"]:
            InfoBar.warning("Nicht konfiguriert",
                            "Bitte zuerst in 'Bug Report Keys' Portal-URL und Admin-Token eintragen.",
                            parent=self, position=InfoBarPosition.TOP)
            return
        self._btn_refresh.setEnabled(False)

        def _do():
            import urllib.request, urllib.error
            try:
                req = urllib.request.Request(
                    f"{cfg['url'].rstrip('/')}/api/admin/activation-requests",
                    headers={"Authorization": f"Bearer {cfg['token']}"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                pending = [r for r in data if r.get("status") == "pending"]
                self._refresh_signal.emit(pending)
            except urllib.error.HTTPError as e:
                self._log_signal.emit(f"✗ HTTP {e.code}: {e.read().decode()[:200]}")
                self._refresh_signal.emit([])
            except Exception as ex:
                self._log_signal.emit(f"✗ Verbindungsfehler: {ex}")
                self._refresh_signal.emit([])

        threading.Thread(target=_do, daemon=True).start()

    @Slot(list)
    def _populate_table(self, requests: list):
        self._btn_refresh.setEnabled(True)
        self._requests = requests
        self._table.setRowCount(len(requests))
        for i, r in enumerate(requests):
            self._table.setItem(i, 0, QTableWidgetItem(r.get("customer_name") or r.get("customer_id", "")[:16] or "CE/unbekannt"))
            self._table.setItem(i, 1, QTableWidgetItem(r.get("instance_uuid", "")[:36]))
            ts = r.get("received_at", "")[:16].replace("T", " ")
            self._table.setItem(i, 2, QTableWidgetItem(ts))
            typ = "Offline (Code)" if r.get("request_code") else "Online (kein Code)"
            self._table.setItem(i, 3, QTableWidgetItem(typ))
            btn = PushButton(FIF.SEND, "Signieren", self)
            btn.clicked.connect(lambda _, row=i: self._sign_one(row))
            self._table.setCellWidget(i, 4, btn)
        self._table.resizeRowsToContents()
        if not requests:
            self._log(f"[{datetime.now().strftime('%H:%M:%S')}] Keine ausstehenden Anfragen.")
        else:
            self._log(f"[{datetime.now().strftime('%H:%M:%S')}] {len(requests)} ausstehende Anfrage(n) geladen.")

    # ------------------------------------------------------------------
    def _load_private_key(self):
        """Load the activation Ed25519 private key. Returns (private_key_b64, error_str)."""
        # 1. Try key_path from portal settings
        cfg = self._cfg()
        candidates = []
        if cfg.get("key_path"):
            candidates.append(Path(cfg["key_path"]).expanduser())
        # 2. Prefer activation_private.pem (separate activation keypair), fall back to license_private.pem
        candidates.append(script_dir / "activation_private.pem")
        candidates.append(script_dir / "license_private.pem")
        candidates.append(Path.home() / ".yads" / "activation_private.pem")
        candidates.append(Path.home() / ".yads" / "license_private.pem")

        for p in candidates:
            if p.exists():
                try:
                    raw = p.read_text().strip()
                    # Verify it loads (raw Ed25519 bytes or PEM)
                    _load_ed25519_key(raw)
                    return raw, None
                except Exception as e:
                    return None, f"Schlüsselfehler ({p}): {e}"
        return None, "Kein Activation Private Key gefunden. Bitte unter 'Key Management' → 'Generate Activation Key Pair' einen Schlüssel erstellen."

    def _build_response_code(self, request: dict) -> tuple[str, str | None]:
        """Sign one activation request. Returns (response_code, error)."""
        priv_b64, err = self._load_private_key()
        if err:
            return "", err

        valid_days = self.spin_valid_days.value()
        install_index = self.spin_install_index.value()

        def _sign_payload(pk, payload):
            def enc(data):
                return base64.urlsafe_b64encode(data).decode().rstrip("=")
            pl = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            pl_b64 = enc(pl)
            return f"{pl_b64}.{enc(pk.sign(pl_b64.encode()))}"

        try:
            pk = _load_ed25519_key(priv_b64)
        except Exception as e:
            return "", f"Private Key konnte nicht geladen werden: {e}"

        request_code = request.get("request_code", "").strip()
        now = int(time.time())

        if request_code:
            # Decode request code to get fields
            try:
                padded = request_code + "=" * ((4 - len(request_code) % 4) % 4)
                req_data = json.loads(base64.urlsafe_b64decode(padded))
                instance_uuid = req_data.get("instance_uuid", request["instance_uuid"])
                customer_id   = req_data.get("customer_id",   request.get("customer_id", ""))
            except Exception as e:
                return "", f"Request-Code konnte nicht dekodiert werden: {e}"
        else:
            instance_uuid = request.get("instance_uuid", "")
            customer_id   = request.get("customer_id", "")
            if not customer_id:
                return "", "Kein customer_id — manuelle Aktivierung ohne customer_id nicht möglich."

        payload = {
            "instance_uuid":  instance_uuid,
            "customer_id":    customer_id,
            "activated_at":   now,
            "exp":            now + valid_days * 86400,
            "install_index":  install_index,
        }
        try:
            response_code = _sign_payload(pk, payload)
            return response_code, None
        except Exception as e:
            return "", f"Signierfehler: {e}"

    def _submit_response(self, instance_uuid: str, response_code: str) -> str | None:
        """POST response code to portal. Returns None on success, error string on failure."""
        cfg = self._cfg()
        import urllib.request, urllib.error
        body = json.dumps({"response_code": response_code}).encode()
        req = urllib.request.Request(
            f"{cfg['url'].rstrip('/')}/api/admin/activation-requests/{instance_uuid}/respond",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {cfg['token']}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
            return None
        except urllib.error.HTTPError as e:
            return f"HTTP {e.code}: {e.read().decode()[:150]}"
        except Exception as e:
            return str(e)

    # ------------------------------------------------------------------
    def _build_preapprove_code(self) -> tuple[str, str, str | None]:
        """Build a response code for manually entered uuid+customer. Returns (uuid, code, error)."""
        uuid_ = self._pre_uuid.text().strip()
        cid   = self._pre_customer.text().strip()
        if not uuid_:
            return "", "", "Bitte Instance UUID eingeben."
        if not cid:
            return "", "", "Bitte Customer ID eingeben."

        priv_b64, err = self._load_private_key()
        if err:
            return uuid_, "", err

        valid_days    = self.spin_valid_days.value()
        install_index = self.spin_install_index.value()
        now = int(time.time())

        def _sign_payload(pk, payload):
            def enc(data):
                return base64.urlsafe_b64encode(data).decode().rstrip("=")
            pl = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            pl_b64 = enc(pl)
            return f"{pl_b64}.{enc(pk.sign(pl_b64.encode()))}"

        try:
            pk = _load_ed25519_key(priv_b64)
        except Exception as e:
            return uuid_, "", f"Private Key konnte nicht geladen werden: {e}"

        payload = {
            "instance_uuid": uuid_,
            "customer_id":   cid,
            "activated_at":  now,
            "exp":           now + valid_days * 86400,
            "install_index": install_index,
        }
        try:
            code = _sign_payload(pk, payload)
            return uuid_, code, None
        except Exception as e:
            return uuid_, "", f"Signierfehler: {e}"

    def _do_preapprove_copy(self):
        uuid_, code, err = self._build_preapprove_code()
        if err:
            InfoBar.error("Fehler", err, parent=self, position=InfoBarPosition.TOP)
            return
        QApplication.clipboard().setText(code)
        self._log(f"✓ Pre-Approve Code generiert und kopiert ({uuid_[:8]}…)")
        InfoBar.success("Kopiert", "Aktivierungscode in Zwischenablage.", parent=self,
                        position=InfoBarPosition.TOP, duration=3000)

    def _do_preapprove_submit(self):
        uuid_, code, err = self._build_preapprove_code()
        if err:
            InfoBar.error("Fehler", err, parent=self, position=InfoBarPosition.TOP)
            return
        cid = self._pre_customer.text().strip()
        err2 = self._submit_response(uuid_, code)
        if err2:
            self._log(f"✗ Pre-Approve Portal-Fehler: {err2}")
            InfoBar.error("Portal-Fehler", err2, parent=self, position=InfoBarPosition.TOP)
        else:
            QApplication.clipboard().setText(code)
            self._log(f"✓ Pre-Approve signiert und ans Portal gesendet ({uuid_[:8]}…)")
            InfoBar.success("Gesendet", f"Aktivierung für {cid or uuid_[:8]} übermittelt.",
                            parent=self, position=InfoBarPosition.TOP, duration=4000)

    def _sign_one(self, row: int):
        if row >= len(self._requests):
            return
        request = self._requests[row]
        uuid_ = request.get("instance_uuid", "?")
        name  = request.get("customer_name") or request.get("customer_id", "?")[:16]

        response_code, err = self._build_response_code(request)
        if err:
            self._log(f"✗ [{name}] {err}")
            InfoBar.error("Fehler", err, parent=self, position=InfoBarPosition.TOP)
            return

        err = self._submit_response(uuid_, response_code)
        if err:
            self._log(f"✗ [{name}] Portal-Fehler: {err}")
            InfoBar.error("Senden fehlgeschlagen", err, parent=self, position=InfoBarPosition.TOP)
        else:
            self._log(f"✓ [{name}] Aktivierung signiert und übermittelt ({uuid_[:8]}…)")
            InfoBar.success("Aktiviert", f"{name} erfolgreich aktiviert.", parent=self,
                            position=InfoBarPosition.TOP, duration=3000)
            # Remove from table
            self._requests.pop(row)
            self._populate_table(self._requests)

    def _sign_all(self):
        if not self._requests:
            InfoBar.info("Keine Anfragen", "Keine ausstehenden Anfragen vorhanden.",
                         parent=self, position=InfoBarPosition.TOP)
            return
        cfg = self._cfg()
        if not cfg["url"] or not cfg["token"]:
            InfoBar.warning("Nicht konfiguriert", "Portal-URL und Admin-Token fehlen.",
                            parent=self, position=InfoBarPosition.TOP)
            return

        self._btn_sign_all.setEnabled(False)
        self._txt_log.clear()
        requests_snapshot = list(self._requests)

        def _do():
            ok = 0
            for r in requests_snapshot:
                code, err = self._build_response_code(r)
                if err:
                    self._log_signal.emit(f"✗ [{r.get('customer_name', '?')}] {err}")
                    continue
                err = self._submit_response(r["instance_uuid"], code)
                if err:
                    self._log_signal.emit(f"✗ [{r.get('customer_name', '?')}] {err}")
                else:
                    self._log_signal.emit(f"✓ [{r.get('customer_name', '?')}] aktiviert ({r['instance_uuid'][:8]}…)")
                    ok += 1
            self._done_signal.emit(ok, len(requests_snapshot))

        threading.Thread(target=_do, daemon=True).start()

    @Slot(int, int)
    def _on_sign_done(self, ok: int, total: int):
        self._btn_sign_all.setEnabled(True)
        if ok == total:
            InfoBar.success("Fertig", f"Alle {ok} Anfragen signiert und gesendet.",
                            parent=self, position=InfoBarPosition.TOP, duration=4000)
        else:
            InfoBar.warning("Teilweise", f"{ok}/{total} erfolgreich.",
                            parent=self, position=InfoBarPosition.TOP)
        self._fetch_requests()  # Reload to confirm


class MainWindow(FluentWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()

        self.setWindowTitle("YADS License Manager")
        self.setMinimumSize(1000, 700)
        self.resize(1100, 800)

        # Initialize database
        db_manager.init_db()

        # Load saved theme preference or detect from system
        self.is_dark = self._load_theme_preference()
        if self.is_dark:
            setTheme(Theme.DARK)
        else:
            setTheme(Theme.LIGHT)
        setThemeColor("#0078d4")

        # Create pages
        self.issue_page = IssueLicensePage(self)
        self.verify_page = VerifyLicensePage(self)
        self.keys_page = KeyManagementPage(self)
        self.history_page = HistoryPage(self, archived=False)
        self.archive_page = HistoryPage(self, archived=True)
        self.bug_report_keys_page = BugReportKeysPage(self)
        self.activation_requests_page = ActivationRequestsPage(self)
        self.about_page = AboutPage(self)

        # Create theme toggle widget
        self.theme_toggle = ThemeToggleWidget(self)
        self.theme_toggle.themeChanged.connect(self._on_theme_changed)

        self._init_navigation()
        self._center_window()

    def _load_theme_preference(self) -> bool:
        """Load saved theme preference or detect from system"""
        config_file = Path.home() / ".yads" / "license_manager_settings.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    data = json.load(f)
                    return data.get("dark_mode", False)
            except:
                pass
        return detect_system_dark_mode()

    @Slot(bool)
    def _on_theme_changed(self, is_dark: bool):
        """Handle theme change - update stylesheets"""
        self.is_dark = is_dark
        # Update code view stylesheets
        if hasattr(self.issue_page, 'txt_license_out'):
            self.issue_page.txt_license_out.setStyleSheet(get_code_stylesheet())
        if hasattr(self.verify_page, 'txt_result'):
            self.verify_page.txt_result.setStyleSheet(get_result_stylesheet())
        if hasattr(self.keys_page, 'txt_pub_export'):
            self.keys_page.txt_pub_export.setStyleSheet(get_code_stylesheet())

    def _init_navigation(self):
        """Initialize navigation sidebar"""
        self.addSubInterface(self.issue_page, FIF.CERTIFICATE, "Issue License")
        self.addSubInterface(self.verify_page, FIF.SEARCH, "Verify")
        self.addSubInterface(self.keys_page, FIF.VPN, "Keys")
        self.addSubInterface(self.history_page, FIF.HISTORY, "History")
        self.addSubInterface(self.archive_page, FIF.DELETE, "Archive")
        self.addSubInterface(self.bug_report_keys_page, FIF.SEND, "Bug Report Keys")
        self.addSubInterface(self.activation_requests_page, FIF.CERTIFICATE, "Activations")

        # Add about at bottom
        self.addSubInterface(
            self.about_page, FIF.INFO, "About",
            position=NavigationItemPosition.BOTTOM
        )

        # Add theme toggle at bottom of navigation
        self.navigationInterface.addWidget(
            routeKey="themeToggle",
            widget=self.theme_toggle,
            onClick=lambda: None,
            position=NavigationItemPosition.BOTTOM
        )

        self.navigationInterface.setCurrentItem(self.issue_page.objectName())

    def _center_window(self):
        """Center window on screen"""
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)


def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("YADS License Manager")

    # Set window icon
    icon_path = script_dir / "logo.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
