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
        features_list = ["reports", "api", "scheduled_scans", "osint", "webhooks", "tenants", "analytics"]

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
        """Save customer defaults"""
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
        layout.addStretch()

    def _load_keys(self):
        """Load existing keys"""
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
                b64 = base64.b64encode(pem).decode('utf-8')
                self.txt_pub_export.setPlainText(b64)
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

    def __init__(self, parent=None):
        super().__init__(parent)
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
                        self._log(f"✓ {r['name']} ({r['customer_uuid'][:8]}…) → {result.get('status','ok')}")
                        ok_count += 1
                except urllib.error.HTTPError as he:
                    self._log(f"✗ {r['name']}: HTTP {he.code} — {he.read().decode()[:120]}")
                except Exception as ex:
                    self._log(f"✗ {r['name']}: {ex}")

            if ok_count == len(rows):
                InfoBar.success("Done", f"All {ok_count} keys synced.", parent=self, position=InfoBarPosition.TOP, duration=4000)
            else:
                InfoBar.warning("Partial", f"{ok_count}/{len(rows)} keys synced.", parent=self, position=InfoBarPosition.TOP)
            self.btn_sync_all.setEnabled(True)

        threading.Thread(target=_do_sync, daemon=True).start()


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
