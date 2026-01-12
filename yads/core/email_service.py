import os
import smtplib
import ssl
import logging
from email.message import EmailMessage
from typing import Optional, Union, List

# Configure logger
logger = logging.getLogger("email_service")
# Ensure it has a handler if not already configured by root
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - EMAIL_SERVICE - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

class EmailService:
    def __init__(self):
        # Hybrid Loading: Check DB first, then Env
        self.smtp_host = os.environ.get("SMTP_HOST")
        self.smtp_port = os.environ.get("SMTP_PORT")
        self.smtp_user = os.environ.get("SMTP_USER")
        self.smtp_password = os.environ.get("SMTP_PASSWORD")
        
        try:
             from yads.config import settings
             from yads.models import SystemConfig
             from sqlmodel import Session, create_engine, select
             
             engine = create_engine(settings.DATABASE_URL)
             with Session(engine) as session:
                 val = session.get(SystemConfig, "SMTP_HOST")
                 if val: self.smtp_host = val.value
                 
                 val = session.get(SystemConfig, "SMTP_PORT")
                 if val: self.smtp_port = val.value
                 
                 val = session.get(SystemConfig, "SMTP_USER")
                 if val: self.smtp_user = val.value
                 
                 val = session.get(SystemConfig, "SMTP_PASSWORD")
                 if val: self.smtp_password = val.value
        except Exception as e:
             pass

        # Hardcoded sender as requested
        self.sender_email = "yads-donotreply@example.internal"

        self.enabled = True
        if not all([self.smtp_host, self.smtp_port, self.smtp_user, self.smtp_password]):
            logger.warning("EmailService configuration missing (SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD). Email sending disabled.")
            self.enabled = False

    def send_mail(self, to_addr: Union[str, List[str]], subject: str, body_text: str, body_html: Optional[str] = None) -> bool:
        """
        Sends an email with plain text and optional HTML content.
        Returns True if successful, False otherwise.
        """
        if not self.enabled:
            logger.debug("EmailService is disabled. Skipping email sending.")
            return False

        if not to_addr:
            logger.error("No recipient specified.")
            return False

        # Create message container
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = self.sender_email
        
        if isinstance(to_addr, list):
            msg['To'] = ', '.join(to_addr)
        else:
            msg['To'] = to_addr

        # Set content
        msg.set_content(body_text)

        # Add HTML version if provided (Multipart)
        if body_html:
            msg.add_alternative(body_html, subtype='html')

        # Secure Context
        context = ssl.create_default_context()

        try:
            port = int(self.smtp_port)
            logger.info(f"Connecting to SMTP server {self.smtp_host}:{port}...")
            
            # Connect to sending server
            with smtplib.SMTP(self.smtp_host, port) as server:
                server.starttls(context=context) # Secure the connection
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
                
            logger.info(f"Email sent successfully to {to_addr}")
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP Authentication failed. Check username/password.")
            return False
        except smtplib.SMTPConnectError:
            logger.error("Failed to connect to SMTP server.")
            return False
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

# Singleton instance for easy import
email_service = EmailService()
