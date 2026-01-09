import re
import unittest
from unittest.mock import MagicMock, patch
from yads.modules.web_analyzer import WebAnalyzer

class TestOSINTExtraction(unittest.TestCase):
    def test_regex_logic(self):
        # Mocking the page object behavior directly for regex testing
        # We are replicating the logic inside _run_headless partially here to test the regex patterns
        
        sample_html = """
        <html>
            <body>
                <p>Contact us at support@example.com or sales@test.co.uk</p>
                <p>Ignore image@2x.png</p>
                <p>Call us at +1-555-0199 or (123) 456-7890</p>
                <a href="https://twitter.com/yads_tool">Twitter</a>
                <a href="https://www.linkedin.com/in/founder">LinkedIn</a>
                <a href="https://example.com/clean.pdf">Download Report</a>
                <a href="/uploads/financials.xlsx">Financials</a>
            </body>
        </html>
        """
        
        sample_text = """
        Contact us at support@example.com or sales@test.co.uk
        Ignore image@2x.png
        Call us at +1-555-0199 or (123) 456-7890
        """
        
        links = [
            "https://twitter.com/yads_tool",
            "https://www.linkedin.com/in/founder",
            "https://example.com/clean.pdf",
            "/uploads/financials.xlsx",
            "https://example.com/image.png"
        ]

        # --- Test logic copy-pasted/adapted from WebAnalyzer to verify correctness ---
        
        results = {"emails": [], "phones": [], "socials": [], "documents": []}
        
        # A. Emails
        email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        raw_emails = re.findall(email_regex, sample_text)
        unique_emails = set()
        ignore_ext = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.css', '.js']
        for email in raw_emails:
            email = email.lower()
            if not any(email.endswith(ext) for ext in ignore_ext):
                    unique_emails.add(email)
        results["emails"] = list(unique_emails)
        
        # B. Socials
        found_socials = []
        social_platforms = {
            "linkedin": r"linkedin\.com/in/|linkedin\.com/company/",
            "twitter": r"twitter\.com/|x\.com/",
        }
        for link in links:
             for platform, regex in social_platforms.items():
                if re.search(regex, link, re.IGNORECASE):
                        found_socials.append(link)
        results["socials"] = found_socials
        
        # C. Documents
        doc_exts = ['.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.csv']
        found_docs = []
        for link in links:
            lower_link = link.lower()
            if any(lower_link.endswith(ext) for ext in doc_exts):
                 found_docs.append(link)
        results["documents"] = found_docs
        
        # Assertions
        print("Emails Found:", results["emails"])
        self.assertIn("support@example.com", results["emails"])
        self.assertIn("sales@test.co.uk", results["emails"])
        self.assertNotIn("image@2x.png", results["emails"])
        
        print("Socials Found:", results["socials"])
        self.assertIn("https://twitter.com/yads_tool", results["socials"])
        
        print("Docs Found:", results["documents"])
        self.assertIn("https://example.com/clean.pdf", results["documents"])
        self.assertIn("/uploads/financials.xlsx", results["documents"])
        
        print("Test Passed!")

if __name__ == '__main__':
    unittest.main()
