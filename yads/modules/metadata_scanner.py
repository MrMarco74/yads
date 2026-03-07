"""
Document Metadata Scanner

Discovers documents (PDF, Word, Excel, PowerPoint) linked from target pages
and extracts metadata to reveal:
- Author names (internal employee names/accounts)
- Software versions (Windows version, Office version, internal tools)
- Creation/modification dates
- Internal file system paths (e.g. C:\\Users\\john.doe\\Documents\\...)
- Company/organization names
- GPS coordinates in images (if any)

Uses PyPDF2 for PDFs, python-docx for Word, openpyxl for Excel.
Falls back to extracting what's available if optional libraries are missing.
"""

import io
import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Document extensions to look for
DOC_EXTENSIONS = {
    ".pdf": "PDF",
    ".doc": "Word (legacy)",
    ".docx": "Word",
    ".xls": "Excel (legacy)",
    ".xlsx": "Excel",
    ".ppt": "PowerPoint (legacy)",
    ".pptx": "PowerPoint",
    ".odt": "OpenDocument Text",
    ".ods": "OpenDocument Spreadsheet",
    ".odp": "OpenDocument Presentation",
}

# Patterns that indicate interesting metadata
INTERNAL_PATH_PATTERN = re.compile(
    r"(?:[A-Za-z]:\\|/home/|/Users/|/var/|/opt/)\S+",
    re.IGNORECASE
)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
USERNAME_PATTERN = re.compile(
    r"(?:Author|Creator|Last Modified By|Modified By)[:\s]+([^\n\r<]{3,80})",
    re.IGNORECASE
)


class MetadataScanner(BaseScannerModule):
    """Discover and analyze document metadata for information disclosure."""

    MAX_DOCS = 20

    @property
    def module_name(self) -> str:
        return "metadata_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = target.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

        result: Dict[str, Any] = {
            "domain": domain,
            "documents_found": [],
            "documents_analyzed": 0,
            "findings": [],
            "metadata_items": [],
            "summary": {
                "score": 100,
                "doc_count": 0,
                "findings_count": 0,
                "authors_found": [],
                "software_found": [],
                "internal_paths": [],
            },
        }

        base_url = self._get_base_url(domain)
        if not base_url:
            result["error"] = "Domain not reachable"
            return result

        html = self._fetch_html(base_url)
        if not html:
            result["error"] = "Could not fetch HTML"
            return result

        # Discover document links
        doc_urls = self._find_document_links(html, base_url, domain)
        result["documents_found"] = doc_urls[:self.MAX_DOCS]
        result["summary"]["doc_count"] = len(doc_urls)

        if not doc_urls:
            return result

        # Analyze each document
        authors: Set[str] = set()
        software: Set[str] = set()
        internal_paths: List[str] = []
        analyzed = 0

        for doc_url in doc_urls[:self.MAX_DOCS]:
            ext = self._get_extension(doc_url)
            meta = self._extract_metadata(doc_url, ext)
            if not meta:
                continue

            analyzed += 1
            meta["url"] = doc_url
            meta["type"] = DOC_EXTENSIONS.get(ext, "Document")
            result["metadata_items"].append(meta)

            # Collect interesting fields
            if meta.get("author"):
                authors.add(meta["author"])
            if meta.get("creator"):
                software.add(meta["creator"])
            if meta.get("producer"):
                software.add(meta["producer"])
            for path in meta.get("internal_paths", []):
                internal_paths.append(path)

            # Generate findings
            if meta.get("author") or meta.get("last_modified_by"):
                name = meta.get("last_modified_by") or meta.get("author", "")
                result["findings"].append({
                    "severity": "medium",
                    "title": f"Author/username found in document: {name}",
                    "detail": f"Document: {doc_url.split('/')[-1]} — Author: {name}",
                    "url": doc_url,
                    "category": "author_disclosure",
                })

            for path in meta.get("internal_paths", []):
                result["findings"].append({
                    "severity": "high",
                    "title": f"Internal path found: {path[:80]}",
                    "detail": f"Found in {doc_url.split('/')[-1]}",
                    "url": doc_url,
                    "category": "path_disclosure",
                })

            if meta.get("emails"):
                for email in meta["emails"]:
                    result["findings"].append({
                        "severity": "low",
                        "title": f"Email address found in document: {email}",
                        "detail": f"Found in {doc_url.split('/')[-1]}",
                        "url": doc_url,
                        "category": "email_disclosure",
                    })

        result["documents_analyzed"] = analyzed
        result["summary"]["authors_found"] = sorted(authors)
        result["summary"]["software_found"] = sorted(software)
        result["summary"]["internal_paths"] = internal_paths[:10]
        result["summary"]["findings_count"] = len(result["findings"])

        # Score
        score = 100
        for f in result["findings"]:
            if f["severity"] == "high":
                score -= 10
            elif f["severity"] == "medium":
                score -= 5
            elif f["severity"] == "low":
                score -= 2
        result["summary"]["score"] = max(0, score)

        return result

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _find_document_links(self, html: str, base_url: str, domain: str) -> List[str]:
        urls = []
        seen: Set[str] = set()
        for match in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = match.group(1)
            ext = self._get_extension(href)
            if ext not in DOC_EXTENSIONS:
                continue

            if href.startswith("//"):
                href = "https:" + href
            elif href.startswith("/"):
                href = base_url.rstrip("/") + href
            elif not href.startswith("http"):
                href = base_url.rstrip("/") + "/" + href

            if href not in seen:
                seen.add(href)
                urls.append(href)

        return urls

    def _get_extension(self, url: str) -> str:
        path = urlparse(url).path.lower()
        for ext in DOC_EXTENSIONS:
            if path.endswith(ext) or f"{ext}?" in path:
                return ext
        return ""

    # ------------------------------------------------------------------
    # Metadata Extraction
    # ------------------------------------------------------------------

    def _get_base_url(self, domain: str) -> Optional[str]:
        for scheme in ("https", "http"):
            try:
                resp = requests.head(
                    f"{scheme}://{domain}",
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
                )
                if resp.status_code < 500:
                    return f"{scheme}://{domain}"
            except Exception:
                continue
        return None

    def _fetch_html(self, url: str) -> Optional[str]:
        try:
            resp = requests.get(
                url, timeout=REQUEST_TIMEOUT, verify=False,
                headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
            )
            return resp.text[:300_000]
        except Exception:
            return None

    def _extract_metadata(self, url: str, ext: str) -> Optional[Dict]:
        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                stream=True,
                headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
            )
            if resp.status_code != 200:
                return None
            content = resp.content[:MAX_FILE_SIZE]
        except Exception as e:
            logger.debug(f"[Metadata] Failed to fetch {url}: {e}")
            return None

        if ext == ".pdf":
            return self._parse_pdf(content)
        elif ext in (".docx", ".xlsx", ".pptx"):
            return self._parse_ooxml(content)
        return None

    def _parse_pdf(self, content: bytes) -> Optional[Dict]:
        try:
            import pypdf  # type: ignore
            reader = pypdf.PdfReader(io.BytesIO(content))
            info = reader.metadata or {}
            text_sample = ""
            try:
                if reader.pages:
                    text_sample = reader.pages[0].extract_text()[:2000] or ""
            except Exception:
                pass

            return self._normalize_metadata(
                author=str(info.get("/Author", "")).strip(),
                creator=str(info.get("/Creator", "")).strip(),
                producer=str(info.get("/Producer", "")).strip(),
                title=str(info.get("/Title", "")).strip(),
                subject=str(info.get("/Subject", "")).strip(),
                creation_date=str(info.get("/CreationDate", "")).strip(),
                mod_date=str(info.get("/ModDate", "")).strip(),
                text_sample=text_sample,
            )
        except ImportError:
            # pypdf not available, try basic regex extraction
            return self._parse_pdf_regex(content)
        except Exception as e:
            logger.debug(f"[Metadata] PDF parse error: {e}")
            return None

    def _parse_pdf_regex(self, content: bytes) -> Optional[Dict]:
        """Regex-based PDF metadata extraction fallback."""
        try:
            text = content.decode("latin-1", errors="replace")[:50000]
            author_match = re.search(r'/Author\s*\(([^)]+)\)', text)
            creator_match = re.search(r'/Creator\s*\(([^)]+)\)', text)
            producer_match = re.search(r'/Producer\s*\(([^)]+)\)', text)
            return self._normalize_metadata(
                author=author_match.group(1).strip() if author_match else "",
                creator=creator_match.group(1).strip() if creator_match else "",
                producer=producer_match.group(1).strip() if producer_match else "",
            )
        except Exception:
            return None

    def _parse_ooxml(self, content: bytes) -> Optional[Dict]:
        """Extract metadata from OOXML (docx/xlsx/pptx) using zipfile."""
        import zipfile
        try:
            zf = zipfile.ZipFile(io.BytesIO(content))
            core_xml = ""
            app_xml = ""
            if "docProps/core.xml" in zf.namelist():
                core_xml = zf.read("docProps/core.xml").decode("utf-8", errors="replace")
            if "docProps/app.xml" in zf.namelist():
                app_xml = zf.read("docProps/app.xml").decode("utf-8", errors="replace")

            def xml_val(xml, tag):
                m = re.search(rf'<[^:>]*:{tag}>([^<]+)</', xml)
                if not m:
                    m = re.search(rf'<{tag}>([^<]+)</', xml)
                return m.group(1).strip() if m else ""

            return self._normalize_metadata(
                author=xml_val(core_xml, "creator"),
                last_modified_by=xml_val(core_xml, "lastModifiedBy"),
                title=xml_val(core_xml, "title"),
                subject=xml_val(core_xml, "subject"),
                company=xml_val(app_xml, "Company"),
                creator=xml_val(app_xml, "Application"),
            )
        except Exception as e:
            logger.debug(f"[Metadata] OOXML parse error: {e}")
            return None

    def _normalize_metadata(self, **kwargs) -> Dict:
        meta = {k: v for k, v in kwargs.items() if v}
        meta["internal_paths"] = []
        meta["emails"] = []

        # Scan all string values for internal paths and emails
        all_text = " ".join(str(v) for v in meta.values() if isinstance(v, str))
        for m in INTERNAL_PATH_PATTERN.finditer(all_text):
            path = m.group(0)[:200]
            if path not in meta["internal_paths"]:
                meta["internal_paths"].append(path)

        for m in EMAIL_PATTERN.finditer(all_text):
            email = m.group(0)
            if email not in meta["emails"]:
                meta["emails"].append(email)

        return meta
