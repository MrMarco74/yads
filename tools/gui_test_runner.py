#!/usr/bin/env python3
# -u passed by caller for unbuffered output
"""
YADS GUI Test Runner
Exhaustive GUI testing with parallel system log monitoring.
"""

import os
import sys
import asyncio
import argparse
import datetime
import json
import subprocess
from pathlib import Path
from playwright.async_api import async_playwright

# Force unbuffered output so the GUI log sees lines in real-time
def _p(msg: str, level: str = ""):
    """Print with immediate flush."""
    prefix = {"error": "❌ ", "warning": "⚠️  ", "ok": "✅ ", "step": "▶ "}.get(level, "")
    print(f"{prefix}{msg}", flush=True)

class GuiTestRunner:
    def __init__(self, target_url, dana_host="dana", dana_user="root"):
        self.target_url = target_url
        self.dana_host = dana_host
        self.dana_user = dana_user
        self.results_dir = Path("tests/results/GUI-Tests")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logs = []
        self.failures = []
        self.visited_urls = set()
        self.fallback_urls = [
            "/", "/analytics", "/attack-surface/", "/targets/table", 
            "/queue", "/workers", "/system/alerts", "/reports",
            "/compliance", "/ports", "/security-findings", "/settings",
            "/logs", "/storage", "/profile"
        ]
        self.version = self._load_version()
        
        # Session-specific directory
        self.session_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = self.results_dir / self.session_id
        self.screenshot_dir = self.session_dir / "Screenshots"
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

    def _load_version(self):
        """Loads version from releases/version.json"""
        v_file = Path(__file__).parent.parent / "releases" / "version.json"
        if v_file.exists():
            try:
                data = json.loads(v_file.read_text())
                return data.get("version", "Unknown")
            except Exception:
                pass
        return "Unknown"
    
    async def capture_screenshot(self, page, name):
        """Helper to capture a screenshot and save it to the session directory."""
        safe_name = "".join(c for c in name if c.isalnum() or c in (" ", ".", "_")).rstrip()
        filename = f"{datetime.datetime.now().strftime('%H%M%S')}_{safe_name}.png"
        path = self.screenshot_dir / filename
        try:
            await page.screenshot(path=str(path))
            print(f"  Screenshot saved: {path.relative_to(self.results_dir)}")
            return path
        except Exception as e:
            print(f"  Failed to save screenshot {name}: {e}")
            return None

    async def ensure_dana_running(self):
        """Ensure the Dana test environment is up and running. Skip if in container."""
        if os.path.exists("/.dockerenv"):
            return True
        # Path from run-tests.sh
        dana_path = "~/yads-testenv"
        compose_file = "docker-compose.testlab.yml"
        
        # Command to pull and start environment
        cmd = [
            "ssh", f"{self.dana_user}@{self.dana_host}",
            f"cd {dana_path} && docker compose -f {compose_file} up -d --remove-orphans"
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        _, stderr = await process.communicate()
        if process.returncode == 0:
            _p("Environment is running.", "ok")
            return True
        else:
            _p(f"Error starting environment: {stderr.decode()}", "error")
            return False

    async def monitor_logs(self, stop_event):
        """Monitor Docker logs. If in container with docker.sock, use local docker command."""
        # Use 'docker' directly since we mount docker.sock
        cmd = ["docker", "compose", "-f", "docker-compose.testlab.yml", "logs", "-f"]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        while not stop_event.is_set():
            line = await process.stdout.readline()
            if not line:
                break
            line_str = line.decode().strip()
            self.logs.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] DANA: {line_str}")
            if "error" in line_str.lower() or "exception" in line_str.lower():
                _p(f"DANA log: {line_str}", "warning")

    async def wait_for_url(self, timeout=120):
        """Wait for the target URL to be accessible."""
        import urllib.request
        import time
        start_time = time.time()
        _p(f"Waiting for {self.target_url} to be ready (timeout {timeout}s)...", "step")
        last_dot = 0
        while time.time() - start_time < timeout:
            try:
                def check():
                    with urllib.request.urlopen(self.target_url, timeout=2.0) as response:
                        return response.getcode() < 500

                if await asyncio.to_thread(check):
                    _p(f"Target URL is up! ({int(time.time()-start_time)}s)", "ok")
                    return True
            except Exception:
                pass
            elapsed = int(time.time() - start_time)
            if elapsed - last_dot >= 10:
                _p(f"  Still waiting for API... ({elapsed}s elapsed)", "")
                last_dot = elapsed
            await asyncio.sleep(1)
        _p(f"Timeout after {timeout}s waiting for {self.target_url}", "error")
        return False

    async def login_step(self, page) -> bool:
        """
        Pre-step: navigate to the app and perform login (no MFA).
        Returns True if login succeeded, False otherwise.
        All subsequent tests must be aborted when this returns False.
        """
        _p("PRE-STEP: Login", "step")
        try:
            _p(f"  Navigating to {self.target_url} ...")
            await page.goto(self.target_url)
            await page.wait_for_load_state("networkidle")

            if "login" not in page.url.lower() and not await page.query_selector('input[name="username"]'):
                await self.capture_screenshot(page, "login_skipped_already_authenticated")
                _p("  Already authenticated — skipping login.", "ok")
                return True

            _p("  Login form found — filling credentials...")
            await self.capture_screenshot(page, "login_page_empty")
            await page.fill('input[name="username"]', "admin")
            await page.fill('input[name="password"]', "admin")
            await self.capture_screenshot(page, "login_page_filled")
            await page.click('button[type="submit"]')
            await page.wait_for_load_state("networkidle")

            if "change-password" in page.url or await page.query_selector("input[name='new_password']"):
                _p("  Force password change detected — updating...", "warning")
                await self.capture_screenshot(page, "force_password_change")
                await page.fill("input[name='new_password']", "adminAdmin123!")
                await page.fill("input[name='confirm_password']", "adminAdmin123!")
                await page.click("button[type='submit']")
                await page.wait_for_load_state("networkidle")
                _p("  Password changed.", "ok")

            await self.capture_screenshot(page, "after_login")

            if "login" in page.url.lower():
                _p("CRITICAL: Login failed — still on login page.", "error")
                await self.record_failure(
                    "Login Pre-Step Failed",
                    "Still on login page after credentials submission. All tests aborted.",
                    page
                )
                return False

            _p(f"  Login successful. Current URL: {page.url}", "ok")
            return True

        except Exception as e:
            _p(f"CRITICAL: Login pre-step raised exception: {e}", "error")
            await self.record_failure("Login Pre-Step Exception", str(e), page)
            return False

    async def run_tests(self):
        _p(f"YADS GUI Test Runner v{self.version} — target: {self.target_url}", "step")

        if not await self.ensure_dana_running():
            _p("Aborting tests due to environment failure.", "error")
            return

        if not await self.wait_for_url():
            _p("Aborting tests: target URL still not reachable.", "error")
            return

        _p(f"Starting GUI tests on {self.target_url}", "step")
        stop_event = asyncio.Event()
        log_task = asyncio.create_task(self.monitor_logs(stop_event))

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport={'width': 1280, 'height': 800})
            page = await context.new_page()

            try:
                # PRE-STEP: Login — abort everything if this fails
                if not await self.login_step(page):
                    _p("Aborting all GUI tests: login pre-step failed.", "error")
                    self.generate_report()
                    stop_event.set()
                    await browser.close()
                    await log_task
                    return

                # 2. Extract Sidebar Links
                try:
                    _p("Scanning sidebar for navigation links...", "step")
                    await page.wait_for_selector("aside", timeout=10000)
                    sidebar_links = await self.get_sidebar_links(page)
                    _p(f"Found {len(sidebar_links)} pages to test.", "ok")
                except Exception:
                    _p("CRITICAL: Sidebar (aside) not found within timeout — using fallback URLs.", "error")
                    await self.record_failure("Missing Sidebar", "Sidebar (aside) not found after login. Verification of dashboard failed.", page)
                    sidebar_links = [self.target_url.rstrip("/") + path for path in self.fallback_urls]
                    _p(f"Using {len(sidebar_links)} fallback URLs.", "warning")

                total = len(sidebar_links)
                # 3. Iterate through Sidebar sections
                for idx, link in enumerate(sidebar_links, 1):
                    _p(f"[{idx}/{total}] Testing: {link.replace(self.target_url, '') or '/'}")
                    await self.test_page(page, link)

            except Exception as e:
                _p(f"Global runner error: {e}", "error")
                await self.record_failure("Global Runner Error", str(e), page)
            finally:
                stop_event.set()
                await browser.close()
                await log_task

        failures = len(self.failures)
        passed = len(self.visited_urls)
        if failures == 0:
            _p(f"All {passed} pages passed — no failures.", "ok")
        else:
            _p(f"{passed} pages tested — {failures} failure(s).", "error")
        self.generate_report()

    async def get_sidebar_links(self, page):
        """Extracts all unique hrefs from the sidebar navigation."""
        links = []
        try:
            # Find all <a> tags within the <aside> element
            sidebar_links_elements = await page.query_selector_all("aside a")
            for link_element in sidebar_links_elements:
                href = await link_element.get_attribute("href")
                if href and not href.startswith("#"): # Ignore anchor links within the same page
                    # Construct full URL if it's a relative path
                    if href.startswith("/"):
                        full_url = self.target_url.rstrip("/") + href
                    else:
                        full_url = href
                    links.append(full_url)
        except Exception as e:
            print(f"Warning: Failed to extract sidebar links: {e}")
        return list(dict.fromkeys(links))

    def _write_report_header(self, f, timestamp):
        f.write(f"# YADS GUI Test Report - {timestamp}\n\n")
        f.write(f"- **Target:** {self.target_url}\n")
        f.write(f"- **YADS Version:** {self.version}\n")
        f.write(f"- **Tests Run:** {len(self.visited_urls)}\n")
        f.write(f"- **Failures:** {len(self.failures)}\n\n")

    def _write_component_list(self, f):
        f.write("## Tested Components\n\n")
        for url in sorted(self.visited_urls):
            if url == self.target_url or url == f"{self.target_url}/":
                continue
            path = url.replace(self.target_url, "") or "/"
            failed = any(f["url"] == url for f in self.failures)
            status = "❌" if failed else "✅"
            f.write(f"- {status} `{path}`\n")
        f.write("\n")

    def _write_screenshot_list(self, f):
        f.write("## Session Screenshots\n\n")
        f.write(f"All screenshots for this session are stored in: `{self.screenshot_dir.relative_to(self.results_dir.parent.parent)}`\n\n")
        screenshot_files = sorted(list(self.screenshot_dir.glob("*.png")))
        if screenshot_files:
            for shot in screenshot_files:
                f.write(f"- [{shot.name}]({shot.relative_to(self.results_dir)})\n")
        else:
            f.write("No screenshots captured.\n")
        f.write("\n")

    def _write_failures(self, f):
        if not self.failures:
            return
        f.write("## Failures\n\n")
        for fail in self.failures:
            f.write(f"### {fail['title']}\n")
            f.write(f"- **URL:** {fail['url']}\n")
            f.write(f"- **Message:** {fail['message']}\n")
            f.write(f"- **Timestamp:** {fail['timestamp']}\n")
            f.write(f"![Failure Screenshot]({fail['screenshot']})\n\n")

    def _write_logs_and_prompt(self, f):
        f.write("## System Logs (Relevant Snippet)\n\n")
        f.write("```\n")
        for line in self.logs[-50:]:
            f.write(f"{line}\n")
        f.write("```\n\n")
        f.write("## AI Debugging Prompt\n\n")
        f.write("> [!TIP]\n")
        f.write("> Copy the block below to an LLM to get a fix proposal.\n\n")
        f.write("```text\n")
        f.write("Ich habe einen automatisierten GUI-Test für YADS durchgeführt und Fehler gefunden.\n")
        f.write(f"Fehler: {json.dumps(self.failures, indent=2)}\n")
        f.write("Logs:\n")
        f.write("\n".join(self.logs[-30:]))
        f.write("\n\nBitte analysiere diese Fehler und schlage eine Korrektur vor.\n")
        f.write("```\n")

    def generate_report(self):
        timestamp_now = datetime.datetime.now()
        timestamp = timestamp_now.strftime("%Y-%m-%d %H:%M:%S")
        timestamp_str = timestamp_now.strftime("%Y%m%d_%H%M%S")
        report_file = self.session_dir / f"test_result_{timestamp_str}.md"
        with open(report_file, "w") as f:
            self._write_report_header(f, timestamp)
            self._write_component_list(f)
            self._write_screenshot_list(f)
            if self.failures:
                self._write_failures(f)
                self._write_logs_and_prompt(f)
            else:
                f.write("✅ All tests passed successfully.\n")
        _p(f"Report generated: {report_file}", "ok")

    async def test_page(self, page, url):
        """Test a specific page including basic interactions."""
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        
        try:
            await page.goto(url)
            await page.wait_for_load_state("networkidle")
            await asyncio.sleep(1)

            page_name = url.split("/")[-1] or "dashboard"
            await self.capture_screenshot(page, f"page_{page_name}")

            content = await page.content()
            if "Internal Server Error" in content or "500" in page.url:
                _p(f"  ❌ HTTP 500 on {url}", "error")
                await self.record_failure(f"HTTP 500 on {url}", "Server returned error", page)
                return

            if "/login" in page.url:
                _p(f"  ❌ Session lost — redirected to login on {url}", "error")
                await self.record_failure(f"Auth Refused: {url}", "Redirected to login page. Session might be invalid.", page)
                return

            _p(f"  ✅ OK", "ok")
            await self.interact_with_page(page, url)

        except Exception as e:
            _p(f"  ❌ Exception on {url}: {e}", "error")
            await self.record_failure(f"Navigation/Interaction Error: {url}", str(e), page)

    async def interact_with_page(self, page, url):
        """Interact with buttons, forms, and specific YADS elements."""
        
        # 1. Click 'Add' or 'Create' buttons to check modals/forms
        try:
            buttons = await page.query_selector_all("button")
            for btn in buttons:
                try:
                    inner_text = await btn.inner_text()
                    text = inner_text.lower()
                    if any(kw in text for kw in ["add", "create", "new", "start", "run"]):
                        if await btn.is_visible() and await btn.is_enabled():
                            print(f"  Stimulating action: {text}")
                            await btn.click()
                            await page.wait_for_load_state("networkidle")
                            await asyncio.sleep(0.5)
                            
                            # Check for crash after click
                            if "Internal Server Error" in await page.content():
                                await self.record_failure(f"Crash clicking '{text}' on {url}", "Server error after interaction", page)
                            
                            # If a modal appeared, try to close it or hit ESC
                            await page.keyboard.press("Escape")
                except Exception:
                    continue
        except Exception:
            pass

    async def record_failure(self, title, message, page):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_path = self.session_dir / f"failure_{timestamp}.png"
        
        try:
            # Also save a debug screenshot of the current state
            await page.screenshot(path=str(screenshot_path))
        except Exception as e:
            print(f"Failed to capture screenshot: {e}")

        self.failures.append({
            "title": title,
            "message": message,
            "url": page.url,
            "timestamp": timestamp,
            "screenshot": str(screenshot_path)
        })
        _p(f"FAILURE: {title} — {message}", "error")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://dana:8085")
    parser.add_argument("--dana-host", default="dana")
    args = parser.parse_args()
    
    runner = GuiTestRunner(args.url, dana_host=args.dana_host)
    asyncio.run(runner.run_tests())
