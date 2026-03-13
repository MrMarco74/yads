#!/usr/bin/env python3
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
            print("Environment is running.")
            return True
        else:
            print(f"Error starting environment: {stderr.decode()}")
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
                print(f"Detected potential error in Dana logs: {line_str}")

    async def wait_for_url(self, timeout=30):
        """Wait for the target URL to be accessible."""
        import urllib.request
        import time
        start_time = time.time()
        print(f"Waiting for {self.target_url} to be ready...")
        while time.time() - start_time < timeout:
            try:
                # Run in thread to not block event loop
                def check():
                    with urllib.request.urlopen(self.target_url, timeout=2.0) as response:
                        return response.getcode() < 500
                
                if await asyncio.to_thread(check):
                    print("Target URL is up!")
                    return True
            except Exception:
                pass
            await asyncio.sleep(1)
        print(f"Timeout waiting for {self.target_url}")
        return False

    async def run_tests(self):
        if not await self.ensure_dana_running():
            print("Aborting tests due to environment failure.")
            return

        if not await self.wait_for_url():
            print("Aborting tests: target URL still not reachable.")
            return

        print(f"Starting GUI tests on {self.target_url}")
        stop_event = asyncio.Event()
        log_task = asyncio.create_task(self.monitor_logs(stop_event))

        async with async_playwright() as p:
            # Launch with a standard viewport
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport={'width': 1280, 'height': 800})
            page = await context.new_page()

            try:
                # 1. Login if needed
                await page.goto(self.target_url)
                await page.wait_for_load_state("networkidle")
                
                if await page.query_selector('input[name="username"]'):
                    print("Attempting login...")
                    await self.capture_screenshot(page, "login_page_empty")
                    await page.fill('input[name="username"]', "admin")
                    await page.fill('input[name="password"]', "admin")
                    await self.capture_screenshot(page, "login_page_filled")
                    await page.click('button[type="submit"]')
                
                # Verify login success
                await page.wait_for_load_state("networkidle")
                await self.capture_screenshot(page, "after_login_attempt")
                if "login" in page.url.lower():
                    print("CRITICAL: Login appears to have failed (still on login page).")
                    await self.record_failure("Login Failed", "Still on login page after credentials submission.", page)

                # 1b. Handle Force Password Change
                if "change-password" in page.url or await page.query_selector("input[name='new_password']"):
                    print("Force password change detected. Updating...")
                    await self.capture_screenshot(page, "before_password_change")
                    await page.fill("input[name='new_password']", "adminAdmin123!")
                    await page.fill("input[name='confirm_password']", "adminAdmin123!")
                    await page.click("button[type='submit']")
                    await page.wait_for_load_state("networkidle")
                    await self.capture_screenshot(page, "after_password_change")

                # 2. Extract Sidebar Links
                try:
                    await page.wait_for_selector("aside", timeout=10000)
                    sidebar_links = await self.get_sidebar_links(page)
                    print(f"Discovered {len(sidebar_links)} sidebar sections.")
                except Exception:
                    print("CRITICAL: Sidebar (aside) not found within timeout.")
                    await self.record_failure("Missing Sidebar", "Sidebar (aside) not found after login. Verification of dashboard failed.", page)
                    # Use fallback links so the report isn't empty
                    sidebar_links = [self.target_url.rstrip("/") + path for path in self.fallback_urls]
                    print(f"Using {len(sidebar_links)} fallback sidebar sections for testing.")
                
                # 3. Iterate through Sidebar sections
                for link in sidebar_links:
                    await self.test_page(page, link)

            except Exception as e:
                await self.record_failure("Global Runner Error", str(e), page)
            finally:
                stop_event.set()
                await browser.close()
                await log_task

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
        report_file = self.results_dir / f"test_result_{timestamp_str}.md"
        with open(report_file, "w") as f:
            self._write_report_header(f, timestamp)
            self._write_component_list(f)
            self._write_screenshot_list(f)
            if self.failures:
                self._write_failures(f)
                self._write_logs_and_prompt(f)
            else:
                f.write("✅ All tests passed successfully.\n")
        print(f"Report generated: {report_file}")

    async def test_page(self, page, url):
        """Test a specific page including basic interactions."""
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        
        try:
            print(f"Testing Page: {url}")
            await page.goto(url)
            await page.wait_for_load_state("networkidle")
            await asyncio.sleep(1) # Wait for HTMX/Alpine transitions
            
            # Capture per-page screenshot
            page_name = url.split("/")[-1] or "dashboard"
            await self.capture_screenshot(page, f"page_{page_name}")
            
            # Check for errors
            content = await page.content()
            if "Internal Server Error" in content or "500" in page.url:
                await self.record_failure(f"HTTP 500 on {url}", "Server returned error", page)
                return
            
            # Check if redirected to login
            if "/login" in page.url:
                await self.record_failure(f"Auth Refused: {url}", "Redirected to login page. Session might be invalid.", page)
                return

            # Perform common interactions
            await self.interact_with_page(page, url)

        except Exception as e:
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
        screenshot_path = self.results_dir / f"failure_{timestamp}.png"
        
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
        print(f"FAILURE: {title} - {message}")

    def generate_report(self):
        timestamp_now = datetime.datetime.now()
        timestamp = timestamp_now.strftime("%Y-%m-%d %H:%M:%S")
        timestamp_str = timestamp_now.strftime("%Y%m%d_%H%M%S")
        report_file = self.results_dir / f"test_result_{timestamp_str}.md"
        
        with open(report_file, "w") as f:
            f.write(f"# YADS GUI Test Report - {timestamp}\n\n")
            f.write(f"- **Target:** {self.target_url}\n")
            f.write(f"- **YADS Version:** {self.version}\n")
            f.write(f"- **Tests Run:** {len(self.visited_urls)}\n")
            f.write(f"- **Failures:** {len(self.failures)}\n\n")
            
            # --- Component List ---
            f.write("## Tested Components\n\n")
            for url in sorted(list(self.visited_urls)):
                # Skip the base URL itself in the list
                if url == self.target_url or url == f"{self.target_url}/":
                    continue
                path = url.replace(self.target_url, "")
                if not path: path = "/"
                
                # Check for failure on this URL
                failed = any(f["url"] == url for f in self.failures)
                status = "❌" if failed else "✅"
                f.write(f"- {status} `{path}`\n")
            f.write("\n")
            
            # --- Session Screenshots ---
            f.write("## Session Screenshots\n\n")
            f.write(f"All screenshots for this session are stored in: `{self.screenshot_dir.relative_to(self.results_dir.parent.parent)}`\n\n")
            
            screenshot_files = sorted(list(self.screenshot_dir.glob("*.png")))
            if screenshot_files:
                for shot in screenshot_files:
                    f.write(f"- [{shot.name}]({shot.relative_to(self.results_dir)})\n")
            else:
                f.write("No screenshots captured.\n")
            f.write("\n")
            
            if self.failures:
                f.write("## Failures\n\n")
                for fail in self.failures:
                    f.write(f"### {fail['title']}\n")
                    f.write(f"- **URL:** {fail['url']}\n")
                    f.write(f"- **Message:** {fail['message']}\n")
                    f.write(f"- **Timestamp:** {fail['timestamp']}\n")
                    f.write(f"![Failure Screenshot]({fail['screenshot']})\n\n")
                    
                f.write("## System Logs (Relevant Snippet)\n\n")
                f.write("```\n")
                # Write last 50 lines of logs
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
            else:
                f.write("✅ All tests passed successfully.\n")

        print(f"Report generated: {report_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://dana:8085")
    parser.add_argument("--dana-host", default="dana")
    args = parser.parse_args()
    
    runner = GuiTestRunner(args.url, dana_host=args.dana_host)
    asyncio.run(runner.run_tests())
