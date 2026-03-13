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
        self.results_dir = Path("tests/results")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logs = []
        self.failures = []
        self.visited_urls = set()

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

    async def run_tests(self):
        if not await self.ensure_dana_running():
            print("Aborting tests due to environment failure.")
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
                
                if await page.query_selector("input[name='username']"):
                    print("Attempting login...")
                    await page.fill("input[name='username']", "admin")
                    await page.fill("input[name='password']", "admin")
                    await page.click("button[type='submit']")
                    await page.wait_for_load_state("networkidle")

                # 1b. Handle Force Password Change
                if "change-password" in page.url or await page.query_selector("input[name='new_password']"):
                    print("Force password change detected. Updating...")
                    await page.fill("input[name='new_password']", "adminAdmin123!")
                    await page.fill("input[name='confirm_password']", "adminAdmin123!")
                    await page.click("button[type='submit']")
                    await page.wait_for_load_state("networkidle")

                # 2. Extract Sidebar Links
                try:
                    await page.wait_for_selector("aside", timeout=10000)
                except:
                    print("Warning: Sidebar (aside) not found within timeout.")
                
                await page.screenshot(path="static/screenshots/debug_dashboard.png")
                
                sidebar_links = await self.get_sidebar_links(page)
                print(f"Discovered {len(sidebar_links)} sidebar sections.")

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
        """Extract all navigation links from the sidebar."""
        links = []
        try:
            # Sidebar is typically in <aside>
            nav_elements = await page.query_selector_all("aside a")
            for nav in nav_elements:
                href = await nav.get_attribute("href")
                if href and href.startswith("/") and not href.startswith("//"):
                    full_url = self.target_url.rstrip("/") + href
                    links.append(full_url)
        except Exception as e:
            print(f"Warning: Failed to extract sidebar links: {e}")
        return list(dict.fromkeys(links)) # Deduplicate

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
            
            # Check for errors
            content = await page.content()
            if "Internal Server Error" in content or "500" in page.url:
                await self.record_failure(f"HTTP 500 on {url}", "Server returned error", page)
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
            await page.screenshot(path=screenshot_path)
        except Exception:
            print("Failed to capture screenshot.")

        self.failures.append({
            "title": title,
            "message": message,
            "url": page.url,
            "timestamp": timestamp,
            "screenshot": str(screenshot_path)
        })
        print(f"FAILURE: {title} - {message}")

    def generate_report(self):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_file = self.results_dir / f"test_result_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(report_file, "w") as f:
            f.write(f"# YADS GUI Test Report - {timestamp}\n\n")
            f.write(f"- **Target:** {self.target_url}\n")
            f.write(f"- **Tests Run:** {len(self.visited_urls)}\n")
            f.write(f"- **Failures:** {len(self.failures)}\n\n")
            
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
