#!/usr/bin/env python3
"""
YADS GUI Reconnaissance Runner
Identifies new/changed links and functions (interactive elements) and generates LLM prompts.
"""

import os
import sys
import asyncio
import argparse
import datetime
import json
from pathlib import Path
from playwright.async_api import async_playwright

class GuiReconRunner:
    def __init__(self, target_url, dana_host="dana", dana_user="root"):
        self.target_url = target_url.rstrip("/")
        self.dana_host = dana_host
        self.dana_user = dana_user
        self.recon_dir = Path("tests/recon")
        self.recon_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_file = self.recon_dir / "baseline.json"
        self.current_findings = {
            "links": [],
            "pages": {} # url -> { buttons: [] }
        }
        self.visited_urls = set()

    async def run_recon(self):
        print(f"Starting GUI Reconnaissance on {self.target_url}")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport={'width': 1280, 'height': 800})
            page = await context.new_page()

            try:
                # 1. Login & Handle Setup
                await page.goto(self.target_url)
                await page.wait_for_load_state("networkidle")
                
                if await page.query_selector("input[name='username']"):
                    print("Logging in...")
                    await page.fill("input[name='username']", "admin")
                    await page.fill("input[name='password']", "adminAdmin123!")
                    await page.click("button[type='submit']")
                    await page.wait_for_load_state("networkidle")

                if "change-password" in page.url:
                    await page.fill("input[name='new_password']", "adminAdmin123!")
                    await page.fill("input[name='confirm_password']", "adminAdmin123!")
                    await page.click("button[type='submit']")
                    await page.wait_for_load_state("networkidle")

                # 2. Extract Sidebar Links
                await page.wait_for_selector("aside", timeout=10000)
                nav_elements = await page.query_selector_all("aside a")
                for nav in nav_elements:
                    href = await nav.get_attribute("href")
                    if href and href.startswith("/") and not href.startswith("//"):
                        self.current_findings["links"].append(href)
                self.current_findings["links"] = sorted(list(set(self.current_findings["links"])))
                
                print(f"Found {len(self.current_findings['links'])} unique internal links.")

                # 3. Explore Pages
                for href in self.current_findings["links"]:
                    url = self.target_url + href
                    await self.explore_page(page, url, href)

                # 4. Compare with Baseline & Report
                self.process_results()

            except Exception as e:
                print(f"CRITICAL ERROR: {e}")
            finally:
                await browser.close()

    async def explore_page(self, page, url, href):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        
        try:
            print(f"Scanning Page: {href}")
            await page.goto(url)
            await page.wait_for_load_state("networkidle")
            await asyncio.sleep(0.5)

            # Find interactive elements (Buttons)
            buttons = await page.query_selector_all("button")
            found_buttons = []
            for btn in buttons:
                try:
                    if await btn.is_visible():
                        inner_text = (await btn.inner_text()).strip()
                        if inner_text:
                            found_buttons.append(inner_text)
                except:
                    continue
            
            self.current_findings["pages"][href] = {
                "buttons": sorted(list(set(found_buttons)))
            }
        except Exception as e:
            print(f"Error exploring {href}: {e}")

    def process_results(self):
        baseline = {}
        if self.baseline_file.exists():
            with open(self.baseline_file, "r") as f:
                baseline = json.load(f)
        
        if not baseline:
            print("No baseline found. Saving current findings as baseline.")
            with open(self.baseline_file, "w") as f:
                json.dump(self.current_findings, f, indent=2)
            return

        # Comparison Logic
        diffs = {
            "new_links": [],
            "removed_links": [],
            "changed_pages": {} # href -> { new_buttons, removed_buttons }
        }

        # Links
        old_links = set(baseline.get("links", []))
        new_links = set(self.current_findings["links"])
        
        diffs["new_links"] = sorted(list(new_links - old_links))
        diffs["removed_links"] = sorted(list(old_links - new_links))

        # Pages/Buttons
        old_pages = baseline.get("pages", {})
        for href, data in self.current_findings["pages"].items():
            if href in old_pages:
                old_btns = set(old_pages[href].get("buttons", []))
                cur_btns = set(data.get("buttons", []))
                
                added = sorted(list(cur_btns - old_btns))
                removed = sorted(list(old_btns - cur_btns))
                
                if added or removed:
                    diffs["changed_pages"][href] = {
                        "added_buttons": added,
                        "removed_buttons": removed
                    }
            elif href not in diffs["new_links"]:
                # Should normally be in new_links, but just in case
                diffs["changed_pages"][href] = {
                    "added_buttons": data.get("buttons", []),
                    "removed_buttons": []
                }

        if any(v for v in diffs.values()):
            self.generate_report(diffs)
            # Update baseline
            with open(self.baseline_file, "w") as f:
                json.dump(self.current_findings, f, indent=2)
        else:
            print("No changes detected since last reconnaissance.")

    def generate_report(self, diffs):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.recon_dir / f"recon_report_{timestamp}.md"
        
        with open(report_file, "w") as f:
            f.write(f"# GUI Reconnaissance Report - {datetime.datetime.now()}\n\n")
            
            if diffs["new_links"]:
                f.write("## 🆕 Neue Links gefunden\n")
                for l in diffs["new_links"]:
                    f.write(f"- `{l}`\n")
                f.write("\n")

            if diffs["removed_links"]:
                f.write("## 🗑️ Entfernte Links\n")
                for l in diffs["removed_links"]:
                    f.write(f"- `{l}`\n")
                f.write("\n")

            if diffs["changed_pages"]:
                f.write("## 📝 Geänderte Funktionen auf Seiten\n")
                for href, change in diffs["changed_pages"].items():
                    f.write(f"### Seite: `{href}`\n")
                    if change["added_buttons"]:
                        f.write("- **Neu:** " + ", ".join([f"`{b}`" for b in change["added_buttons"]]) + "\n")
                    if change["removed_buttons"]:
                        f.write("- **Gegangen:** " + ", ".join([f"`{b}`" for b in change["removed_buttons"]]) + "\n")
                    f.write("\n")

            f.write("## 🤖 AI Update Prompt\n\n")
            f.write("> [!IMPORTANT]\n")
            f.write("> Nutze diesen Prompt, um die Test-Suite zu aktualisieren.\n\n")
            f.write("```text\n")
            f.write("Die YADS GUI-Struktur hat sich geändert. Bitte aktualisiere die Test-Logik basierend auf diesen Änderungen:\n\n")
            f.write(f"Änderungen:\n{json.dumps(diffs, indent=2)}\n\n")
            f.write("Aufgaben:\n")
            f.write("1. Analysiere, ob neue Tests für die neuen Links/Buttons nötig sind.\n")
            f.write("2. Entferne veraltete Tests für gelöschte Elemente.\n")
            f.write("3. Passe bestehende Interaktionen an.\n")
            f.write("```\n")

        print(f"Recon report generated: {report_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://172.30.0.250:8085")
    parser.add_argument("--dana-host", default="dana")
    args = parser.parse_args()
    
    runner = GuiReconRunner(args.url, dana_host=args.dana_host)
    asyncio.run(runner.run_recon())
