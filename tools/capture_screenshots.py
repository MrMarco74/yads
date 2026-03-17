import asyncio
import os
from playwright.async_api import async_playwright

async def capture():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(viewport={'width': 1280, 'height': 720})
        page = await context.new_page()

        print("[*] Navigating to YADS login...")
        await page.goto("http://localhost:8085/login", wait_until="networkidle")
        
        # Login
        print("[*] Filling login form...")
        await page.fill('input[name="username"]', "admin")
        await page.fill('input[name="password"]', "admin")
        
        print("[*] Submitting login...")
        await asyncio.gather(
            page.wait_for_load_state("networkidle"),
            page.click('button[type="submit"]')
        )
        print(f"[*] Current URL: {page.url}")

        # Ensure Dark Mode
        print("[*] Setting Dark Mode...")
        await page.evaluate("document.documentElement.classList.add('dark')")
        await asyncio.sleep(2)

        # 1. Dashboard screenshot
        print("[*] Capturing Dashboard...")
        await page.goto("http://localhost:8085/", wait_until="networkidle")
        await page.screenshot(path="/app/screenshots/dashboard.png", full_page=True)
        
        # 2. Targets Table
        print("[*] Capturing Targets Table...")
        await page.goto("http://localhost:8085/targets/table", wait_until="networkidle")
        await page.screenshot(path="/app/screenshots/targets.png", full_page=True)
        
        # 3. Findings for DVWA
        print("[*] Capturing Findings for DVWA...")
        await page.goto("http://localhost:8085/targets/1", wait_until="networkidle")
        await page.screenshot(path="/app/screenshots/findings.png", full_page=True)

        await browser.close()
        print("[+] Screenshots captured in /app/screenshots/")

if __name__ == "__main__":
    os.makedirs("/app/screenshots", exist_ok=True)
    asyncio.run(capture())
