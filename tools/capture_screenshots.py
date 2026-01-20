
from playwright.sync_api import sync_playwright
import time
import os

BASE_URL = "http://localhost:8000"
USERNAME = "admin"
PASSWORD = "admin"
OUTPUT_DIR = "product_screenshots"

def capture():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # Grant permissions or set viewport if needed
        context = browser.new_context(viewport={"width": 1920, "height": 1080})
        page = context.new_page()

        # Login
        print("Logging in...")
        page.goto(f"{BASE_URL}/login")
        if "login" in page.url:
            page.fill('input[name="username"]', USERNAME)
            page.fill('input[name="password"]', PASSWORD)
            page.click('button[type="submit"]')
            page.wait_for_url(f"{BASE_URL}/")
        print("Logged in.")

        # 1. Dashboard Dark (Default)
        print("Capturing Dashboard Dark...")
        page.goto(f"{BASE_URL}/")
        time.sleep(2) # Wait for charts/widgets
        page.screenshot(path=f"{OUTPUT_DIR}/dashboard_dark.png")

        # 2. Dashboard Light
        print("Capturing Dashboard Light...")
        page.evaluate("document.documentElement.classList.remove('dark')")
        time.sleep(0.5)
        page.screenshot(path=f"{OUTPUT_DIR}/dashboard_light.png")
        # Reset to dark
        page.evaluate("document.documentElement.classList.add('dark')")

        # 3. Network Graph
        print("Capturing Network Graph...")
        page.goto(f"{BASE_URL}/visualizations/network")
        page.wait_for_selector("#cy")
        time.sleep(3) # Wait for graph to settle
        page.screenshot(path=f"{OUTPUT_DIR}/network_graph.png")

        # 4. Attack Path
        print("Capturing Attack Path...")
        # Check the toggle
        toggle = page.query_selector("#attackPathToggle")
        if toggle:
            toggle.check()
            time.sleep(2) # Wait for styling change
            page.screenshot(path=f"{OUTPUT_DIR}/network_attack_path.png")
        else:
            print("Warning: Attack Path toggle not found!")

        # 5. Tech Radar
        print("Capturing Tech Radar...")
        page.goto(f"{BASE_URL}/analytics/tech-radar")
        time.sleep(2)
        page.screenshot(path=f"{OUTPUT_DIR}/tech_radar.png")

        # 6. Hijacking
        print("Capturing Hijacking...")
        page.goto(f"{BASE_URL}/analytics/hijacking")
        time.sleep(2)
        page.screenshot(path=f"{OUTPUT_DIR}/hijacking.png")

        browser.close()
        print("Done.")

if __name__ == "__main__":
    capture()
