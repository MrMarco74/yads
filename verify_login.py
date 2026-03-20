#!/usr/bin/env python3
import sys
import asyncio
from playwright.async_api import async_playwright

async def verify_login(url, username, password):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        
        print(f"Navigating to {url}...")
        await page.goto(url)
        
        # Check if we are on the login page
        if "/login" not in page.url:
            print(f"Error: Not on login page. Current URL: {page.url}")
            await browser.close()
            return False
            
        print(f"Logging in as {username}...")
        await page.fill("input[name='username']", username)
        await page.fill("input[name='password']", password)
        await page.click("button[type='submit']")
        
        # Wait for navigation or change
        await page.wait_for_timeout(2000)
        
        print(f"After login URL: {page.url}")
        
        # Check for MFA setup redirect (new user) or MFA code prompt (existing user with MFA)
        # Based on auth.py, new users are redirected to /mfa/setup
        if "/mfa/setup" in page.url:
            print("SUCCESS: Reached MFA Setup screen.")
            await browser.close()
            return True
        elif "mfa_required" in await page.content():
            print("SUCCESS: Reached MFA Code prompt.")
            await browser.close()
            return True
        elif "/login" in page.url and "error" in await page.content():
            print(f"FAILURE: Login failed. Page content: {await page.content()}")
            await browser.close()
            return False
        else:
            print(f"WARNING: Unexpected URL after login: {page.url}")
            await browser.close()
            return "unknown"

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 verify_login.py <url> <username> <password>")
        sys.exit(1)
        
    url, user, pw = sys.argv[1:4]
    result = asyncio.run(verify_login(url, user, pw))
    sys.exit(0 if result is True else 1)
