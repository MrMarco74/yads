import os

HOMEPAGE_DIR = "yads-homepage"
BASE_URL = "https://yads-security.com"

# Mappings for replacement
# We handle both ../ (from subdirs) and direct (from root) just in case
REPLACEMENTS = {
    '../css/': f'{BASE_URL}/css/',
    '../images/': f'{BASE_URL}/images/',
    '../scripts/': f'{BASE_URL}/scripts/',
    '../fonts/': f'{BASE_URL}/fonts/',
    '"css/': f'"{BASE_URL}/css/',
    '"images/': f'"{BASE_URL}/images/',
    '"scripts/': f'"{BASE_URL}/scripts/',
    '"fonts/': f'"{BASE_URL}/fonts/',
}

def update_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    for old, new in REPLACEMENTS.items():
        content = content.replace(old, new)
        
    if content != original_content:
        print(f"Updating {filepath}")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

def main():
    if not os.path.exists(HOMEPAGE_DIR):
        print(f"Directory {HOMEPAGE_DIR} not found.")
        return

    for root, dirs, files in os.walk(HOMEPAGE_DIR):
        for file in files:
            if file.endswith(".html"):
                update_file(os.path.join(root, file))

if __name__ == "__main__":
    main()
