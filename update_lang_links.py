import os
import glob

def update_de_files():
    files = glob.glob('/home/mrmarco/Documents/gitlab/yads/yads-homepage/de/*.html')
    for file_path in files:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Replace /en/ with root for .com links
        new_content = content.replace('https://yads-security.com/en/', 'https://yads-security.com/')
        
        if content != new_content:
            with open(file_path, 'w') as f:
                f.write(new_content)
            print(f"Updated {file_path}")

def update_en_files():
    files = glob.glob('/home/mrmarco/Documents/gitlab/yads/yads-homepage/en/*.html')
    for file_path in files:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Replace .com/en/ with .de/ (root) and update flag
        # Current: <a href="https://yads-security.com/en/index.html" ...>🇺🇸 EN</a>
        # Target: <a href="https://yads-security.de/index.html" ...>🇩🇪 DE</a>
        
        new_content = content.replace('https://yads-security.com/en/', 'https://yads-security.de/')
        new_content = new_content.replace('🇺🇸 EN', '🇩🇪 DE')
        
        if content != new_content:
            with open(file_path, 'w') as f:
                f.write(new_content)
            print(f"Updated {file_path}")

if __name__ == '__main__':
    print("Updating DE files...")
    update_de_files()
    print("Updating EN files...")
    update_en_files()
