import re
from bs4 import BeautifulSoup

html_path = '/home/mrmarco/Documents/gitlab/yads/yads_summary_static.html'
output_path = '/home/mrmarco/Documents/gitlab/yads/yads_summary_static.html'

with open(html_path, 'r', encoding='utf-8') as f:
    html_content = f.read()

soup = BeautifulSoup(html_content, 'html.parser')

# Find original style if it still exists in the head (it might have been mutated)
# Let's try to find the full style block from the original file if needed, 
# but let's assume it's in the head of yads_summary_static.html for now.
# Actually, I'll read yads_summary.html for the clean CSS.
original_html_path = '/home/mrmarco/Documents/gitlab/yads/yads_summary.html'
with open(original_html_path, 'r', encoding='utf-8') as f:
    orig_content = f.read()
orig_soup = BeautifulSoup(orig_content, 'html.parser')
style_tag = orig_soup.find('style')
css_text = style_tag.string

# 1. Resolve Variables
# Extract :root variables
root_match = re.search(r':root\s*\{([^}]+)\}', css_text, re.DOTALL)
variables = {}
if root_match:
    var_lines = root_match.group(1).split(';')
    for line in var_lines:
        if ':' in line:
            name, value = line.split(':', 1)
            variables[name.strip()] = value.strip()

# Resolve variable references in other variables
for _ in range(3): # Simple iteration to resolve nested vars like --accent-gradient
    for name, value in variables.items():
        for v_name, v_val in variables.items():
            if f'var({v_name})' in value:
                variables[name] = value.replace(f'var({v_name})', v_val)

# Replace all var() in CSS
for name, value in variables.items():
    css_text = css_text.replace(f'var({name})', value)

# 2. Extract Rules
# This is a simple parser for rules like ".class { prop: val; }"
rules = []
# Match rules (ignoring media queries for now)
# We use a non-greedy match for the content to avoid gobbling multiple rules
raw_rules = re.findall(r'([^{]+)\{([^}]+)\}', css_text)
for selector, body in raw_rules:
    selector = selector.strip()
    if selector.startswith('@media') or selector.startswith(':root'):
        continue
    body = body.strip().replace('\n', ' ').replace('  ', ' ')
    # Split multiple selectors
    for sub_sel in selector.split(','):
        rules.append((sub_sel.strip(), body))

# 3. Apply Rules
# Priority: Tags < Classes (simplified)
# We'll apply tags first, then classes
tag_rules = [r for r in rules if re.match(r'^[a-z0-9]+$', r[0])]
other_rules = [r for r in rules if not re.match(r'^[a-z0-9]+$', r[0])]

def apply_styles(sel, styles):
    try:
        elements = soup.select(sel)
        for el in elements:
            existing = el.get('style', '')
            if existing and not existing.strip().endswith(';'):
                existing += ';'
            el['style'] = (existing + ' ' + styles).strip()
    except Exception as e:
        print(f"Error applying {sel}: {e}")

# Reset all styles in soup first to avoid duplicates from previous runs
for el in soup.find_all(style=True):
    del el['style']

for sel, styles in tag_rules:
    apply_styles(sel, styles)
for sel, styles in other_rules:
    # Handle pseudo-classes - we'll just ignore them for inlining as they aren't supported
    if ':' in sel: continue
    apply_styles(sel, styles)

# 4. Clean up style tag
# Keep only media queries
media_queries = re.findall(r'@media[^{]+\{(?:[^{}]+\{[^{}]+\})*\s*\}', css_text, re.DOTALL)
new_style_tag = soup.find('style')
if not new_style_tag:
    new_style_tag = soup.new_tag('style')
    soup.head.append(new_style_tag)

if media_queries:
    new_style_tag.string = "\n".join(media_queries)
else:
    new_style_tag.decompose()

# 5. Fix logo scaling - the user asked for 400%
# The 180px x 180px is already "large" but I'll make sure it's explicitly set
logo_img = soup.find('img', class_='logo-image')
if logo_img:
    logo_img['style'] = logo_img.get('style', '') + ' width: 180px !important; height: 180px !important;'

with open(output_path, 'w', encoding='utf-8') as f:
    f.write(soup.prettify())
