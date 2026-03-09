import re
from bs4 import BeautifulSoup

html_path = '/home/mrmarco/Documents/gitlab/yads/yads_summary_static.html'
output_path = '/home/mrmarco/Documents/gitlab/yads/yads_summary_static.html'

with open(html_path, 'r', encoding='utf-8') as f:
    html_content = f.read()

# Fix the extra brace first
html_content = html_content.replace('@media (max-width: 768px) {\n        }\n    }\n    </style>', '@media (max-width: 768px) {\n        }\n    </style>')

soup = BeautifulSoup(html_content, 'html.parser')
style_tag = soup.find('style')

if style_tag:
    css_text = style_tag.string
    # Simple CSS parser for class selectors
    # Matches .classname { ... }
    rules = re.findall(r'\.([a-zA-Z0-9_-]+)\s*\{([^}]+)\}', css_text)
    
    for class_name, styles in rules:
        elements = soup.find_all(class_=class_name)
        for el in elements:
            existing_style = el.get('style', '')
            # Strip whitespace and normalize
            new_styles = styles.strip().replace('\n', ' ').replace('  ', ' ')
            if existing_style and not existing_style.endswith(';'):
                existing_style += ';'
            el['style'] = (existing_style + ' ' + new_styles).strip()

    # Also handle some basic tag selectors like h1, h2, table, etc.
    tags_to_inline = ['h1', 'h2', 'h3', 'table', 'th', 'td', 'body', 'header', 'footer', 'section', 'div', 'p', 'span', 'ul', 'li']
    for tag in tags_to_inline:
        tag_rules = re.findall(rf'^{tag}\s*\{{([^}}]+)\}}', css_text, re.MULTILINE)
        for styles in tag_rules:
            elements = soup.find_all(tag)
            for el in elements:
                existing_style = el.get('style', '')
                new_styles = styles.strip().replace('\n', ' ').replace('  ', ' ')
                if existing_style and not existing_style.endswith(';'):
                    existing_style += ';'
                el['style'] = (existing_style + ' ' + new_styles).strip()

    # Remove the style tag after inlining (optional, but requested for 'static')
    # style_tag.decompose()

with open(output_path, 'w', encoding='utf-8') as f:
    f.write(str(soup))
