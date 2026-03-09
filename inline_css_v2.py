import re
from bs4 import BeautifulSoup

html_path = '/home/mrmarco/Documents/gitlab/yads/yads_summary_static.html'
output_path = '/home/mrmarco/Documents/gitlab/yads/yads_summary_static.html'

with open(html_path, 'r', encoding='utf-8') as f:
    html_content = f.read()

soup = BeautifulSoup(html_content, 'html.parser')
style_tag = soup.find('style')

if style_tag:
    css_text = style_tag.string
    
    # 1. Clean up CSS - remove media queries for inlining (they can't be inlined)
    # But wait, we should keep the style tag but ONLY with media queries if we can't inline them.
    # For now, let's just inline everything we can and keep the media queries in the style tag.
    
    # Match basic class selectors
    class_rules = re.findall(r'\.([a-zA-Z0-9_-]+)\s*\{([^}]+)\}', css_text)
    for class_name, styles in class_rules:
        elements = soup.find_all(class_=class_name)
        for el in elements:
            existing_style = el.get('style', '')
            new_styles = styles.strip().replace('\n', ' ').replace('  ', ' ')
            if existing_style and not existing_style.endswith(';'):
                existing_style += ';'
            el['style'] = (existing_style + ' ' + new_styles).strip()

    # Match tag selectors
    tag_selectors = ['body', 'header', 'footer', 'h1', 'h2', 'h3', 'table', 'th', 'td', 'p', 'span', 'ul', 'li', 'div', 'a']
    for tag in tag_selectors:
        # Regex to find tag styles, ensuring it's not a class or inside a media query
        # This is a bit rough but works for simple CSS
        tag_rules = re.findall(rf'^{tag}\s*\{{([^}}]+)\}}', css_text, re.MULTILINE)
        for styles in tag_rules:
            elements = soup.find_all(tag)
            for el in elements:
                existing_style = el.get('style', '')
                new_styles = styles.strip().replace('\n', ' ').replace('  ', ' ')
                if existing_style and not existing_style.endswith(';'):
                    existing_style += ';'
                el['style'] = (existing_style + ' ' + new_styles).strip()

    # Keep only media queries in the style tag
    media_queries = re.findall(r'@media[^{]+\{(?:[^{}]+\{[^{}]+\})*\s*\}', css_text, re.DOTALL)
    if media_queries:
        style_tag.string = "\n".join(media_queries)
    else:
        style_tag.decompose()

with open(output_path, 'w', encoding='utf-8') as f:
    f.write(soup.prettify())
