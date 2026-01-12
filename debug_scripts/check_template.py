import re

def check_template_tags(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()

    stack = []
    
    # Simple regex for block start/end
    # Captures tag name: if, for, block, etc.
    start_tag_re = re.compile(r'{%\s*(if|for|block|macro|call)\s+')
    end_tag_re = re.compile(r'{%\s*end(if|for|block|macro|call)\s*%}')
    
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Check for start tags
        starts = start_tag_re.findall(line)
        for tag in starts:
            stack.append((tag, line_num))
            # print(f"Lines {line_num}: Opened {tag}")

        # Check for end tags
        ends = end_tag_re.findall(line)
        for tag in ends:
            if not stack:
                print(f"Error at line {line_num}: Found {{% end{tag} %}} but no block is open.")
                return

            last_tag, last_line = stack.pop()
            if tag != last_tag:
                print(f"Error at line {line_num}: Found {{% end{tag} %}} but expected {{% end{last_tag} %}} (opened at line {last_line}).")
                return
            # print(f"Lines {line_num}: Closed {tag} (opened at {last_line})")

    if stack:
        print("Error: Unclosed blocks remaining at end of file:")
        for tag, line_num in stack:
            print(f"  - {tag} opened at line {line_num}")
    else:
        print("Success: All blocks balanced.")

if __name__ == "__main__":
    check_template_tags("yads/api/templates/target_detail.html")
