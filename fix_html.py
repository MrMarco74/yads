import sys
import base64

html_path = '/home/mrmarco/Documents/gitlab/yads/yads_summary.html'
logo_base64_path = '/home/mrmarco/Documents/gitlab/yads/logo_base64.txt'
output_path = '/home/mrmarco/Documents/gitlab/yads/yads_summary_static.html'

with open(html_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Line numbers are 1-indexed in the tool output, 0-indexed here.
# 314: @media (max-width: 768px) {
# 315:     h1 { font-size: 1.8rem; }
# 316-318: corruption
# 319: </style>

# Let's fix the CSS block first.
# We want to remove 316, 317, 318.
# And ensure 314, 315 are closed.
fixed_lines = lines[:315] # Keep up to line 315 (index 314)
fixed_lines.append("        }\n") # Close h1
fixed_lines.append("    }\n") # Close @media
fixed_lines.append("    </style>\n") # Close style (was at 319)

# Now skip the corruption and look for the start of body
# 320: </head>
# 321: <body>
# 322: <div class="container">
# 323: <header>
# 324: <div class="logo-container">
# 325: <!-- Relative path for local file browsing -->
# 326: alt="YADS Logo" class="logo-image" ...
# 327: <div class="logo-placeholder" style="display:none">Y</div>

# We want to replace line 326 with a proper <img> tag using the Base64 logo.
with open(logo_base64_path, 'r') as f:
    logo_base64 = f.read().strip()

logo_img_tag = f'                <img src="data:image/png;base64,{logo_base64}" alt="YADS Logo" class="logo-image" style="width: 160px; height: auto;">\n'

# We'll construct the rest of the file.
# Skip lines 316 to 326 (indices 315 to 325)
fixed_lines.extend(lines[319:325]) # 320 to 325 (indices 319 to 324)
fixed_lines.append(logo_img_tag)
fixed_lines.extend(lines[326:]) # From 327 onwards

with open(output_path, 'w', encoding='utf-8') as f:
    f.writelines(fixed_lines)

