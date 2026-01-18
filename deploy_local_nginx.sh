#!/bin/bash

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit 1
fi

PROJECT_DIR="/home/mrmarco/Documents/gitlab/yads"
CONFIG_SRC="$PROJECT_DIR/nginx_yads.conf"
NGINX_AVAIL="/etc/nginx/sites-available/yads-local"
NGINX_ENAB="/etc/nginx/sites-enabled/yads-local"

echo "Deploying YADS Homepage to Nginx..."

# 1. Install Configuration
cp "$CONFIG_SRC" "$NGINX_AVAIL"
ln -sf "$NGINX_AVAIL" "$NGINX_ENAB"
echo "✅ Configuration linked to sites-enabled."

# 2. Fix Permissions for Nginx Access (www-data needs scan rights)
# We give otherusers execute (+x) permission to traverse to the folder
echo "Adjusting permissions for Nginx access..."
chmod o+x /home
chmod o+x /home/mrmarco
chmod o+x /home/mrmarco/Documents
chmod o+x /home/mrmarco/Documents/gitlab
chmod o+x /home/mrmarco/Documents/gitlab/yads
# Files need read permission
chmod -R o+rX "$PROJECT_DIR/yads-homepage"

echo "✅ Permissions updated."

# 3. Test and Restart Nginx
nginx -t
if [ $? -eq 0 ]; then
    systemctl restart nginx
    echo "✅ Nginx restarted successfully."
    echo "🌍 Site available at: http://localhost:8082"
else
    echo "❌ Nginx configuration test failed. Please check errors above."
    exit 1
fi
