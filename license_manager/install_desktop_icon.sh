#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICON_PATH="$SCRIPT_DIR/logo.png"
EXEC_PATH="$SCRIPT_DIR/start.sh"
DESKTOP_FILE_NAME="yads-license-manager.desktop"
INSTALL_DIR="$HOME/.local/share/applications"

# Ensure Install Directory exists
mkdir -p "$INSTALL_DIR"

# Generate the .desktop file content
cat > "$SCRIPT_DIR/$DESKTOP_FILE_NAME" << EOL
[Desktop Entry]
Version=1.0
Type=Application
Name=YADS License Manager
Comment=Manage Licenses for YADS Security Platform
Exec="$EXEC_PATH"
Icon=$ICON_PATH
Terminal=false
Categories=Development;Utility;Security;
StartupNotify=true
EOL

# Install (Copy) to user applications
cp "$SCRIPT_DIR/$DESKTOP_FILE_NAME" "$INSTALL_DIR/$DESKTOP_FILE_NAME"
chmod +x "$INSTALL_DIR/$DESKTOP_FILE_NAME"

echo "--------------------------------------------------------"
echo "Desktop Entry Created!"
echo "Name: YADS License Manager"
echo "Icon: $ICON_PATH"
echo "Exec: $EXEC_PATH"
echo "--------------------------------------------------------"
echo "You can now find 'YADS License Manager' in your start menu."
echo "If it doesn't appear immediately, try logging out and back in."
