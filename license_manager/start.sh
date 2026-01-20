#!/bin/bash

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PATH="$SCRIPT_DIR/license_manager_gui.py"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== YADS License Manager GUI ===${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not found.${NC}"
    read -p "Press Enter to exit..."
    exit 1
fi

# Check Dependencies
echo "Checking dependencies..."
python3 -c "import cryptography" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing required library: cryptography..."
    pip3 install cryptography
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install dependencies. Please run 'pip3 install cryptography' manually.${NC}"
        read -p "Press Enter to exit..."
        exit 1
    fi
fi

# Run
echo "Starting GUI..."
python3 "$APP_PATH"
