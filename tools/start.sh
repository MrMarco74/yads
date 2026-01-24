#!/bin/bash

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PATH="$SCRIPT_DIR/release_gui.py"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== YADS Release Manager GUI ===${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not found.${NC}"
    read -p "Press Enter to exit..."
    exit 1
fi

# Virtual Environment Setup
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate
source "$VENV_DIR/bin/activate"

# Check & Install Requirements
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    echo "Checking dependencies..."
    pip install -q --upgrade pip
    pip install -q -r "$SCRIPT_DIR/requirements.txt"
else
    echo -e "${RED}Warning: requirements.txt not found in $SCRIPT_DIR${NC}"
fi

# Run
echo "Starting GUI..."
python3 "$APP_PATH"
