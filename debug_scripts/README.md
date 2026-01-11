# Debug and Maintenance Scripts

This directory contains various scripts for debugging, testing, and maintaining the YADS application.

## How to Run

To run these scripts, execute them from the **project root directory** to ensure Python can resolve the `yads` package imports correctly.

**Example:**

```bash
# Correct way (from project root)
python debug_scripts/run_debug.py
python debug_scripts/test_analytics.py

# Incorrect way (do not do this)
cd debug_scripts
python run_debug.py
```

## Contents

- **debug_*.py**: Scripts for debugging specific features or modules.
- **test_*.py**: Manual integration tests or verification scripts.
- **verify_*.py**: Scripts to verify system integrity or specific bug fixes.
- **check_*.py**: Quick checks for system status, database consistency, etc.
- **repair_*.py**: Scripts to fix known issues in data or configuration.
