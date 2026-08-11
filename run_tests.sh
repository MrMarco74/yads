#!/usr/bin/env bash
set -e

echo "=== Running YADS Unit & Integration Tests ==="
python3 -m unittest discover -s tests -p "test_*.py"
echo "=== All Tests Passed Successfully ==="
