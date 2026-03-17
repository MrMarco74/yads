#!/bin/bash
# Wartet bis MinIO bereit ist und erstellt den WORM-Bucket für Log-Retention
sleep 10
mc alias set local http://minio:9000 minioadmin minioadmin123
mc mb local/yads-logs-cold --ignore-existing
mc ilm add local/yads-logs-cold --expiry-days 1825  # 5 Jahre = 1825 Tage
echo "MinIO bucket yads-logs-cold created with 5-year retention"
