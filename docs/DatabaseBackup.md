# Database Backup System

## Architecture

YADS uses a dedicated Docker container (`yads-backup`) running alongside the database to perform automated PostgreSQL backups. The container uses `postgres:15-alpine` to guarantee `pg_dump` version compatibility and BusyBox `crond` for scheduling.

```
yads-backup (crond) → pg_dump → /backups/ (Hetzner Storage Box)
```

Backups are stored on the Hetzner Storage Box mounted at `/mnt/backups/yads/`.

## Schedule & Retention

| Type    | Schedule           | Retention       | Directory  |
|---------|--------------------|-----------------|------------|
| Daily   | 03:00 UTC daily    | 14 days         | `daily/`   |
| Monthly | 1st of each month  | Never deleted   | `monthly/` |

An initial backup also runs on every container start.

## File Naming

```
{APP_NAME}_{DB_NAME}_{YYYY-MM-DD}_{HHMMSS}.sql.gz
```

Example: `yads_yads_2026-02-08_030000.sql.gz`

## Configuration

All settings are controlled via environment variables in `docker-compose.swarm.yml`:

| Variable               | Default        | Description                        |
|------------------------|----------------|------------------------------------|
| `DB_HOST`              | `db`           | PostgreSQL hostname                |
| `DB_PORT`              | `5432`         | PostgreSQL port                    |
| `DB_NAME`              | `yads`         | Database name                      |
| `DB_USER`              | `yads`         | Database user                      |
| `PGPASSWORD`           | *(required)*   | Database password                  |
| `BACKUP_BASE`          | `/backups`     | Container-internal backup path     |
| `APP_NAME`             | `yads`         | Prefix for backup filenames        |
| `DAILY_RETENTION_DAYS` | `14`           | Days to keep daily backups         |
| `CRON_SCHEDULE`        | `0 3 * * *`    | Cron expression for backup timing  |

## Initial Setup

Run on the production host before first deployment:

```bash
bash scripts/setup_backup.sh
```

This creates the required directories and validates the storage mount is writable.

## Manual Backup

To trigger a backup manually:

```bash
docker exec $(docker ps -q -f name=yads_yads-backup) /usr/local/bin/backup.sh
```

## Restore

1. Copy the backup file to a host with database access
2. Decompress and restore:

```bash
gunzip -c yads_yads_2026-02-08_030000.sql.gz | psql -h <db_host> -U yads -d yads
```

The backup includes `DROP ... IF EXISTS` statements (`pg_dump -c --if-exists`), so it performs a clean restore.

## Monitoring & Troubleshooting

**View logs:**
```bash
docker service logs yads_yads-backup
```

**Check recent backups:**
```bash
ls -lht "/mnt/backups/yads/daily/" | head -5
```

**Verify backup integrity:**
```bash
gunzip -t "/mnt/backups/yads/daily/<filename>.sql.gz"
```

**Common issues:**
- `pg_dump: could not connect to server` — Check that `DB_HOST` is reachable on the `yads-internal` network
- `Permission denied` on `/backups` — Verify the host mount is writable (`scripts/setup_backup.sh`)
- Backup size is 0 — Check `PGPASSWORD` is set correctly
