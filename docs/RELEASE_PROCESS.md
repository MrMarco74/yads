# How to Build a Release (and don't fuck it up)

Follow this checklist precisely to ensure a broken release is never shipped to a customer.

## 1. Preparation
fi
### 1.1 Check Git Status

Ensure you are on the `main` branch and have no uncommitted changes (except the version bump you are about to do).

```bash
git checkout main
git pull
git status
```

### 1.2 Bump Version

Open `yads/config.py` and increment the `VERSION` variable.

```python
# yads/config.py
VERSION: str = "1.11.0"  # <--- Update this
```

## 2. Updates & Notifications

### 2.1 Add Changelog Entry

Open `yads/core/seeding.py` and add a new entry to the `changelog_data` list.

```python
# yads/core/seeding.py
{
    "version": "1.11.0",
    "date": "2026-01-19",
    "changes": [
        "NEW: Added Setup Guide to Homepage",
        "FIX: Resolved Startup Crash",
        # ...
    ]
},
```

### 2.2 Create System Notification

Open `migrate_db.py` and ensure a notification is seeded for this version.

```python
# migrate_db.py
create_notification(
    title="System Update v1.11.0",
    message="YADS has been updated to v1.11.0. Check the changelog for details.",
    severity="info"
)
```

### 2.3 Verify System Boot

Run the migration script and start the API locally to ensure no import errors exist.

```bash
# In one terminal
make db-migrate

# In another
make dev
# OR
python -m uvicorn yads.api.main:app
```

**STOP** if you see any stack traces. Fix them before proceeding.

## 3. Packaging

### 3.1 Run the Packaging Script

We have a foolproof script that:

1. Builds Docker images.
2. Exports them to a tarball.
3. Bundles documentation (excluding internal License Guide).
4. Creates the customer zip file.
5. **Automatically calculates SHA256 hash.**
6. **Automatically updates the Homepage (DE/EN) with the new version and hash.**

```bash
cd /home/mrmarco/Documents/gitlab/yads
./tools/package_release.sh
```

### 3.2 Watch for Errors

The script will exit immediately if any command fails.

- If Docker build fails: Check your Dockerfile.
- If Image save fails: Check disk space.
- If Zip fails: Check permissions.
- **Verification**: The script will output the new SHA256 hash at the end. Verify this matches the update on the homepage.

## 4. Verification

### 4.1 Check the Output

Go to the `releases/` directory. You should see a new zip file.

```bash
ls -lh releases/
# Example: yads_v1.11.0_customer_pkg.zip
```

### 4.2 Validate Content (Optional but Recommended)

Unzip it in a temporary folder and check the contents of `README_SETUP.md`.

```bash
unzip -l releases/yads_v1.11.0_customer_pkg.zip
```

Ensure it contains:

- `yads-images.tar.gz` (Big file, ~500MB+)
- `docker-compose.yml`
- `README_SETUP.md`
- `docs/` folder

## 5. Deployment

### 5.1 Push Code

Commit the version bump and changelog updates.

```bash
git add .
git commit -m "chore: release v1.11.0"
git push
```

### 5.2 Distribute

Upload `releases/yads_v1.11.0_customer_pkg.zip` to the customer portal or send the link.
**DONE.**
