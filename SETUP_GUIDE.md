# YADS Setup Guide (Offline / Docker Images)

This guide explains how to install and configure YADS using the provided Docker images and your License Key.

## Prerequisites

- **Docker Engine** (v20.10+)
- **Docker Compose** (v2.0+)
- **Provided Files**:
  - `yads-images.tar.gz` (Docker Images)
  - `docker-compose.yml` (Configuration)
  - Your **License Key** string

---

## Step 1: Load Docker Images

Load the provided images into your local Docker instance:

```bash
docker load < yads-images.tar.gz
```

Verify that the images are loaded:

```bash
docker images | grep yads
# Output should list: yads-api, yads-worker
```

---

## Step 2: Configuration

1. Create a project directory:
   ```bash
   mkdir yads-install
   cd yads-install
   ```

2. Save the provided `docker-compose.yml` file into this directory.

3. Create a `.env` file for your configuration:
   ```bash
   nano .env
   ```

   **Paste the following content and update the values:**

   ```ini
   # --- License Configuration ---
   # Paste your full License Key string here
   LICENSE_KEY=ey...<your_long_key_string>...

   # --- Database ---
   # Set a strong password for the internal database
   POSTGRES_PASSWORD=secure_password_here

   # --- Security ---
   # Generate a random string for session security
   # You can generate one with: openssl rand -hex 32
   SECRET_KEY=change_this_to_a_random_string
   ```

---

## Step 3: Start the Platform

Run the following command to start YADS:

```bash
docker compose up -d
```

This will:
- Start the Database, Redis, API, and Worker containers.
- Automatically apply your License Key.
- Run necessary database migrations.

Check the status:

```bash
docker compose ps
```

All containers (`yads-api`, `yads-worker`, `db`, `redis`) should be in the `Up` or `Running` state.

---

## Step 4: Access the Dashboard

1. Open your web browser and navigate to:
   [http://localhost:8000](http://localhost:8000)

2. Log in with the default credentials:
   - **Username**: `admin`
   - **Password**: `admin`

   > **Important**: You will be prompted to change the default password upon first login.

---

## Troubleshooting

**License Not Applied?**
Check the API logs to see if the license script ran:
```bash
docker compose logs yads-api | grep "License key"
```

**Database Connection Error?**
Ensure the `POSTGRES_PASSWORD` in `.env` matches what you expected. If you changed it *after* the first run, you may need to reset the database volume:
```bash
docker compose down -v
docker compose up -d
```
