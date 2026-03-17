# YADS Setup Guide (Offline / Docker Images)

This guide explains how to install and configure YADS using the provided Docker images and your License Key.

## Quick Start (Recommended)

The easiest way to set up YADS is to use the interactive setup script:

```bash
chmod +x setup.sh
./setup.sh
```

Follow the prompts to configure:

- **Docker Host**: Where to deploy (local or remote).
- **Network**: Port (default 80/443) and SSL.
- **Credentials**: Automatically generates secure passwords.

Once the script finishes, start the platform:

```bash
docker compose up -d
```

---

## Manual Configuration (Advanced)

If you prefer to configure YADS manually, follow these steps:

### Prerequisites

- **Docker Engine** (v20.10+)
- **Docker Compose** (v2.0+)
- **Provided Files**:
  - `yads-images.tar.gz` (Docker Images)
  - `docker-compose.yml` (Configuration)
  - Your **License Key** string

---

### Step 1: Load Docker Images

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

### Step 2: Configuration

1. Create a project directory:

   ```bash
   mkdir yads-install
   cd yads-install
   ```

2. Save the provided `docker-compose.yml` file into this directory.

3. Create a `.env` file for your configuration:
   ```bash
   # Use example values or generate new ones
   echo "POSTGRES_PASSWORD=$(openssl rand -base64 24)" >> .env
   echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
   echo "API_PORT=80" >> .env
   ```

   > **⚠️ SECURITY WARNING**: 
   > - **NEVER commit the `.env` file to version control!**
   > - Keep this file secure and restrict access to authorized personnel only.

---

### Step 3: Start the Platform

Run the following command to start YADS:

```bash
docker compose up -d
```

Check the status:

```bash
docker compose ps
```

---

### Step 4: Access the Dashboard

1. Open your web browser and navigate to the configured port (e.g., [http://localhost](http://localhost)).

2. Log in with the default credentials:
   - **Username**: `admin`
   - **Password**: `admin`

   > **Important**: You will be prompted to change the default password upon first login.
