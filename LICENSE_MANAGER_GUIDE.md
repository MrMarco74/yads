# YADS License Manager Guide

This guide explains how to use the standalone **License Manager Tool** (`tools/license_admin.py`) to generate cryptographic keys, issue signed licenses for customers, and verify them.

## Prerequisites

The tool requires **Python 3** and the `cryptography` library.

```bash
# Install dependencies
pip install cryptography
```

## Running the Tool

To start the interactive License Manager:

```bash
python3 tools/license_admin.py
```

You will see the main menu:

```text
=== YADS License Manager ===
1. Issue License
2. Verify License
3. Setup / Generate Keys
q. Quit
```

---

## Step 1: Initial Setup (Generate Keys)

**Run this once** to create your Vendor Keypair.

1. Select option **3** (`Setup / Generate Keys`).
2. The tool will generate two files in the current directory:
   - `license_private.pem`: **KEEP SECRET!** Used to sign licenses.
   - `license_public.pem`: **PUBLIC.** Used by YADS to verify licenses.
3. It will also display a **Base64 String** of the Public Key.
   - **Action:** Copy this Base64 string and paste it into `yads/config.py` (or update it in the core application code if you are the developer) to enable the application to verify your licenses.

## Step 2: Issue a License

To create a new license for a customer:

1. Select option **1** (`Issue License`).
2. Enter the **Customer Name** (e.g., `Acme Corp`).
3. Enter the **Max Targets** (e.g., `50`).
4. Enter the **Validity in Days** (default is 365).
5. The tool will generate a **License Key** (a long string starting with `ey...`).
   - **Action:** Send this string to your customer.

## Step 3: Verify a License

To check if a license key is valid:

1. Select option **2** (`Verify License`).
2. Paste the License Key string.
3. The tool will decode it and show:
   - **Status:** `[OK] Signature Verified` or `[FAIL] Invalid Signature`.
   - **Customer:** Name of the licensee.
   - **Expiration:** Date and days remaining.
   - **Limits:** Max targets allowed.

---

## Applying the License (For Admins)

Admins can apply the license in the YADS Dashboard:

1. Log in to YADS as an **Admin**.
2. Go to **Settings** -> **License Management**.
3. Paste the **License Key** into the text area.
4. Click **Save Configuration**.
5. The status indicator should turn **Green (Valid)**.

## Security Notes

- **Protect `license_private.pem`**: Anyone with this file can generate valid licenses for your software. Store it securely (e.g., in an encrypted vault), not in the source code repository distributed to customers.
- **Distribution**: You only need to distribute the `license_admin.py` tool to your sales/ops team. Do not ship `license_private.pem` to customers.
