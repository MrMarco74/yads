# YADS Security Guide

This document outlines security best practices for deploying and managing YADS.

## Configuration Security

### Environment Variables

YADS uses environment variables for sensitive configuration. **NEVER commit these files to version control:**

- `data/config.env` - Runtime configuration with database credentials
- `.env` - Docker Compose environment file
- Any files matching `*.env` or `*.env.*`

### Required Environment Variables

#### Database Configuration

```bash
# PostgreSQL Database Password
# Generate with: openssl rand -base64 32
POSTGRES_PASSWORD=your_secure_password_here

# Database Connection URL
DATABASE_URL=postgresql://yads:your_secure_password_here@db:5432/yads
```

#### Application Security

```bash
# Secret Key for JWT Token Signing
# Generate with: openssl rand -hex 32
SECRET_KEY=your_secret_key_here

# License Key (provided by vendor)
LICENSE_KEY=your_license_key_here
```

### Configuration File Template

A template configuration file is provided at `data/config.env.example`. Copy this file to `data/config.env` and update with your actual values:

```bash
cp data/config.env.example data/config.env
# Edit data/config.env with your secure values
```

## API Key Management

### Tenant-Specific API Keys

YADS supports tenant-specific API keys for third-party integrations. These are stored **encrypted in the database** and configured via the web interface:

1. **Google API Key** - For OSINT Search and Vision API
2. **Nuclei API Key** - For vulnerability scanning (ProjectDiscovery Cloud Platform)
3. **HIBP API Key** - For credential monitoring (Have I Been Pwned)

**Important**: These keys are stored per-tenant and are NOT included in the application code or configuration files.

### Configuring API Keys

1. Log in to the YADS dashboard
2. Navigate to **Settings** → **Tenant Settings**
3. Enter your API keys in the respective fields
4. Click **Save All Settings**

API keys are encrypted before storage and are only accessible to users with appropriate tenant permissions.

## Backup Security

### Database Backups

YADS automatically creates database backups before migrations. These backups may contain sensitive data including:

- User credentials (hashed passwords)
- Tenant API keys (encrypted)
- Scan results and findings
- Target configurations

**Security Measures:**

1. Backups are stored in `logs/backups/` (excluded from version control)
2. Automatic retention policy keeps only the last 10 backups
3. Backups can be encrypted with a password when exported via the UI

### Backup Best Practices

- **Never commit backup files** (`.sql`, `.sql.gz`, `.zip`) to version control
- Store backups in a secure location with restricted access
- Use encrypted backups when transferring data
- Regularly test backup restoration procedures
- Implement off-site backup storage for disaster recovery

## Credential Rotation

### Database Password Rotation

To rotate the database password:

1. Update `POSTGRES_PASSWORD` in your `.env` or `data/config.env`
2. Update `DATABASE_URL` with the new password
3. Restart the database container:
   ```bash
   docker compose down
   docker compose up -d
   ```

### Secret Key Rotation

Rotating the `SECRET_KEY` will invalidate all existing user sessions:

1. Generate a new secret key: `openssl rand -hex 32`
2. Update `SECRET_KEY` in your configuration
3. Restart the application
4. All users will need to log in again

### API Key Rotation

To rotate tenant API keys:

1. Obtain new API keys from the respective service providers
2. Log in to YADS and navigate to **Tenant Settings**
3. Update the API keys
4. Save the configuration

## Release Build Security

The release packaging script (`tools/package_release.sh`) includes automated security checks:

- ✅ Verifies `data/config.env` is not tracked in Git
- ✅ Scans for hardcoded API keys in source code
- ✅ Checks for database backups in the repository
- ✅ Ensures no `.env` files are tracked
- ✅ Detects hardcoded passwords

**The build will fail if any security issues are detected.**

## Access Control

### User Management

- Change the default admin password immediately after installation
- Use strong, unique passwords for all user accounts
- Enable Multi-Factor Authentication (MFA) for admin accounts
- Regularly review and audit user access permissions
- Remove inactive user accounts promptly

### Network Security

- Deploy YADS behind a reverse proxy (e.g., Nginx, Traefik)
- Use HTTPS/TLS for all external access
- Restrict database access to the internal Docker network
- Implement firewall rules to limit access to authorized IPs
- Consider using a VPN for remote access

## Monitoring & Auditing

### Security Logs

YADS logs security-relevant events including:

- User authentication attempts
- Permission changes
- Configuration modifications
- License validation events

Logs are stored in `logs/` and should be monitored regularly.

### Audit Trail

The application maintains an audit trail for:

- User login/logout events
- Scan executions
- Target modifications
- Settings changes

Review the audit trail regularly via the **System** → **Changelog** section.

## Incident Response

### Suspected Credential Compromise

If you suspect credentials have been compromised:

1. **Immediately rotate** all affected passwords and API keys
2. Review access logs for unauthorized activity
3. Check for unexpected scan results or configuration changes
4. Restore from a known-good backup if necessary
5. Update `.gitignore` and verify no secrets are in version control

### Data Breach

In case of a data breach:

1. Isolate the affected system
2. Preserve logs and evidence
3. Notify affected users and stakeholders
4. Conduct a security audit
5. Implement additional security measures

## Security Updates

- Regularly update YADS to the latest version
- Monitor security advisories from the vendor
- Subscribe to security notifications
- Test updates in a staging environment before production deployment

## Contact

For security concerns or to report vulnerabilities, contact:

**Email**: support@yads-security.com

---

**Last Updated**: 2026-01-21
