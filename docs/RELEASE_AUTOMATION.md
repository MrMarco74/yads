# YADS Release Automation

Comprehensive guide for using the automated release tool.

## Table of Contents

- [Overview](#overview)
- [Setup](#setup)
- [Usage](#usage)
- [Workflow](#workflow)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

## Overview

The YADS release automation tool (`tools/release.py`) streamlines the entire release process:

- ✅ Semantic version bumping (major/minor/patch)
- ✅ Interactive changelog collection
- ✅ Automated German translation (Gemini API)
- ✅ Multi-file updates (8+ files)
- ✅ Release packaging integration
- ✅ SSH/FTP upload with fallback
- ✅ Git commit and tagging
- ✅ Rollback on failure

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `google-generativeai` - Gemini translation API
- `pyyaml` - YAML configuration parsing
- `rich` - Enhanced terminal output

### 2. Create Configuration File

```bash
./tools/release.py init-config
```

This creates `~/.yads/release.yaml` with default settings.

### 3. Configure Settings

Edit `~/.yads/release.yaml`:

```yaml
upload:
  method: ssh  # or 'ftp'
  fallback: true

  ssh:
    host: your-server.com
    user: deploy
    key_file: ~/.ssh/deploy_key
    port: 22

  paths:
    releases: /var/www/releases
    homepage_en: /var/www/html/en
    homepage_de: /var/www/html/de

translation:
  service: gemini
  api_key: ${GEMINI_API_KEY}
```

### 4. Set Environment Variables

```bash
export GEMINI_API_KEY='your-gemini-api-key'
export YADS_FTP_PASSWORD='your-ftp-password'  # if using FTP
```

Add these to your `~/.bashrc` or `~/.zshrc` for persistence.

### 5. Get Gemini API Key

1. Sign up at https://aistudio.google.com/app/apikey
2. Free tier: 500,000 characters/month (sufficient for releases)
3. Copy API key and set environment variable

## Usage

### Full Release Process

```bash
# Preview patch release
./tools/release.py release --bump patch --dry-run

# Execute patch release
./tools/release.py release --bump patch

# Minor version release
./tools/release.py release --bump minor

# Major version release (breaking changes)
./tools/release.py release --bump major
```

### Version Bumping

- **Patch** (1.13.3 → 1.13.4): Bug fixes, no new features
- **Minor** (1.13.3 → 1.14.0): New features, backward compatible
- **Major** (1.13.3 → 2.0.0): Breaking changes

### Options

```bash
# Use editor for changelog (instead of interactive)
./tools/release.py release --bump patch --editor

# Skip upload step
./tools/release.py release --bump patch --no-upload

# Skip git commit
./tools/release.py release --bump patch --no-commit

# Custom config file
./tools/release.py release --bump patch --config /path/to/config.yaml
```

### Retry Upload

If upload fails, retry without re-running the entire release:

```bash
./tools/release.py upload --version 1.13.4
```

### Check Current Version

```bash
./tools/release.py version
```

## Workflow

### Step-by-Step Process

1. **Pre-flight Checks**
   - Verifies git repository
   - Checks for uncommitted changes
   - Validates config file and package script

2. **Version Bump**
   - Reads current version from `yads/config.py`
   - Calculates new version based on bump type
   - Confirms with user

3. **Changelog Collection**
   - Interactive prompts for release title
   - Section selection (Features, Fixes, etc.)
   - Item entry for each section
   - Preview before confirmation

4. **Translation**
   - Translates changelog to German via Gemini (AI Studio) or Vertex AI (GCP)
   - Supports keyless authentication via Google Service Accounts
   - Fallback to manual input if API fails
   - Preview German translation

5. **File Updates**
   Updates 8+ files with new version and changelog:
   - `yads/config.py` - Version string
   - `docs/USER_GUIDE.md` - Version and date
   - `yads-homepage/en/docs.html` - Version references
   - `yads-homepage/de/docs.html` - Version references
   - `yads/core/seeding.py` - Changelog entry (Python)
   - `yads/core/seeding.py` - Update notification
   - `yads-homepage/en/changes.html` - Changelog (HTML)
   - `yads-homepage/de/changes.html` - Changelog (HTML)

6. **Packaging**
   - Executes existing `tools/package_release.sh`
   - Builds Docker image with Nuitka
   - Creates release archive (~770MB)
   - Generates SHA256 hash
   - Updates support.html
   - Generates version.json

7. **Upload**
   - Uploads release package
   - Uploads version.json
   - Uploads 6 homepage HTML files
   - Falls back to FTP if SSH fails

8. **Git Operations**
   - Stages all changes
   - Creates commit: "Release vX.Y.Z: Title"
   - Creates tag: vX.Y.Z
   - Prompts to push to remote

### Rollback

If any step fails, the tool automatically:
- Restores `.bak` files
- Reverts all changes
- Keeps local files for debugging

## Configuration

### Configuration File Structure

```yaml
# Upload settings
upload:
  method: ssh              # Primary: 'ssh' or 'ftp'
  fallback: true           # Auto-fallback on failure

  ssh:
    host: server.com
    user: deploy
    key_file: ~/.ssh/key   # Path to SSH private key
    port: 22

  ftp:
    host: server.com
    user: ftpuser
    password: ${VAR}       # Environment variable
    port: 21

  paths:
    releases: /path/to/releases
    homepage_en: /path/to/en
    homepage_de: /path/to/de

# Translation settings
translation:
  service: gemini           # 'gemini' or 'manual'
  api_key: ${GEMINI_KEY}
  source_lang: EN
  target_lang: DE

# Git settings
git:
  auto_commit: true        # Create commit automatically
  auto_tag: true           # Create tag automatically
  push_after_release: false  # Manual push recommended

# Release settings
release:
  changelog_mode: interactive  # 'interactive' or 'editor'
  dry_run_default: true       # Safe default
```

### Environment Variables

Use `${VAR_NAME}` syntax in config to reference environment variables:

```yaml
api_key: ${DEEPL_API_KEY}
password: ${YADS_FTP_PASSWORD}
```

export GEMINI_API_KEY='your-key-here'
```

### Option B: Vertex AI (GCP Keyless)

For fully automated CI/CD without manual keys:

1.  **Configure Service**: Set `service: vertexai` in `release.yaml`.
2.  **Project ID**: provide your GCP `project_id`.
3.  **Auth**: Ensure the runner has the `Vertex AI User` role.

## Troubleshooting

### Gemini API Errors

**Problem**: Translation fails with API error

**Solutions**:
1. Check API key is set: `echo $GEMINI_API_KEY`
2. Verify API quota: Google AI Studio
3. Use manual fallback: tool will prompt for manual translations
4. Set service to 'manual' in config to skip API

### SSH Upload Fails

**Problem**: SSH/rsync upload fails

**Solutions**:
1. Test SSH connection: `ssh -i ~/.ssh/key user@host`
2. Verify key file permissions: `chmod 600 ~/.ssh/key`
3. Check server paths exist
4. Enable FTP fallback in config
5. Use `--no-upload` and upload manually

### Git Errors

**Problem**: Git commit or tag fails

**Solutions**:
1. Ensure git is installed: `git --version`
2. Configure git user: `git config user.name` and `git config user.email`
3. Use `--no-commit` to skip git operations
4. Commit manually after release

### File Update Errors

**Problem**: File update fails or syntax errors

**Solutions**:
1. Check `.bak` files for recovery
2. Use `--dry-run` to preview changes
3. Verify file paths and patterns
4. Restore from backups if needed

### Packaging Errors

**Problem**: package_release.sh fails

**Solutions**:
1. Run script manually: `./tools/package_release.sh`
2. Check Docker is running
3. Verify disk space for ~770MB archive
4. Review script security checks
5. Check API keys and .env files

### Configuration Errors

**Problem**: Config validation fails

**Solutions**:
1. Validate YAML syntax: `python -c "import yaml; yaml.safe_load(open('~/.yads/release.yaml'))"`
2. Check required fields are present
3. Verify environment variables are set
4. Review error messages for missing fields
5. Regenerate config: `./tools/release.py init-config`

## Best Practices

### Before Release

1. **Test changes**: Ensure all features work
2. **Update tests**: Add tests for new features
3. **Review commits**: Clean commit history
4. **Backup database**: Run backup before release
5. **Check security**: No API keys in code

### During Release

1. **Use dry-run first**: Always preview changes
2. **Review changelog**: Accurate and complete
3. **Verify translation**: German text makes sense
4. **Monitor packaging**: Watch for errors
5. **Test upload**: Verify files uploaded correctly

### After Release

1. **Verify website**: Check changelog visible
2. **Test download**: Download and verify package
3. **Update documentation**: Keep docs current
4. **Announce release**: Notify users
5. **Monitor issues**: Watch for bug reports

## Examples

### Typical Patch Release

```bash
# 1. Preview changes
./tools/release.py release --bump patch --dry-run

# 2. Execute release
./tools/release.py release --bump patch

# 3. Enter changelog when prompted:
#    Title: Bug Fixes and Stability
#    Section: Bug Fixes
#    Items:
#      - Fixed authentication timeout issue
#      - Resolved dashboard loading error
#      - Corrected API response format

# 4. Review German translation
# 5. Confirm packaging
# 6. Monitor upload progress
# 7. Push to git when prompted
```

### Minor Release with New Features

```bash
./tools/release.py release --bump minor

# Changelog sections:
#   - New Features
#     - Added user dashboard
#     - Implemented export to PDF
#   - Improvements
#     - Enhanced performance by 25%
#   - Bug Fixes
#     - Fixed memory leak in scanner
```

### Major Release (Breaking Changes)

```bash
./tools/release.py release --bump major

# Changelog sections:
#   - Breaking Changes
#     - Removed deprecated API endpoints
#     - Changed database schema
#   - New Features
#     - Complete UI redesign
#   - Migration Guide
#     - See MIGRATION.md for upgrade steps
```

### Upload Only (After Failed Upload)

```bash
# Release completed but upload failed
./tools/release.py upload --version 1.13.4
```

### Skip Upload (Deploy Manually)

```bash
# Create release but deploy later
./tools/release.py release --bump patch --no-upload

# Later, deploy manually
scp releases/yads_v1.13.4_customer_pkg.zip server:/path/
```

## Support

For issues or questions:

1. Check this documentation
2. Review troubleshooting section
3. Check log output for errors
4. Test individual components
5. Create issue in GitLab

## File Locations

- **Script**: `tools/release.py`
- **Library**: `tools/release_lib/*.py`
- **Config**: `~/.yads/release.yaml`
- **Template**: `tools/release_config.yaml`
- **Backups**: `*.bak` (cleaned up after success)
- **Releases**: `releases/yads_vX.Y.Z_customer_pkg.zip`
