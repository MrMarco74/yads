# YADS Release Tools

Automation tools for the YADS release process.

## Tools

### `release.py` - Release Automation Tool

**NEW**: Comprehensive CLI tool for automating the entire release process.

**Features**:
- Semantic version bumping (major/minor/patch)
- Interactive changelog collection
- Automated German translation via Gemini
- Multi-file updates (8+ files)
- Release packaging integration
- SSH/FTP upload with fallback
- Git commit and tagging
- Rollback on failure

**Quick Start**:
```bash
# Initialize configuration
./tools/release.py init-config

# Preview patch release
./tools/release.py release --bump patch --dry-run

# Execute patch release
./tools/release.py release --bump patch
```

**Full Documentation**: See [docs/RELEASE_AUTOMATION.md](../docs/RELEASE_AUTOMATION.md)

### `package_release.sh` - Legacy Packaging Script

**PRESERVED**: Original bash script for building release packages.

This script is still used by the new automation tool and handles:
- Security validation (API keys, .env files)
- Docker image building (Nuitka compilation)
- Release archive creation (~770MB)
- SHA256 hash generation
- Homepage updates (support.html)
- version.json generation

**Note**: You don't need to run this directly anymore - `release.py` handles it.

### `capture_screenshots.py` - Screenshot Capture Tool

Utility for capturing screenshots of the YADS interface.

## Directory Structure

```
tools/
├── release.py              # Main release automation CLI
├── release_lib/            # Release automation library
│   ├── __init__.py
│   ├── version.py          # Semantic versioning
│   ├── config.py           # Configuration management
│   ├── changelog.py        # Changelog generation
│   ├── translator.py       # Gemini translation
│   ├── updater.py          # File update engine
│   └── uploader.py         # SSH/FTP upload
├── release_config.yaml     # Example configuration
├── package_release.sh      # Legacy packaging script
├── capture_screenshots.py  # Screenshot utility
└── README.md              # This file
```

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `google-generativeai` - Gemini translation API
- `pyyaml` - YAML configuration
- `rich` - Terminal output

### 2. Configure Release Tool

```bash
# Create configuration template
./tools/release.py init-config

# Edit configuration
vim ~/.yads/release.yaml

# Set API keys
export GEMINI_API_KEY='your-api-key'
```

### 3. Test Configuration

```bash
# Check current version
./tools/release.py version

# Preview release (dry-run)
./tools/release.py release --bump patch --dry-run
```

## Usage Examples

### Standard Patch Release

```bash
./tools/release.py release --bump patch
```

This will:
1. Bump version 1.13.3 → 1.13.4
2. Collect changelog interactively
3. Translate to German
4. Update all files
5. Build release package
6. Upload to server
7. Create git commit and tag

### Minor Version Release

```bash
./tools/release.py release --bump minor
```

Bumps version 1.13.3 → 1.14.0 (new features).

### Major Version Release

```bash
./tools/release.py release --bump major
```

Bumps version 1.13.3 → 2.0.0 (breaking changes).

### Release Without Upload

```bash
./tools/release.py release --bump patch --no-upload
```

Creates release but skips upload step (for manual deployment).

### Retry Failed Upload

```bash
./tools/release.py upload --version 1.13.4
```

Re-uploads files for an existing release.

### Editor Mode for Changelog

```bash
./tools/release.py release --bump patch --editor
```

Opens your `$EDITOR` with a YAML template for changelog entry.

## Configuration

Configuration file: `~/.yads/release.yaml`

```yaml
upload:
  method: ssh  # or 'ftp'
  fallback: true

  ssh:
    host: yads-security.com
    user: deploy
    key_file: ~/.ssh/deploy_key
    port: 22

  paths:
    releases: /var/www/releases
    homepage_en: /var/www/html/en
    homepage_de: /var/www/html/de

translation:
  service: gemini # 'gemini', 'vertexai', or 'manual'
  api_key: ${GEMINI_API_KEY} # For 'gemini'
  # For Vertex AI (keyless):
  # project_id: my-gcp-project
  # location: us-central1

git:
  auto_commit: true
  auto_tag: true
  push_after_release: false
```

## Troubleshooting

### Gemini API Errors

**Issue**: Translation fails

**Solution**:
- Check API key: `echo $GEMINI_API_KEY`
- Verify quota at Google AI Studio
- Use manual fallback (tool will prompt)

### SSH Upload Fails

**Issue**: Cannot upload via SSH

**Solution**:
- Test SSH: `ssh -i ~/.ssh/key user@host`
- Check key permissions: `chmod 600 ~/.ssh/key`
- Enable FTP fallback in config

### Packaging Fails

**Issue**: package_release.sh fails

**Solution**:
- Check Docker is running
- Verify disk space (~770MB needed)
- Review security validation errors
- Run script manually to debug

## Files Updated by Release Tool

The release tool automatically updates:

1. `yads/config.py` - Version string
2. `docs/USER_GUIDE.md` - Version and date
3. `yads-homepage/en/docs.html` - Version references
4. `yads-homepage/de/docs.html` - Version references
5. `yads/core/seeding.py` - Changelog entry
6. `yads/core/seeding.py` - Update notification
7. `yads-homepage/en/changes.html` - Changelog
8. `yads-homepage/de/changes.html` - Changelog

Backup files (`.bak`) are created and cleaned up automatically.

## Rollback

If release fails, the tool automatically:
- Restores all `.bak` files
- Reverts changes
- Displays error message

You can also manually restore from `.bak` files if needed.

## API Keys

### Google Gemini API (AI Studio)

Sign up: https://aistudio.google.com/app/apikey

Set environment variable:
```bash
export GEMINI_API_KEY='your-key-here'
```

### Google Vertex AI (GCP)

For automated, keyless authentication in CI/CD:

1. Enable Vertex AI API in your GCP project.
2. Configure `service: vertexai` and `project_id` in `release.yaml`.
3. The tool will use **Application Default Credentials (ADC)**.

## Best Practices

1. **Always dry-run first**: `--dry-run` to preview changes
2. **Test in development**: Test release process on test server
3. **Backup before release**: Database backup before major releases
4. **Review changelog**: Ensure accuracy before confirming
5. **Monitor upload**: Watch upload progress for errors
6. **Verify deployment**: Check website after release
7. **Keep config secure**: `chmod 600 ~/.yads/release.yaml`

## Support

**Documentation**: [docs/RELEASE_AUTOMATION.md](../docs/RELEASE_AUTOMATION.md)

**Issues**: Report in GitLab issue tracker

**Testing**: Run unit tests with `pytest tests/`

## Migration from Manual Process

If you previously released manually:

1. **Install dependencies**: `pip install -r requirements.txt`
2. **Create config**: `./tools/release.py init-config`
3. **Configure settings**: Edit `~/.yads/release.yaml`
4. **Set API keys**: Export environment variables
5. **Test with dry-run**: `./tools/release.py release --bump patch --dry-run`
6. **Execute first release**: Follow prompts carefully
7. **Verify results**: Check all files updated correctly

The tool preserves the existing `package_release.sh` script, so your packaging process remains unchanged.

## Development

### Project Structure

- **release_lib/**: Python package with modular components
- **tests/**: Unit tests (pytest)
- **docs/**: Documentation
- **release_config.yaml**: Example configuration template

### Running Tests

```bash
# Install dev dependencies
pip install pytest

# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_version.py -v

# Run with coverage
pytest tests/ --cov=release_lib
```

### Adding New Features

1. Update relevant module in `release_lib/`
2. Add unit tests in `tests/`
3. Update documentation in `docs/RELEASE_AUTOMATION.md`
4. Test with `--dry-run` flag
5. Submit merge request

## License

Part of the YADS project. Same license applies.
