# YADS Security Audit Report - Authentication & Core Components

## Executive Summary
This report details the findings from a security review of the YADS application, focusing heavily on authentication, authorization, and core component security. The assessment identified several areas for security hardening, particularly concerning path traversal during backups, potential Server-Side Template Injection (SSTI), and missing rate-limiting on sensitive operations. 

## Vulnerability Findings & Security Weaknesses

### 1. Path Traversal in Backup Restore (`yads/core/backup.py`)
**Severity:** High
**Location:** `restore_backup_from_zip` function in `yads/core/backup.py`

**Description:** 
When restoring a backup, the application extracts files from the `screenshots/` directory within the ZIP archive into `SCREENSHOT_DIR`. The extraction logic strips the `screenshots/` prefix but does not sanitize the remaining `rel_path` against directory traversal characters (e.g., `../`).
```python
if member.startswith("screenshots/"):
    rel_path = member[len("screenshots/"):]
    if not rel_path: continue
    target_path = os.path.join(SCREENSHOT_DIR, rel_path)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "wb") as f:
        f.write(zf.read(member))
```
If an attacker, acting as an administrator (or compromising an admin account), uploads a maliciously crafted ZIP file containing entries like `screenshots/../../../etc/passwd` or overwrites application Python files, it could lead to Arbitrary File Write and potential Remote Code Execution (RCE). While limited to administrators, it breaches the security boundary between the application admin and the underlying operating system.

**Recommendation:**
Use `os.path.abspath` to resolve the final `target_path` and verify that it strictly starts with the absolute path of `SCREENSHOT_DIR`. Reject any file extraction that attempts to break out of this directory constraint.

### 2. Potential Server-Side Template Injection (SSTI) (`yads/core/markdown_report_generator.py`)
**Severity:** Medium/High (Dependent on input source)
**Location:** `render_markdown_with_data` function

**Description:**
The application uses Jinja2 to render markdown reports. The Jinja environment is explicitly configured with `autoescape=False` to prevent double-escaping markdown syntax. 
```python
env = Environment(loader=BaseLoader(), autoescape=False)
...
template = env.from_string(markdown_content)
rendered_markdown = template.render(**context)
```
If `markdown_content` can be fully or partially supplied or influenced by user input (e.g., a tenant modifying custom report templates), this leads directly to a Server-Side Template Injection (SSTI) vulnerability, enabling arbitrary Python execution or data exfiltration.

**Recommendation:**
If user-provided templates are required, use a sandboxed Jinja2 environment (`jinja2.sandbox.SandboxedEnvironment`) to restrict malicious payload execution. Validate the source of `markdown_content` to ensure it only originates from trusted, hardcoded application files.

### 3. Missing Rate Limiting on MFA and Password Reset (`yads/api/routers/users.py`)
**Severity:** Low / Medium
**Location:** `/users/reset_password` and `/users/reset_mfa`

**Description:**
While external API calls are heavily rate-limited (`ApiRateLimiter`), sensitive internal administrative operations like resetting passwords or disabling MFA lack explicit rate limiting or secondary confirmation flows. An attacker with compromised generic administrative credentials (like a Tenant Admin) could rapidly cycle passwords for all users in a tenant or clear their MFA, locking them out without sufficient friction.

**Recommendation:**
Implement rate limiting on sensitive `/users/*` endpoints. Furthermore, require the active administrator to re-authenticate (e.g., provide their own password or an MFA code) before executing destructive or highly sensitive actions on other users.

### 4. Admin API Key Generation Secret Display (`yads/api/routers/api_keys.py`)
**Severity:** Info
**Location:** `create_key` function

**Description:**
When an API key is generated, it correctly returns the plain key only once. However, ensuring that this key is securely transmitted over TLS is paramount. The system configures TLS globally, but any misconfiguration allowing plain HTTP could expose these keys during generation. Furthermore, the scopes are hardcoded to `["read", "write"]`, which violates the Principle of Least Privilege if a user only needs read access.

**Recommendation:**
Implement granular scopes for API keys (e.g., `read_only`, `scan_execute`). Ensure HSTS is strictly enforced so keys are never transmitted over an insecure channel.

### 5. Custom Module Upload Protections (`yads/api/routers/scan_modules.py`)
**Severity:** Better than average (Security control observation)

**Description:**
The application allows installing custom scanner modules via ZIP upload. It correctly enforces an Ed25519 signature check `_verify_module_signature` if `MODULE_SIGNING_PUBLIC_KEY` is configured in `settings`. It explicitly checks and blocks executable setup scripts (`setup.py`, `setup.sh`).

**Recommendation:**
This is a good design pattern. To improve it, enforce signature verification by default and require a deliberate application override (rather than simply leaving the public key empty) to disable it, ensuring secure defaults.

## Conclusion
The YADS authentication and core components employ solid baseline mechanics, including proper password hashing, role-based access control, tenant isolation, and security event logging (`security_audit.py`). However, high-severity risks like Path Traversal during backup restores and potential SSTI in report generation require immediate remediation to prevent privilege escalation from application administrator to system-level execution.
