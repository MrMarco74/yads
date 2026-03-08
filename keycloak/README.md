# Keycloak — YADS Identity Provider

Keycloak is configured to auto-import realm definitions at startup via `--import-realm`.
The realm JSON files in `keycloak/realms/` are mounted to `/opt/keycloak/data/import/`
(see `docker-compose.yml`).

---

## Realms

### `yads-platform` — Platform Administration

Used for platform-wide admins with cross-tenant access (`tenant_id=NULL` in YADS).

| User | Email | Password | YADS Role |
|---|---|---|---|
| `platform-admin` | platform-admin@yads.local | `admin123` | `admin` |

- OIDC client secret: `yads-platform-secret`
- Custom claim `yads_tenant=platform` in all tokens
- Group `yads-platform-admins` maps to YADS role `admin`

### `frischkorn` — Tenant Frischkorn

Tenant-scoped realm. Users in this realm can only access the Frischkorn tenant in YADS.

| User | Email | Password | YADS Role |
|---|---|---|---|
| `frischkorn-admin` | admin@frischkorn.local | `admin123` | `tenant_admin` |
| `frischkorn-scanner` | scanner@frischkorn.local | `scanner123` | `scanner` |
| `frischkorn-auditor` | auditor@frischkorn.local | `auditor123` | `auditor` |

- OIDC client secret: `frischkorn-yads-secret`
- Custom claim `yads_tenant=frischkorn` in all tokens
- Three groups mapping to YADS roles: `frischkorn-admins`, `frischkorn-scanners`, `frischkorn-auditors`

---

## How YADS uses Keycloak tokens

On OIDC login (`/auth/oidc/callback`), YADS reads:

- `sub` — Keycloak Subject ID, stored in `User.oidc_sub`
- `yads_tenant` — custom claim (hardcoded per realm), stored in `User.oidc_tenant`
- `groups` — group membership claim, first group's `yads_role` attribute maps to `User.role`

Users are auto-provisioned on first login if `User.oidc_sub` does not yet exist in the database.

---

## Realm Isolation

Each Keycloak realm is a fully isolated identity silo:

- A `frischkorn` realm user **cannot** log into the `yads-platform` realm and vice versa.
- The `yads_tenant` hardcoded claim ensures YADS assigns users to the correct tenant even if
  usernames overlap across realms.
- A tenant admin (`tenant_admin` role) sees only their own tenant's data in YADS. This mirrors
  the Keycloak-level isolation — they can only manage users within their own realm.

---

## Adding a new Tenant Realm

1. Copy `keycloak/realms/realm-frischkorn.json` to `keycloak/realms/realm-<tenantname>.json`
2. Replace all occurrences of `frischkorn` with the new tenant name (lowercase, no spaces)
3. Update the `displayName` field
4. Update user credentials and emails
5. Update `"claim.value": "frischkorn"` to `"claim.value": "<tenantname>"` in the hardcoded claim mapper
6. Update the OIDC client `"secret"` to a new unique value
7. Restart Keycloak (`docker-compose restart keycloak`) — new realms are imported on startup

Example find-and-replace command:
```bash
sed 's/frischkorn/newtenantname/g' \
    keycloak/realms/realm-frischkorn.json \
    > keycloak/realms/realm-newtenantname.json
```

Then edit the file to update passwords, emails, and the `displayName`.

> **Note:** Keycloak only imports realms that do not already exist. To re-import after changes,
> either delete the realm via the Admin UI first, or use the Keycloak Admin API.

---

## Keycloak Admin UI

Available at: http://localhost:8080

- Admin username: `admin`
- Admin password: `admin` (set via `KEYCLOAK_ADMIN_PASSWORD` in docker-compose.yml)
