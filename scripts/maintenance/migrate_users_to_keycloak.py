"""
migrate_users_to_keycloak.py
============================
Migriert bestehende YADS-Benutzer und Tenants nach Keycloak.

Für jeden Tenant wird ein eigener Keycloak-Realm angelegt.
Für jeden User wird ein Keycloak-Account mit korrekter Gruppe erstellt.
Der oidc_sub wird zurück in die YADS-Datenbank geschrieben.

Verwendung:
    # Dry-Run (keine Änderungen, nur Vorschau)
    python scripts/maintenance/migrate_users_to_keycloak.py --dry-run

    # Echte Migration
    python scripts/maintenance/migrate_users_to_keycloak.py

    # Mit custom Keycloak-URL (z.B. Produktion)
    python scripts/maintenance/migrate_users_to_keycloak.py --keycloak-url http://keycloak:8080

    # Nur einen bestimmten Tenant migrieren
    python scripts/maintenance/migrate_users_to_keycloak.py --tenant frischkorn

    # Temporäres Passwort überschreiben (Default: Yads_Migrate_2024!)
    python scripts/maintenance/migrate_users_to_keycloak.py --temp-password "MeinPasswort123!"

Voraussetzungen:
    - Keycloak läuft und ist erreichbar
    - Keycloak Admin-Credentials (--admin-user / --admin-password)
    - YADS-Datenbank ist erreichbar (via DATABASE_URL)
"""

import sys
import os
import re
import argparse
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import create_engine, text
from yads.config import settings

# ---------------------------------------------------------------------------
# Keycloak Admin API Client
# ---------------------------------------------------------------------------

class KeycloakAdmin:
    def __init__(self, base_url: str, admin_user: str, admin_password: str):
        self.base_url = base_url.rstrip("/")
        self.admin_user = admin_user
        self.admin_password = admin_password
        self._token = None

    def _get_token(self) -> str:
        resp = requests.post(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.admin_user,
                "password": self.admin_password,
            },
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _headers(self) -> dict:
        if not self._token:
            self._token = self._get_token()
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    def _req(self, method: str, path: str, **kwargs):
        """Wrapper mit Token-Refresh bei 401."""
        url = f"{self.base_url}/admin{path}"
        resp = requests.request(method, url, headers=self._headers(), **kwargs)
        if resp.status_code == 401:
            self._token = self._get_token()
            resp = requests.request(method, url, headers=self._headers(), **kwargs)
        return resp

    # --- Realms ---

    def realm_exists(self, realm: str) -> bool:
        resp = self._req("GET", f"/realms/{realm}")
        return resp.status_code == 200

    def create_realm(self, realm: str, display_name: str) -> bool:
        payload = {
            "realm": realm,
            "displayName": display_name,
            "enabled": True,
            "registrationAllowed": False,
            "loginWithEmailAllowed": True,
            "duplicateEmailsAllowed": False,
            "ssoSessionIdleTimeout": 1800,
            "ssoSessionMaxLifespan": 36000,
            "accessTokenLifespan": 300,
        }
        resp = self._req("POST", "/realms", json=payload)
        if resp.status_code == 201:
            return True
        if resp.status_code == 409:
            return True  # Bereits vorhanden
        resp.raise_for_status()
        return False

    # --- Clients ---

    def get_client_id(self, realm: str, client_id: str) -> str | None:
        resp = self._req("GET", f"/realms/{realm}/clients", params={"clientId": client_id})
        resp.raise_for_status()
        clients = resp.json()
        return clients[0]["id"] if clients else None

    def create_yads_client(self, realm: str, redirect_uri: str) -> str:
        """Legt den YADS OIDC-Client an und gibt die interne Keycloak-ID zurück."""
        existing = self.get_client_id(realm, "yads")
        if existing:
            return existing

        payload = {
            "clientId": "yads",
            "name": "YADS",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": settings.OIDC_CLIENT_SECRET,
            "redirectUris": [redirect_uri, redirect_uri.rstrip("/") + "/*"],
            "webOrigins": ["+"],
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": True,
            "fullScopeAllowed": True,
        }
        resp = self._req("POST", f"/realms/{realm}/clients", json=payload)
        resp.raise_for_status()
        # Location header enthält die neue ID
        location = resp.headers.get("Location", "")
        return location.split("/")[-1]

    def add_client_mappers(self, realm: str, client_uuid: str):
        """Fügt Protocol-Mapper für groups und yads_tenant hinzu."""
        mappers = [
            {
                "name": "groups",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-group-membership-mapper",
                "config": {
                    "full.path": "false",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "userinfo.token.claim": "true",
                    "claim.name": "groups",
                },
            },
            {
                "name": "yads_tenant",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "config": {
                    "claim.value": realm,
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "userinfo.token.claim": "true",
                    "claim.name": "yads_tenant",
                    "jsonType.label": "String",
                },
            },
        ]
        for mapper in mappers:
            resp = self._req(
                "POST",
                f"/realms/{realm}/clients/{client_uuid}/protocol-mappers/models",
                json=mapper,
            )
            if resp.status_code not in (201, 409):
                print(f"    [WARN] Mapper '{mapper['name']}' konnte nicht angelegt werden: {resp.text}")

    # --- Groups ---

    def get_group_id(self, realm: str, group_name: str) -> str | None:
        resp = self._req("GET", f"/realms/{realm}/groups", params={"search": group_name})
        resp.raise_for_status()
        groups = [g for g in resp.json() if g["name"] == group_name]
        return groups[0]["id"] if groups else None

    def create_group(self, realm: str, group_name: str) -> str:
        existing = self.get_group_id(realm, group_name)
        if existing:
            return existing
        resp = self._req("POST", f"/realms/{realm}/groups", json={"name": group_name})
        resp.raise_for_status()
        location = resp.headers.get("Location", "")
        return location.split("/")[-1]

    def ensure_tenant_groups(self, realm: str) -> dict:
        """Legt die Standard-Gruppen für einen Tenant-Realm an."""
        groups = {}
        for suffix in ("admins", "scanners", "auditors"):
            name = f"{realm}-{suffix}"
            gid = self.create_group(realm, name)
            groups[suffix] = gid
        return groups

    def ensure_platform_admin_group(self, realm: str) -> str:
        return self.create_group(realm, "yads-platform-admins")

    # --- Users ---

    def get_user_id(self, realm: str, username: str) -> str | None:
        resp = self._req("GET", f"/realms/{realm}/users", params={"username": username, "exact": "true"})
        resp.raise_for_status()
        users = resp.json()
        return users[0]["id"] if users else None

    def create_user(self, realm: str, username: str, email: str, first_name: str, last_name: str) -> str | None:
        """Legt User an. Gibt Keycloak-User-UUID zurück."""
        existing = self.get_user_id(realm, username)
        if existing:
            return existing

        payload = {
            "username": username,
            "email": email or f"{username}@yads.local",
            "firstName": first_name or "",
            "lastName": last_name or "",
            "enabled": True,
            "emailVerified": False,
            "requiredActions": ["UPDATE_PASSWORD"],
        }
        resp = self._req("POST", f"/realms/{realm}/users", json=payload)
        if resp.status_code == 409:
            return self.get_user_id(realm, username)
        resp.raise_for_status()
        location = resp.headers.get("Location", "")
        return location.split("/")[-1]

    def set_temp_password(self, realm: str, user_id: str, password: str):
        resp = self._req(
            "PUT",
            f"/realms/{realm}/users/{user_id}/reset-password",
            json={"type": "password", "value": password, "temporary": True},
        )
        resp.raise_for_status()

    def assign_group(self, realm: str, user_id: str, group_id: str):
        resp = self._req("PUT", f"/realms/{realm}/users/{user_id}/groups/{group_id}")
        resp.raise_for_status()

    def get_user_sub(self, realm: str, user_id: str) -> str:
        """Gibt den Keycloak 'sub' (= User-UUID) zurück."""
        return user_id  # In Keycloak ist id == sub


# ---------------------------------------------------------------------------
# Rolle → Gruppen-Suffix Mapping
# ---------------------------------------------------------------------------

ROLE_TO_GROUP = {
    "admin": "admins",           # Platform-Admins → yads-platform-admins
    "tenant_admin": "admins",    # → {tenant}-admins
    "scanner": "scanners",       # → {tenant}-scanners
    "auditor": "auditors",       # → {tenant}-auditors
}


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def split_full_name(full_name: str) -> tuple[str, str]:
    parts = (full_name or "").strip().split(" ", 1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def gen_temp_password(base: str) -> str:
    """Gibt das base-Passwort zurück (mit einfachem Sicherheitscheck)."""
    if len(base) < 8:
        raise ValueError("Temporäres Passwort muss mindestens 8 Zeichen haben.")
    return base


# ---------------------------------------------------------------------------
# Haupt-Migrations-Logik
# ---------------------------------------------------------------------------

def migrate(
    keycloak_url: str,
    admin_user: str,
    admin_password: str,
    temp_password: str,
    dry_run: bool,
    tenant_filter: str | None,
    redirect_uri: str,
):
    print(f"\n{'='*60}")
    print(f"  YADS → Keycloak User Migration")
    print(f"  Modus:    {'DRY-RUN (keine Änderungen)' if dry_run else 'LIVE'}")
    print(f"  Keycloak: {keycloak_url}")
    print(f"  Filter:   {tenant_filter or 'alle Tenants'}")
    print(f"{'='*60}\n")

    kc = KeycloakAdmin(keycloak_url, admin_user, admin_password)

    # Verbindung testen
    try:
        kc._get_token()
        print("[OK] Keycloak-Verbindung erfolgreich.\n")
    except Exception as e:
        print(f"[FEHLER] Keycloak nicht erreichbar: {e}")
        sys.exit(1)

    engine = create_engine(settings.DATABASE_URL)

    with engine.connect() as conn:
        # --- Tenants laden ---
        tenants = conn.execute(text('SELECT id, name FROM tenant ORDER BY id')).fetchall()
        if tenant_filter:
            tenants = [t for t in tenants if t.name.lower() == tenant_filter.lower()]

        if not tenants:
            print("[WARN] Keine Tenants gefunden (oder Filter greift nicht).")

        # --- Platform-Admin-Realm sicherstellen ---
        print("[1/4] Platform-Admin-Realm prüfen...")
        platform_realm = "yads-platform"
        if not dry_run:
            if not kc.realm_exists(platform_realm):
                kc.create_realm(platform_realm, "YADS Platform Admins")
                print(f"      Realm '{platform_realm}' angelegt.")
                client_uuid = kc.create_yads_client(platform_realm, redirect_uri)
                kc.add_client_mappers(platform_realm, client_uuid)
                print(f"      Client 'yads' + Mapper angelegt.")
            platform_admin_group_id = kc.ensure_platform_admin_group(platform_realm)
        else:
            print(f"      [DRY-RUN] Realm '{platform_realm}' würde angelegt werden.")
            platform_admin_group_id = "dry-run-id"

        # --- Tenant-Realms anlegen ---
        print(f"\n[2/4] {len(tenants)} Tenant-Realm(s) anlegen...")
        tenant_group_map = {}  # tenant_name → {suffix: group_id}

        for tenant in tenants:
            # Keycloak Realm-Namen: lowercase, Leerzeichen → Bindestrich, nur [a-z0-9-_.]
            realm = re.sub(r'[^a-z0-9._-]', '-', tenant.name.lower()).strip('-')
            display = tenant.name
            print(f"\n  Tenant: {display} → Realm: {realm}")
            if not dry_run:
                if not kc.realm_exists(realm):
                    kc.create_realm(realm, f"YADS – {display}")
                    print(f"    Realm '{realm}' neu angelegt.")
                else:
                    print(f"    Realm '{realm}' bereits vorhanden.")
                client_uuid = kc.create_yads_client(realm, redirect_uri)
                kc.add_client_mappers(realm, client_uuid)
                groups = kc.ensure_tenant_groups(realm)
                tenant_group_map[display] = groups
                print(f"    Gruppen: {list(groups.keys())}")
            else:
                print(f"    [DRY-RUN] Realm '{realm}' + Client + Gruppen würden angelegt.")
                tenant_group_map[display] = {"admins": "dry", "scanners": "dry", "auditors": "dry"}

        # --- User laden und migrieren ---
        print(f"\n[3/4] User migrieren...")

        # Platform-Admins: role='admin' (tenant_id kann NULL oder gesetzt sein)
        platform_users = conn.execute(text(
            "SELECT id, username, email, role, is_active, auth_mode, oidc_sub "
            "FROM \"user\" WHERE role = 'admin'"
        )).fetchall()

        # Tenant-User
        if tenant_filter:
            # Admins only in yads-platform, filter by tenant name
            query = (
                'SELECT u.id, u.username, u.email, u.role, u.is_active, u.auth_mode, '
                'u.oidc_sub, t.name as tenant_name '
                'FROM "user" u JOIN tenant t ON u.tenant_id = t.id '
                "WHERE u.role != 'admin' AND lower(t.name) = lower(:tf) "
                'ORDER BY t.name, u.role, u.username'
            )
            params = {"tf": tenant_filter}
        else:
            # Admins only in yads-platform, all tenants
            query = (
                'SELECT u.id, u.username, u.email, u.role, u.is_active, u.auth_mode, '
                'u.oidc_sub, t.name as tenant_name '
                'FROM "user" u JOIN tenant t ON u.tenant_id = t.id '
                "WHERE u.role != 'admin' "
                'ORDER BY t.name, u.role, u.username'
            )
            params = {}

        tenant_users = conn.execute(text(query), params).fetchall()

        migrated = 0
        skipped = 0
        errors = 0

        # Platform-Admins migrieren
        print(f"\n  Platform-Admins ({len(platform_users)} User):")
        for u in platform_users:
            if u.oidc_sub and u.auth_mode == "oidc":
                print(f"    SKIP {u.username} — bereits migriert (oidc_sub={u.oidc_sub[:8]}...)")
                skipped += 1
                continue

            first, last = split_full_name(u.username)
            print(f"    {'[DRY] ' if dry_run else ''}Migriere {u.username} → {platform_realm}/yads-platform-admins")

            if not dry_run:
                try:
                    user_id = kc.create_user(platform_realm, u.username, u.email or "", first, last)
                    kc.set_temp_password(platform_realm, user_id, temp_password)
                    kc.assign_group(platform_realm, user_id, platform_admin_group_id)
                    # oidc_sub zurückschreiben
                    conn.execute(text(
                        'UPDATE "user" SET oidc_sub = :sub, auth_mode = :mode WHERE id = :id'
                    ), {"sub": user_id, "mode": "oidc", "id": u.id})
                    conn.commit()
                    migrated += 1
                except Exception as e:
                    print(f"    [FEHLER] {u.username}: {e}")
                    errors += 1
            else:
                migrated += 1

        # Tenant-User migrieren
        print(f"\n  Tenant-User ({len(tenant_users)} User):")
        for u in tenant_users:
            if u.oidc_sub and u.auth_mode == "oidc":
                print(f"    SKIP {u.username} ({u.tenant_name}) — bereits migriert")
                skipped += 1
                continue

            realm = u.tenant_name
            if realm not in tenant_group_map:
                print(f"    SKIP {u.username} — Tenant '{realm}' nicht im Scope")
                skipped += 1
                continue

            role_suffix = ROLE_TO_GROUP.get(u.role, "auditors")
            group_id = tenant_group_map[realm].get(
                role_suffix.rstrip("s") if role_suffix.endswith("s") else role_suffix,
                tenant_group_map[realm].get("auditors")
            )
            # Korrekte Gruppen-ID holen
            group_suffix_map = {
                "tenant_admin": "admins",
                "scanner": "scanners",
                "auditor": "auditors",
            }
            group_key = group_suffix_map.get(u.role, "auditors")
            group_id = tenant_group_map[realm][group_key]

            print(f"    {'[DRY] ' if dry_run else ''}Migriere {u.username} "
                  f"({u.tenant_name}, {u.role}) → {realm}/{realm}-{group_key}")

            if not dry_run:
                try:
                    first, last = split_full_name(u.username)
                    user_id = kc.create_user(realm, u.username, u.email or "", first, last)
                    kc.set_temp_password(realm, user_id, temp_password)
                    kc.assign_group(realm, user_id, group_id)
                    conn.execute(text(
                        'UPDATE "user" SET oidc_sub = :sub, auth_mode = :mode WHERE id = :id'
                    ), {"sub": user_id, "mode": "oidc", "id": u.id})
                    conn.commit()
                    migrated += 1
                except Exception as e:
                    print(f"    [FEHLER] {u.username}: {e}")
                    errors += 1
            else:
                migrated += 1

        # --- Zusammenfassung ---
        print(f"\n[4/4] Migration abgeschlossen.")
        print(f"{'='*60}")
        print(f"  Migriert:   {migrated}")
        print(f"  Übersprungen: {skipped} (bereits migriert)")
        print(f"  Fehler:     {errors}")
        if dry_run:
            print(f"\n  ⚠  DRY-RUN — keine Änderungen wurden vorgenommen.")
            print(f"     Führe ohne --dry-run aus um die Migration durchzuführen.")
        else:
            print(f"\n  Temporäres Passwort: {temp_password}")
            print(f"  Alle migrierten User müssen beim ersten Login ein neues Passwort setzen.")
        print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Migriert YADS-User und Tenants nach Keycloak."
    )
    parser.add_argument(
        "--keycloak-url",
        default=os.getenv("OIDC_PUBLIC_URL", "http://localhost:8080"),
        help="Keycloak Base-URL (Default: OIDC_PUBLIC_URL oder http://localhost:8080)",
    )
    parser.add_argument(
        "--admin-user",
        default=os.getenv("KC_ADMIN", "admin"),
        help="Keycloak Admin-Username (Default: admin)",
    )
    parser.add_argument(
        "--admin-password",
        default=os.getenv("KC_ADMIN_PASSWORD", "admin"),
        help="Keycloak Admin-Passwort (Default: admin)",
    )
    parser.add_argument(
        "--temp-password",
        default="Yads_Migrate_2024!",
        help="Temporäres Passwort für neue Keycloak-User (Default: Yads_Migrate_2024!)",
    )
    parser.add_argument(
        "--redirect-uri",
        default=os.getenv("OIDC_REDIRECT_URI", "http://localhost:8085/auth/oidc/callback"),
        help="YADS OIDC Redirect-URI für den Keycloak-Client",
    )
    parser.add_argument(
        "--tenant",
        default=None,
        help="Nur diesen Tenant migrieren (Name). Ohne Angabe: alle Tenants.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Nur Vorschau — keine Änderungen in Keycloak oder YADS-DB.",
    )

    args = parser.parse_args()

    migrate(
        keycloak_url=args.keycloak_url,
        admin_user=args.admin_user,
        admin_password=args.admin_password,
        temp_password=args.temp_password,
        dry_run=args.dry_run,
        tenant_filter=args.tenant,
        redirect_uri=args.redirect_uri,
    )
