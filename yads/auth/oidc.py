"""
OIDC/Keycloak Authentication für YADS.
Aktiviert via AUTH_MODE=oidc in config.py.

Flow:
1. User klickt "Mit SSO anmelden"
2. Redirect zu Keycloak /auth endpoint
3. Keycloak redirectet zurück zu /auth/oidc/callback mit code
4. YADS tauscht code gegen tokens
5. YADS extrahiert claims (sub, groups, yads_tenant)
6. YADS erstellt/aktualisiert User in DB
7. YADS erstellt eigenes Session-Cookie (wie lokaler Login)
"""

import logging
import httpx
from typing import Optional, Dict, Any
from datetime import datetime
from jose import jwt as jose_jwt, JWTError
from sqlmodel import Session, select

from yads.config import settings
from yads.models import User, Tenant

logger = logging.getLogger("yads.auth.oidc")

# Rollen-Mapping: Keycloak-Gruppe → YADS-Rolle
ROLE_MAPPING = {
    "yads-platform-admins": "admin",
    # Tenant-spezifische Gruppen: {tenant}-admins → tenant_admin
    # Erkannt via Suffix-Matching unten
}


def get_oidc_config() -> Dict[str, str]:
    """Gibt OIDC-Konfiguration aus Settings zurück."""
    return {
        "server_url": settings.OIDC_SERVER_URL,
        "realm": settings.OIDC_REALM,
        "client_id": settings.OIDC_CLIENT_ID,
        "client_secret": settings.OIDC_CLIENT_SECRET,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
    }


def get_authorization_url(realm: str = None) -> str:
    """
    Baut die Keycloak-Autorisierungs-URL.
    realm: Optional — überschreibt Default-Realm aus Settings.
    Verwendet OIDC_PUBLIC_URL für Browser-Redirect (nicht Docker-internal URL).
    """
    cfg = get_oidc_config()
    r = realm or cfg["realm"]
    # OIDC_PUBLIC_URL: extern erreichbar (Browser), nicht OIDC_SERVER_URL (Docker-intern)
    public_url = settings.OIDC_PUBLIC_URL.rstrip("/")
    base = f"{public_url}/realms/{r}/protocol/openid-connect/auth"
    params = (
        f"?client_id={cfg['client_id']}"
        f"&redirect_uri={cfg['redirect_uri']}"
        f"&response_type=code"
        f"&scope=openid+profile+email+groups"
    )
    return base + params


def exchange_code_for_token(code: str, realm: str = None) -> Optional[Dict[str, Any]]:
    """
    Tauscht Authorization Code gegen Access + ID Token.
    Gibt Token-Response dict zurück oder None bei Fehler.
    """
    cfg = get_oidc_config()
    r = realm or cfg["realm"]
    token_url = f"{cfg['server_url']}/realms/{r}/protocol/openid-connect/token"

    try:
        response = httpx.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "code": code,
                "redirect_uri": cfg["redirect_uri"],
            },
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"OIDC token exchange failed: {e}")
        return None


def decode_token_claims(token_response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Dekodiert JWT-Claims aus dem Access-Token (ohne Signatur-Verifikation im Dev-Modus).
    In Produktion: Public Key von Keycloak JWKS-Endpoint holen.
    """
    try:
        id_token = token_response.get("access_token") or token_response.get("id_token")
        if not id_token:
            return None
        # Dev: decode ohne Signatur-Verifikation (Keycloak ist lokal vertrauenswürdig)
        claims = jose_jwt.decode(
            id_token,
            key="",
            algorithms=["RS256", "HS256"],
            options={"verify_signature": False, "verify_exp": False},
        )
        return claims
    except JWTError as e:
        logger.error(f"JWT decode failed: {e}")
        return None
    except Exception as e:
        logger.error(f"JWT decode unexpected error: {e}")
        return None


def map_groups_to_role(groups: list, yads_tenant: str = None) -> str:
    """
    Mappt Keycloak-Gruppen auf YADS-Rolle.

    Mapping-Logik:
    - yads-platform-admins → admin
    - {tenant}-admins      → tenant_admin
    - {tenant}-scanners    → scanner
    - {tenant}-auditors    → auditor
    """
    if not groups:
        return "auditor"  # Default: minimale Rechte

    # Platform Admin hat Vorrang
    if "yads-platform-admins" in groups:
        return "admin"

    # Tenant-spezifische Gruppen
    for group in groups:
        if group.endswith("-admins"):
            return "tenant_admin"
        if group.endswith("-scanners"):
            return "scanner"
        if group.endswith("-auditors"):
            return "auditor"

    return "auditor"


def get_or_create_user(session: Session, claims: Dict[str, Any]) -> Optional[User]:
    """
    Erstellt oder aktualisiert einen YADS-User basierend auf OIDC-Claims.

    Claims die erwartet werden:
    - sub: Keycloak User-ID (eindeutig)
    - email: E-Mail-Adresse
    - given_name / family_name: Name
    - groups: Liste der Keycloak-Gruppen
    - yads_tenant: Tenant-Name (Custom Claim aus Keycloak)
    """
    oidc_sub = claims.get("sub")
    if not oidc_sub:
        logger.error("OIDC claim missing: sub")
        return None

    email = claims.get("email", "")
    yads_tenant = claims.get("yads_tenant", "")
    groups = claims.get("groups", [])
    role = map_groups_to_role(groups, yads_tenant)

    # Tenant in DB finden
    tenant_id = None
    if yads_tenant and yads_tenant != "platform":
        tenant = session.exec(
            select(Tenant).where(Tenant.name == yads_tenant)
        ).first()
        if tenant:
            tenant_id = tenant.id
        else:
            logger.warning(f"OIDC: Tenant '{yads_tenant}' not found in DB")

    # Bestehenden User per oidc_sub suchen
    user = session.exec(
        select(User).where(User.oidc_sub == oidc_sub)
    ).first()

    if user:
        # User aktualisieren (Rolle/Tenant können sich in Keycloak ändern)
        user.role = role
        user.tenant_id = tenant_id
        user.oidc_tenant = yads_tenant
        user.last_login = datetime.utcnow()
        session.add(user)
        session.commit()
        logger.info(f"OIDC: Updated user {email} (sub={oidc_sub}, role={role})")
        return user

    # Fallback: per E-Mail suchen (Migration lokaler User)
    if email:
        user = session.exec(select(User).where(User.email == email)).first()
        if user:
            user.oidc_sub = oidc_sub
            user.auth_mode = "oidc"
            user.role = role
            user.oidc_tenant = yads_tenant
            session.add(user)
            session.commit()
            logger.info(f"OIDC: Linked existing user {email} to OIDC sub={oidc_sub}")
            return user

    # Neuen User anlegen
    username = claims.get("preferred_username") or (email.split("@")[0] if email else oidc_sub)
    first_name = claims.get("given_name", "")
    last_name = claims.get("family_name", "")

    new_user = User(
        username=username,
        email=email,
        full_name=f"{first_name} {last_name}".strip(),
        role=role,
        tenant_id=tenant_id,
        auth_mode="oidc",
        oidc_sub=oidc_sub,
        oidc_tenant=yads_tenant,
        is_active=True,
        password_hash="",  # Kein lokales Passwort
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    logger.info(f"OIDC: Created new user {email} (role={role}, tenant={yads_tenant})")
    return new_user
