import pytest
from sqlmodel import Session, SQLModel, create_engine
from sqlalchemy import event, TypeDecorator
from sqlalchemy.types import JSON
from sqlalchemy.dialects.sqlite import base as sqlite_base
from yads.models import Target
from yads.core.parked_domain_tags import PARKED_TAG_MAP, tag_parked_domain


@pytest.fixture
def session():
    """Create an in-memory SQLite engine, with JSONB support via JSON."""
    # Patch the SQLite type compiler to handle JSONB as JSON
    from sqlalchemy.dialects.postgresql import JSONB

    original_visit_JSONB = None
    try:
        original_visit_JSONB = sqlite_base.SQLiteTypeCompiler.visit_JSONB
    except AttributeError:
        pass

    # Add visit_JSONB method to SQLiteTypeCompiler
    def visit_JSONB(self, type_, **kw):
        return self.visit_JSON(type_, **kw)

    sqlite_base.SQLiteTypeCompiler.visit_JSONB = visit_JSONB

    try:
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            echo=False,
        )

        # Create all tables
        SQLModel.metadata.create_all(engine)

        with Session(engine) as s:
            yield s
    finally:
        # Cleanup
        if original_visit_JSONB:
            sqlite_base.SQLiteTypeCompiler.visit_JSONB = original_visit_JSONB
        else:
            delattr(sqlite_base.SQLiteTypeCompiler, 'visit_JSONB')


def _make_target(session, domain="example.com", tags=None):
    t = Target(domain=domain, tags=tags or [])
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


def test_known_signature_maps_to_expected_tag():
    # All commercial-parking vendors consolidate to the single provider-neutral
    # "parked" tag (see PARKED_TAG_MAP comment). placeholder-page stays distinct:
    # those are live default server splash pages, not commercially parked domains.
    assert PARKED_TAG_MAP["sedo"] == "parked"
    assert PARKED_TAG_MAP["godaddy_parked"] == "parked"
    assert PARKED_TAG_MAP["bodis"] == "parked"
    assert PARKED_TAG_MAP["generic_for_sale"] == "parked"
    assert PARKED_TAG_MAP["apache_default"] == "placeholder-page"
    assert PARKED_TAG_MAP["ionos_default"] == "placeholder-page"


def test_tag_parked_domain_appends_mapped_tag(session):
    target = _make_target(session)
    tag_parked_domain(session, target.id, "sedo")
    session.refresh(target)
    assert target.tags == ["parked"]


def test_tag_parked_domain_does_not_duplicate(session):
    target = _make_target(session, tags=["parked"])
    tag_parked_domain(session, target.id, "sedo")
    session.refresh(target)
    assert target.tags == ["parked"]


def test_tag_parked_domain_preserves_existing_tags(session):
    target = _make_target(session, tags=["customer-a"])
    tag_parked_domain(session, target.id, "godaddy_parked")
    session.refresh(target)
    assert set(target.tags) == {"customer-a", "parked"}


def test_placeholder_signature_stays_distinct(session):
    # Default server splash pages must NOT be folded into "parked".
    target = _make_target(session)
    tag_parked_domain(session, target.id, "nginx_default")
    session.refresh(target)
    assert target.tags == ["placeholder-page"]


def test_tag_parked_domain_unmapped_signature_falls_back_to_parked(session):
    # An unrecognized catch-all signature still means "parked" — the same tag
    # every known vendor now consolidates onto, so unknowns don't re-fragment.
    target = _make_target(session)
    tag_parked_domain(session, target.id, "some_unknown_signature")
    session.refresh(target)
    assert target.tags == ["parked"]


def test_tag_parked_domain_missing_target_is_noop(session):
    # Should not raise for a target_id that doesn't exist
    tag_parked_domain(session, 999999, "sedo")


def test_tag_parked_domain_handles_null_tags(session):
    # Existing rows can have tags IS NULL at the DB level (nullable column,
    # no server-side default) even though the model default is []. Bypass
    # the model default to simulate that and confirm tag_parked_domain
    # doesn't raise a TypeError on `None`.
    target = _make_target(session)
    target.tags = None
    session.add(target)
    session.commit()

    tag_parked_domain(session, target.id, "sedo")
    session.refresh(target)
    assert target.tags == ["parked"]


def _get_or_reset_target(db_session, tenant_id, domain):
    from yads.models import Target
    from sqlmodel import select
    t = db_session.exec(select(Target).where(Target.domain == domain)).first()
    if t:
        t.tags = []
        db_session.add(t); db_session.commit(); db_session.refresh(t)
        return t
    t = Target(domain=domain, tenant_id=tenant_id, tags=[])
    db_session.add(t); db_session.commit(); db_session.refresh(t)
    return t


def test_ns_based_signature_maps_to_parked(db_session, test_tenant):
    """NS-based detection (matched_signature 'ns:<provider>') consolidates onto
    the same provider-neutral 'parked' tag as every HTTP signature."""
    from yads.core.parked_domain_tags import tag_parked_domain

    t = _get_or_reset_target(db_session, test_tenant.id, "ns-parked-fixture.example.com")
    tag_parked_domain(db_session, t.id, "ns:sedoparking.com")
    db_session.refresh(t)
    assert "parked" in t.tags


def test_ns_unknown_provider_falls_back_to_parked(db_session, test_tenant):
    from yads.core.parked_domain_tags import tag_parked_domain

    t = _get_or_reset_target(db_session, test_tenant.id, "ns-unknown-fixture.example.com")
    tag_parked_domain(db_session, t.id, "ns:some-unknown-parker.example")
    db_session.refresh(t)
    assert "parked" in t.tags
