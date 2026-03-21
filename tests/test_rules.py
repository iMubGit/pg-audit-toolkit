"""
Tests for pg_audit_toolkit rules.

Uses mocking to avoid requiring a live PostgreSQL connection.
All database interactions are simulated via unittest.mock.
"""
import pytest
from unittest.mock import MagicMock, patch
from pg_audit_toolkit.rules import (
    check_privileges,
    check_excessive_privileges,
    check_pii_columns,
)
from pg_audit_toolkit.models import RiskLevel


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_mock_conn(rows: list) -> MagicMock:
    """Create a mock database connection that returns the given rows."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = rows
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn


# ── check_privileges tests ────────────────────────────────────────────────────

def test_flags_non_system_superuser():
    """A non-system role with SUPERUSER should be flagged as CRITICAL."""
    conn = make_mock_conn([
        ("app_user", True, False, False),
    ])
    findings = check_privileges(conn)
    assert len(findings) == 1
    assert findings[0].risk == RiskLevel.CRITICAL
    assert findings[0].object == "app_user"


def test_skips_postgres_superuser():
    """The built-in postgres role should never be flagged."""
    conn = make_mock_conn([
        ("postgres", True, True, True),
    ])
    findings = check_privileges(conn)
    assert len(findings) == 0


def test_skips_pg_monitor_role():
    """Built-in pg_monitor role should never be flagged."""
    conn = make_mock_conn([
        ("pg_monitor", False, False, False),
    ])
    findings = check_privileges(conn)
    assert len(findings) == 0


def test_no_findings_on_clean_roles():
    """Roles without superuser and not in system roles should not be flagged."""
    conn = make_mock_conn([
        ("readonly_user", False, False, False),
        ("reporting_user", False, False, False),
    ])
    findings = check_privileges(conn)
    assert len(findings) == 0


def test_flags_multiple_superusers():
    """Multiple non-system superuser roles should all be flagged."""
    conn = make_mock_conn([
        ("app_user", True, False, False),
        ("admin_user", True, False, False),
        ("postgres", True, True, True),  # should be skipped
    ])
    findings = check_privileges(conn)
    assert len(findings) == 2
    objects = [f.object for f in findings]
    assert "app_user" in objects
    assert "admin_user" in objects
    assert "postgres" not in objects


# ── check_excessive_privileges tests ─────────────────────────────────────────

def test_flags_createrole_privilege():
    """A role with CREATEROLE should be flagged as HIGH."""
    conn = make_mock_conn([
        ("power_user", True, False),
    ])
    findings = check_excessive_privileges(conn)
    assert any(f.risk == RiskLevel.HIGH for f in findings)
    assert any("create other roles" in f.issue for f in findings)


def test_flags_createdb_privilege():
    """A role with CREATEDB should be flagged as MEDIUM."""
    conn = make_mock_conn([
        ("dev_user", False, True),
    ])
    findings = check_excessive_privileges(conn)
    assert any(f.risk == RiskLevel.MEDIUM for f in findings)


def test_skips_system_roles_in_excessive_privileges():
    """System roles should be skipped in excessive privilege checks."""
    conn = make_mock_conn([
        ("postgres", True, True),
        ("pg_monitor", False, False),
    ])
    findings = check_excessive_privileges(conn)
    assert len(findings) == 0


# ── check_pii_columns tests ───────────────────────────────────────────────────

def test_flags_email_column():
    """A column named email should be flagged as HIGH."""
    conn = make_mock_conn([
        ("users", "email"),
    ])
    findings = check_pii_columns(conn)
    assert len(findings) == 1
    assert findings[0].risk == RiskLevel.HIGH
    assert "users.email" == findings[0].object


def test_flags_multiple_pii_columns():
    """Multiple PII columns should all be flagged."""
    conn = make_mock_conn([
        ("users", "email"),
        ("customers", "bvn"),
        ("accounts", "password"),
    ])
    findings = check_pii_columns(conn)
    assert len(findings) == 3


def test_no_pii_findings_on_clean_schema():
    """A schema with no PII column names should produce zero findings."""
    conn = make_mock_conn([])
    findings = check_pii_columns(conn)
    assert len(findings) == 0


def test_pii_finding_control_reference():
    """PII findings should reference NDPA and SOC 2 controls."""
    conn = make_mock_conn([
        ("users", "email"),
    ])
    findings = check_pii_columns(conn)
    assert "NDPA" in findings[0].control
    assert "SOC 2" in findings[0].control
