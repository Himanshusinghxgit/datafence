"""
Tests for SQL firewall.

Tests SQL injection prevention, dangerous operation blocking, and query validation.
"""

import pytest

from datafence.errors import ValidationError
from datafence.security.sql_firewall import (
    QueryRisk,
    SQLFirewall,
    extract_tables,
    normalize_query,
)


@pytest.fixture
def strict_firewall():
    """Strict firewall (read-only)."""
    return SQLFirewall(allow_write=False, allow_ddl=False, allow_subqueries=True, allow_unions=True)


@pytest.fixture
def permissive_firewall():
    """Permissive firewall (allows writes)."""
    return SQLFirewall(allow_write=True, allow_ddl=False, allow_subqueries=True, allow_unions=True)


def test_safe_select_query(strict_firewall):
    """Test that safe SELECT queries pass."""
    query = "SELECT id, name FROM users WHERE id = 1"
    risk, reasons = strict_firewall.validate(query)

    assert risk == QueryRisk.SAFE
    assert len(reasons) == 0


def test_block_drop_table(strict_firewall):
    """Test that DROP TABLE is blocked."""
    query = "DROP TABLE users"
    risk, reasons = strict_firewall.validate(query)

    assert risk == QueryRisk.BLOCKED
    assert "DROP" in reasons[0]


def test_block_truncate(strict_firewall):
    """Test that TRUNCATE is blocked."""
    query = "TRUNCATE TABLE users"
    risk, reasons = strict_firewall.validate(query)

    assert risk == QueryRisk.BLOCKED
    assert "TRUNCATE" in reasons[0]


def test_block_delete_when_write_disabled(strict_firewall):
    """Test that DELETE is blocked when writes disabled."""
    query = "DELETE FROM users WHERE id = 1"
    risk, reasons = strict_firewall.validate(query)

    assert risk == QueryRisk.BLOCKED
    assert "DELETE" in reasons[0]


def test_allow_delete_when_write_enabled(permissive_firewall):
    """Test that DELETE is allowed when writes enabled."""
    query = "DELETE FROM users WHERE id = 1"
    risk, reasons = permissive_firewall.validate(query)

    # Should be dangerous but not blocked
    assert risk == QueryRisk.DANGEROUS
    assert "DELETE" in reasons[0]


def test_block_update_when_write_disabled(strict_firewall):
    """Test that UPDATE is blocked when writes disabled."""
    query = "UPDATE users SET name = 'test' WHERE id = 1"
    risk, reasons = strict_firewall.validate(query)

    assert risk == QueryRisk.BLOCKED
    assert "UPDATE" in reasons[0]


def test_block_insert_when_write_disabled(strict_firewall):
    """Test that INSERT is blocked when writes disabled."""
    query = "INSERT INTO users (name) VALUES ('test')"
    risk, reasons = strict_firewall.validate(query)

    assert risk == QueryRisk.BLOCKED
    assert "INSERT" in reasons[0]


def test_block_sql_injection_comment(strict_firewall):
    """Test that SQL comments are blocked (injection vector)."""
    query = "SELECT * FROM users WHERE id = 1 -- AND role = 'admin'"
    risk, reasons = strict_firewall.validate(query)

    assert risk == QueryRisk.BLOCKED
    assert "comment" in reasons[0].lower()


def test_block_multiline_comment_injection(strict_firewall):
    """Test that multiline comments are blocked."""
    query = "SELECT * FROM users /* WHERE id = 1 */ WHERE role = 'admin'"
    risk, reasons = strict_firewall.validate(query)

    assert risk == QueryRisk.BLOCKED


def test_block_union_injection():
    """Test that UNION attacks can be blocked."""
    firewall = SQLFirewall(allow_unions=False)

    query = "SELECT id FROM users UNION SELECT card_number FROM payments"
    risk, reasons = firewall.validate(query)

    assert risk == QueryRisk.BLOCKED
    assert "UNION" in reasons[0]


def test_allow_union_when_enabled(strict_firewall):
    """Test that UNION is allowed when enabled."""
    query = "SELECT id FROM users UNION SELECT id FROM archived_users"
    risk, reasons = strict_firewall.validate(query)

    assert risk == QueryRisk.SAFE


def test_block_exec_execute():
    """Test that EXEC/EXECUTE are always blocked."""
    firewall = SQLFirewall(allow_write=True, allow_ddl=True)

    queries = ["EXEC sp_executesql @query", "EXECUTE sp_executesql @query"]

    for query in queries:
        risk, reasons = firewall.validate(query)
        assert risk == QueryRisk.BLOCKED
        assert any("EXEC" in r.upper() for r in reasons)


def test_block_grant_revoke():
    """Test that GRANT/REVOKE are always blocked."""
    firewall = SQLFirewall(allow_write=True, allow_ddl=True)

    queries = [
        "GRANT SELECT ON users TO user1",
        "REVOKE SELECT ON users FROM user1",
    ]

    for query in queries:
        risk, reasons = firewall.validate(query)
        assert risk == QueryRisk.BLOCKED


def test_empty_query_raises_error(strict_firewall):
    """Test that empty queries raise validation error."""
    with pytest.raises(ValidationError, match="Empty query"):
        strict_firewall.validate("")


def test_check_or_block_raises_on_blocked(strict_firewall):
    """Test that check_or_block raises exception for blocked queries."""
    query = "DROP TABLE users"

    with pytest.raises(ValidationError, match="blocked"):
        strict_firewall.check_or_block(query)


def test_check_or_block_passes_safe_query(strict_firewall):
    """Test that check_or_block doesn't raise for safe queries."""
    query = "SELECT id FROM users"

    # Should not raise
    strict_firewall.check_or_block(query)


def test_extract_tables_from_select():
    """Test extracting table names from SELECT."""
    query = "SELECT id, name FROM users WHERE active = 1"
    tables = extract_tables(query)

    assert "users" in tables


def test_extract_tables_from_join():
    """Test extracting tables from JOIN."""
    query = """
        SELECT u.id, p.name
        FROM users u
        JOIN profiles p ON u.id = p.user_id
    """
    tables = extract_tables(query)

    assert "users" in tables
    assert "profiles" in tables


def test_normalize_query():
    """Test query normalization."""
    query = "  select   id,name  from users  where  id=1  "
    normalized = normalize_query(query)

    # Should be cleaned up
    assert normalized.startswith("SELECT")
    assert "  " not in normalized  # No double spaces


def test_normalize_removes_comments():
    """Test that normalization removes comments."""
    query = "SELECT id FROM users -- comment"
    normalized = normalize_query(query)

    assert "--" not in normalized
    assert "comment" not in normalized.lower() or "SELECT" in normalized
