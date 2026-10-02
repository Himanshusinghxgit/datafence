"""
SQL Query Firewall.

Parses, validates, and rewrites SQL queries to prevent dangerous operations.
Uses sqlparse for proper SQL parsing (not regex).
"""

from enum import Enum

import sqlparse
from sqlparse import sql
from sqlparse.tokens import DDL, DML, Keyword, Name

from datafence.errors import ValidationError


class QueryRisk(str, Enum):
    """SQL query risk levels."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    BLOCKED = "blocked"


class DangerousOperation(str, Enum):
    """Dangerous SQL operations."""

    DROP = "DROP"
    TRUNCATE = "TRUNCATE"
    DELETE = "DELETE"
    UPDATE = "UPDATE"
    INSERT = "INSERT"
    ALTER = "ALTER"
    CREATE = "CREATE"
    GRANT = "GRANT"
    REVOKE = "REVOKE"
    EXEC = "EXEC"
    EXECUTE = "EXECUTE"


class SQLFirewall:
    """
    SQL query firewall.

    Validates SQL queries and blocks dangerous operations.
    """

    def __init__(
        self,
        allow_write: bool = False,
        allow_ddl: bool = False,
        allow_subqueries: bool = True,
        allow_unions: bool = True,
        block_comments: bool = True,
    ):
        """
        Initialize SQL firewall.

        Args:
            allow_write: Allow INSERT/UPDATE/DELETE operations
            allow_ddl: Allow DDL operations (CREATE/DROP/ALTER)
            allow_subqueries: Allow subqueries
            allow_unions: Allow UNION operations
            block_comments: Block SQL comments (防御注入攻击)
        """
        self.allow_write = allow_write
        self.allow_ddl = allow_ddl
        self.allow_subqueries = allow_subqueries
        self.allow_unions = allow_unions
        self.block_comments = block_comments

    def validate(self, query: str) -> tuple[QueryRisk, list[str]]:
        """
        Validate a SQL query.

        Args:
            query: SQL query to validate

        Returns:
            Tuple of (risk_level, reasons)

        Raises:
            ValidationError: If query is invalid
        """
        if not query or not query.strip():
            raise ValidationError("Empty query")

        reasons: list[str] = []

        # Parse query
        try:
            parsed = sqlparse.parse(query)
        except Exception as e:
            raise ValidationError(f"Failed to parse SQL query: {e}") from e

        if not parsed:
            raise ValidationError("Failed to parse SQL query")

        # Check each statement
        for statement in parsed:
            stmt_risk, stmt_reasons = self._validate_statement(statement)
            reasons.extend(stmt_reasons)

            if stmt_risk == QueryRisk.BLOCKED:
                return QueryRisk.BLOCKED, reasons
            elif stmt_risk == QueryRisk.DANGEROUS:
                return QueryRisk.DANGEROUS, reasons

        # If we got here, query is safe or suspicious
        if reasons:
            return QueryRisk.SUSPICIOUS, reasons

        return QueryRisk.SAFE, []

    def _validate_statement(self, statement: sql.Statement) -> tuple[QueryRisk, list[str]]:
        """Validate a single SQL statement."""
        reasons: list[str] = []

        # Check for comments
        if self.block_comments:
            if self._has_comments(statement):
                return (
                    QueryRisk.BLOCKED,
                    ["SQL comments are not allowed (potential injection vector)"],
                )

        # Get statement type
        stmt_type = statement.get_type()

        # Check DDL operations
        if stmt_type in ("DROP", "TRUNCATE", "ALTER", "CREATE"):
            if not self.allow_ddl:
                return (
                    QueryRisk.BLOCKED,
                    [f"DDL operation '{stmt_type}' is not allowed"],
                )
            else:
                reasons.append(f"DDL operation '{stmt_type}' detected")
                return QueryRisk.DANGEROUS, reasons

        # Check DML write operations
        if stmt_type in ("DELETE", "UPDATE", "INSERT"):
            if not self.allow_write:
                return (
                    QueryRisk.BLOCKED,
                    [f"Write operation '{stmt_type}' is not allowed"],
                )
            else:
                reasons.append(f"Write operation '{stmt_type}' detected")
                return QueryRisk.DANGEROUS, reasons

        # Check for dangerous keywords
        dangerous = self._find_dangerous_keywords(statement)
        if dangerous:
            return (
                QueryRisk.BLOCKED,
                [f"Dangerous keywords found: {', '.join(dangerous)}"],
            )

        # Check UNION
        if not self.allow_unions:
            if self._has_union(statement):
                return QueryRisk.BLOCKED, ["UNION operations are not allowed"]

        # Check subqueries
        if not self.allow_subqueries:
            if self._has_subquery(statement):
                return QueryRisk.BLOCKED, ["Subqueries are not allowed"]

        return QueryRisk.SAFE, reasons

    def _has_comments(self, statement: sql.Statement) -> bool:
        """Check if statement contains comments."""
        for token in statement.flatten():
            if token.ttype in (
                sqlparse.tokens.Comment.Single,
                sqlparse.tokens.Comment.Multiline,
            ):
                return True
        return False

    def _find_dangerous_keywords(self, statement: sql.Statement) -> list[str]:
        """Find dangerous keywords in statement."""
        dangerous = []

        for token in statement.flatten():
            if token.ttype in (Keyword, DML, DDL):
                value = token.value.upper()
                if value in (
                    "EXEC",
                    "EXECUTE",
                    "GRANT",
                    "REVOKE",
                    "SHUTDOWN",
                    "KILL",
                ):
                    dangerous.append(value)
            # Also check if token is a keyword by value
            elif token.is_keyword:
                value = token.value.upper()
                if value in ("GRANT", "REVOKE", "EXEC", "EXECUTE"):
                    dangerous.append(value)

        return dangerous

    def _has_union(self, statement: sql.Statement) -> bool:
        """Check if statement contains UNION."""
        for token in statement.flatten():
            if token.ttype is Keyword and token.value.upper() == "UNION":
                return True
        return False

    def _has_subquery(self, statement: sql.Statement) -> bool:
        """Check if statement contains subqueries."""
        for token in statement.tokens:
            if isinstance(token, sql.Parenthesis):
                # Check if parenthesis contains SELECT
                sub_tokens = [
                    t for t in token.flatten() if t.ttype is DML and t.value.upper() == "SELECT"
                ]
                if sub_tokens:
                    return True
        return False

    def check_or_block(self, query: str) -> None:
        """
        Check query and raise exception if blocked.

        Args:
            query: SQL query to check

        Raises:
            ValidationError: If query is blocked
        """
        risk, reasons = self.validate(query)

        if risk == QueryRisk.BLOCKED:
            raise ValidationError(f"SQL query blocked: {'; '.join(reasons)}\nQuery: {query[:100]}")

        if risk == QueryRisk.DANGEROUS:
            # Log but don't block
            # In production, you might want to add extra logging here
            pass


def extract_tables(query: str) -> list[str]:
    """
    Extract table names from SQL query.

    Args:
        query: SQL query

    Returns:
        List of table names
    """
    tables = []

    try:
        parsed = sqlparse.parse(query)
        for statement in parsed:
            tables.extend(_extract_tables_from_statement(statement))
    except Exception:
        # If parsing fails, return empty list
        pass

    return list(set(tables))


def _extract_tables_from_statement(statement: sql.Statement) -> list[str]:
    """Extract table names from a statement."""
    tables = []

    # Simple approach: look for identifiers after FROM and JOIN keywords
    tokens = list(statement.flatten())

    for i, token in enumerate(tokens):
        if token.ttype is Keyword and token.value.upper() in ("FROM", "JOIN"):
            # Next non-whitespace token should be table name
            for j in range(i + 1, len(tokens)):
                next_token = tokens[j]
                if next_token.ttype in Name and str(next_token).strip():
                    # This might be a table name
                    name = str(next_token).strip()
                    # Remove alias if present
                    name = name.split()[0]
                    if name and name.upper() not in (
                        "WHERE",
                        "ON",
                        "INNER",
                        "LEFT",
                        "RIGHT",
                        "OUTER",
                        "JOIN",
                    ):
                        tables.append(name)
                    break
                elif next_token.ttype not in (sqlparse.tokens.Whitespace, sqlparse.tokens.Newline):
                    break

    return tables


def normalize_query(query: str) -> str:
    """
    Normalize SQL query for consistent formatting.

    Args:
        query: SQL query

    Returns:
        Normalized query
    """
    try:
        # Parse and format
        formatted = sqlparse.format(
            query,
            reindent=False,
            keyword_case="upper",
            identifier_case="lower",
            strip_comments=True,
            use_space_around_operators=False,  # Changed to avoid extra spaces
        )
        # Clean up extra whitespace
        formatted = " ".join(formatted.split())
        return formatted.strip()
    except Exception:
        # If formatting fails, return cleaned version
        return " ".join(query.split())
