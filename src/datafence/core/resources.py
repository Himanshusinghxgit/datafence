"""
DataFence Resource / Execution IR (Phase 2).

This module provides TYPED security objects for the execution intermediate
representation (IR).  Instead of raw strings, connectors receive typed
objects that can be validated and compiled into safe parameterised queries.

The hierarchy:

    ResourceRef   — identifies a data resource by namespace + name
    FieldRef      — identifies a single field within a resource
    Predicate     — a single comparison (field op value)
    Filter        — a collection of Predicates (ANDed together)
    Projection    — the set of FieldRefs to return
    RowLimit      — maximum row count
    SortSpec      — optional ordering

These objects replace bare strings in AuthorizedExecution and ExecutionPlan,
eliminating a whole class of identifier-injection vulnerabilities.

Before this change, the SQLite connector could build:
    SELECT {fields} FROM {resource}          ← f-string, unsafe identifiers
    
After this change, the connector receives a typed Projection and ResourceRef,
and the SQL compiler validates every identifier against an allowlist before
interpolating it into the query.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Safe identifier validation
# ---------------------------------------------------------------------------

_SAFE_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def validate_identifier(name: str, context: str = "identifier") -> str:
    """
    Validate that *name* is a safe SQL identifier.

    Raises ValueError if *name* contains anything other than letters,
    digits, and underscores (and must start with a letter or underscore).
    This prevents identifier injection even when DataFence itself generates
    the SQL.
    """
    if not _SAFE_IDENTIFIER.match(name):
        raise ValueError(
            f"Unsafe {context}: {name!r}. "
            "Identifiers must match [A-Za-z_][A-Za-z0-9_]*"
        )
    return name


# ---------------------------------------------------------------------------
# Core IR types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResourceRef:
    """
    A typed reference to a data resource.

    Parameters
    ----------
    name : str
        Table / collection name (e.g. "transactions").
    namespace : str
        Optional schema / database qualifier (e.g. "banking", "public").
    """

    name: str
    namespace: str = ""

    def __post_init__(self) -> None:
        validate_identifier(self.name, context="resource name")
        if self.namespace:
            validate_identifier(self.namespace, context="resource namespace")

    def qualified_name(self) -> str:
        """Return the fully-qualified resource name."""
        if self.namespace:
            return f"{self.namespace}.{self.name}"
        return self.name

    @classmethod
    def from_string(cls, s: str) -> "ResourceRef":
        """Parse "namespace.name" or plain "name"."""
        parts = s.split(".", 1)
        if len(parts) == 2:
            return cls(name=parts[1], namespace=parts[0])
        return cls(name=s)


@dataclass(frozen=True)
class FieldRef:
    """
    A typed reference to a single field within a resource.

    Parameters
    ----------
    name : str
        Column / attribute name (e.g. "merchant", "amount").
    resource : ResourceRef | None
        Optional resource qualification for multi-table contexts.
    """

    name: str
    resource: ResourceRef | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.name, context="field name")

    @classmethod
    def from_string(cls, s: str) -> "FieldRef":
        """Parse "resource.field" or plain "field"."""
        parts = s.split(".", 1)
        if len(parts) == 2:
            return cls(name=parts[1], resource=ResourceRef.from_string(parts[0]))
        return cls(name=s)


class PredicateOperator(Enum):
    """Comparison operators supported in predicates."""

    EQ = "="
    NEQ = "!="
    LT = "<"
    LTE = "<="
    GT = ">"
    GTE = ">="
    IN = "IN"
    NOT_IN = "NOT IN"
    IS_NULL = "IS NULL"
    IS_NOT_NULL = "IS NOT NULL"


@dataclass(frozen=True)
class Predicate:
    """
    A single comparison predicate: field operator value.

    Used in WHERE clauses and policy row-filters.

    Parameters
    ----------
    field : FieldRef
        The field being compared.
    operator : PredicateOperator
        The comparison operator.
    value : Any
        The literal value or actor-attribute reference.
        Special string ":actor_tenant_id" resolves to the principal's tenant.
        Special string ":actor_id"        resolves to the principal's id.
        Any other string is treated as a literal.
    """

    field: FieldRef
    operator: PredicateOperator
    value: Any

    def is_actor_reference(self) -> bool:
        """Return True if value is an actor-attribute placeholder."""
        return isinstance(self.value, str) and self.value.startswith(":")

    def resolve(self, principal: Any) -> "Predicate":
        """
        Resolve actor-attribute references using the provided principal.

        Returns a new Predicate with the placeholder replaced by a real value.
        """
        if not self.is_actor_reference():
            return self
        ref = self.value
        if ref == ":actor_tenant_id":
            return Predicate(self.field, self.operator, principal.tenant_id)
        if ref == ":actor_id":
            return Predicate(self.field, self.operator, principal.id)
        # Try arbitrary attribute access: ":actor.department" → principal.attributes["department"]
        if ref.startswith(":actor."):
            attr_name = ref[len(":actor."):]
            attr_val = getattr(principal, attr_name, None)
            if attr_val is None:
                attr_val = principal.attributes.get(attr_name)
            if attr_val is None:
                raise ValueError(
                    f"Cannot resolve actor reference {ref!r}: "
                    f"principal has no attribute {attr_name!r}"
                )
            return Predicate(self.field, self.operator, attr_val)
        raise ValueError(f"Unknown actor reference: {ref!r}")


@dataclass(frozen=True)
class Filter:
    """
    A collection of Predicates ANDed together.

    This replaces the raw ``dict[str, Any]`` enforced_filters in the old model.
    """

    predicates: tuple[Predicate, ...]

    def __bool__(self) -> bool:
        return bool(self.predicates)

    @classmethod
    def empty(cls) -> "Filter":
        return cls(predicates=())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Filter":
        """
        Build a Filter from a legacy ``{field: value}`` dict.

        Each entry becomes an EQ predicate.
        Actor references (:actor_tenant_id etc.) are preserved.
        """
        preds = tuple(
            Predicate(
                field=FieldRef(name=k),
                operator=PredicateOperator.EQ,
                value=v,
            )
            for k, v in d.items()
        )
        return cls(predicates=preds)

    def to_dict(self) -> dict[str, Any]:
        """Convert back to legacy {field: value} dict (EQ predicates only)."""
        result: dict[str, Any] = {}
        for pred in self.predicates:
            if pred.operator == PredicateOperator.EQ:
                result[pred.field.name] = pred.value
        return result

    def merge(self, other: "Filter") -> "Filter":
        """
        Merge two filters, deduplicating on field name (self takes priority).
        Used to merge policy-enforced filters with intent-provided filters.
        """
        existing_fields = {p.field.name for p in self.predicates}
        added = tuple(
            p for p in other.predicates
            if p.field.name not in existing_fields
        )
        return Filter(predicates=self.predicates + added)

    def resolve(self, principal: Any) -> "Filter":
        """Resolve all actor-attribute references in the predicates."""
        return Filter(
            predicates=tuple(p.resolve(principal) for p in self.predicates)
        )


@dataclass(frozen=True)
class Projection:
    """
    The set of fields to return from a query.

    Replaces the raw ``list[str]`` selected_fields in the old model.
    """

    fields: tuple[FieldRef, ...]

    @classmethod
    def from_strings(cls, names: list[str]) -> "Projection":
        return cls(fields=tuple(FieldRef(name=n) for n in names))

    def field_names(self) -> list[str]:
        return [f.name for f in self.fields]

    def __bool__(self) -> bool:
        return bool(self.fields)

    def __len__(self) -> int:
        return len(self.fields)


@dataclass(frozen=True)
class RowLimit:
    """Maximum number of rows to return."""

    value: int

    def __post_init__(self) -> None:
        if self.value <= 0:
            raise ValueError(f"RowLimit must be positive, got {self.value}")

    @classmethod
    def default(cls) -> "RowLimit":
        return cls(value=100)


@dataclass(frozen=True)
class SortSpec:
    """Optional sort specification."""

    field: FieldRef
    ascending: bool = True
