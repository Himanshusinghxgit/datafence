"""
Structured logging for DataFence.

JSON logging with contextual information for production observability.
"""

import logging
import json
import sys
from datetime import datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    """
    JSON log formatter.

    Outputs logs in structured JSON format for easy parsing and analysis.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "actor_id"):
            log_data["actor_id"] = record.actor_id
        if hasattr(record, "tenant_id"):
            log_data["tenant_id"] = record.tenant_id
        if hasattr(record, "resource"):
            log_data["resource"] = record.resource
        if hasattr(record, "operation"):
            log_data["operation"] = record.operation
        if hasattr(record, "decision"):
            log_data["decision"] = record.decision
        if hasattr(record, "duration_ms"):
            log_data["duration_ms"] = record.duration_ms

        return json.dumps(log_data)


def setup_logging(
    level: str = "INFO",
    format: str = "json",
    output: str = "stdout",
) -> logging.Logger:
    """
    Setup structured logging for DataFence.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format: Log format ("json" or "text")
        output: Output destination ("stdout", "stderr", or file path)

    Returns:
        Root logger

    Example:
        setup_logging(level="INFO", format="json")
        logger = get_logger(__name__)
        logger.info("Request processed", extra={"actor_id": "user:123"})
    """
    # Get root logger
    root_logger = logging.getLogger("datafence")
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create handler
    if output == "stdout":
        handler = logging.StreamHandler(sys.stdout)
    elif output == "stderr":
        handler = logging.StreamHandler(sys.stderr)
    else:
        handler = logging.FileHandler(output)

    # Set formatter
    if format == "json":
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(f"datafence.{name}")


class LoggingMiddleware:
    """
    Middleware for automatic request logging.

    Logs all requests with contextual information.
    """

    def __init__(self, fence: Any, logger: logging.Logger | None = None):
        self.fence = fence
        self.logger = logger or get_logger("middleware")

    def execute(self, request_dict: dict[str, Any]) -> Any:
        """Execute request with logging."""
        import time

        actor = request_dict.get("actor", {})
        actor_id = actor.get("id", "unknown")
        tenant_id = actor.get("tenant_id", "unknown")
        operation = request_dict.get("operation", "unknown")
        resource = request_dict.get("resource", "unknown")

        # Log request start
        self.logger.info(
            "Request started",
            extra={
                "actor_id": actor_id,
                "tenant_id": tenant_id,
                "operation": operation,
                "resource": resource,
            },
        )

        start = time.perf_counter()
        error = None

        try:
            result = self.fence.execute(request_dict)

            # Log result
            duration_ms = (time.perf_counter() - start) * 1000

            self.logger.info(
                "Request completed",
                extra={
                    "actor_id": actor_id,
                    "tenant_id": tenant_id,
                    "operation": operation,
                    "resource": resource,
                    "decision": result.decision.decision.value,
                    "verified": result.verified,
                    "row_count": len(result.data) if result.verified else 0,
                    "duration_ms": round(duration_ms, 2),
                },
            )

            return result

        except Exception as e:
            error = e
            duration_ms = (time.perf_counter() - start) * 1000

            self.logger.error(
                f"Request failed: {str(e)}",
                extra={
                    "actor_id": actor_id,
                    "tenant_id": tenant_id,
                    "operation": operation,
                    "resource": resource,
                    "duration_ms": round(duration_ms, 2),
                },
                exc_info=True,
            )

            raise


class AuditLogger:
    """
    Audit logger for security-critical events.

    Separate from application logging, focuses on security and compliance.
    """

    def __init__(self, output_file: str = "datafence-audit.log"):
        self.logger = logging.getLogger("datafence.audit")
        self.logger.setLevel(logging.INFO)

        # Audit logs always in JSON format
        handler = logging.FileHandler(output_file)
        handler.setFormatter(JsonFormatter())

        self.logger.addHandler(handler)
        self.logger.propagate = False  # Don't propagate to root logger

    def log_access(
        self,
        actor_id: str,
        tenant_id: str,
        operation: str,
        resource: str,
        decision: str,
        fields: list[str] | None = None,
        row_count: int | None = None,
    ):
        """Log data access."""
        self.logger.info(
            "Data access",
            extra={
                "event_type": "data_access",
                "actor_id": actor_id,
                "tenant_id": tenant_id,
                "operation": operation,
                "resource": resource,
                "decision": decision,
                "fields": fields,
                "row_count": row_count,
            },
        )

    def log_policy_violation(
        self,
        actor_id: str,
        tenant_id: str,
        operation: str,
        resource: str,
        reasons: list[str],
    ):
        """Log policy violation."""
        self.logger.warning(
            "Policy violation",
            extra={
                "event_type": "policy_violation",
                "actor_id": actor_id,
                "tenant_id": tenant_id,
                "operation": operation,
                "resource": resource,
                "reasons": reasons,
            },
        )

    def log_sql_injection_attempt(
        self,
        actor_id: str,
        tenant_id: str,
        query: str,
        reason: str,
    ):
        """Log SQL injection attempt."""
        self.logger.warning(
            "SQL injection attempt",
            extra={
                "event_type": "sql_injection_attempt",
                "actor_id": actor_id,
                "tenant_id": tenant_id,
                "query": query[:100],  # Truncate for safety
                "reason": reason,
            },
        )

    def log_pii_access(
        self,
        actor_id: str,
        tenant_id: str,
        resource: str,
        pii_types: list[str],
        redacted: bool,
    ):
        """Log PII access."""
        self.logger.info(
            "PII access",
            extra={
                "event_type": "pii_access",
                "actor_id": actor_id,
                "tenant_id": tenant_id,
                "resource": resource,
                "pii_types": pii_types,
                "redacted": redacted,
            },
        )

    def log_authentication(
        self,
        actor_id: str,
        success: bool,
        method: str | None = None,
    ):
        """Log authentication attempt."""
        level = logging.INFO if success else logging.WARNING

        self.logger.log(
            level,
            "Authentication attempt",
            extra={
                "event_type": "authentication",
                "actor_id": actor_id,
                "success": success,
                "method": method,
            },
        )
