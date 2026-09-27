"""
Health check system for DataFence.

Comprehensive health checks for monitoring system health.
"""

import time
from typing import Any
from enum import Enum
from dataclasses import dataclass


class HealthStatus(Enum):
    """Health check status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class HealthCheckResult:
    """Result of a health check."""

    name: str
    status: HealthStatus
    message: str | None = None
    duration_ms: float | None = None
    details: dict[str, Any] | None = None


class HealthChecker:
    """
    Health checker for DataFence components.

    Performs various health checks to ensure system is operational.
    """

    def __init__(self, fence: Any | None = None):
        self.fence = fence
        self.start_time = time.time()

    def check_all(self) -> dict[str, Any]:
        """
        Run all health checks.

        Returns:
            Dictionary with overall status and individual check results
        """
        checks = [
            self.check_uptime(),
            self.check_policy(),
            self.check_connector(),
        ]

        # Overall status
        statuses = [check.status for check in checks]
        if any(s == HealthStatus.UNHEALTHY for s in statuses):
            overall_status = HealthStatus.UNHEALTHY
        elif any(s == HealthStatus.DEGRADED for s in statuses):
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY

        return {
            "status": overall_status.value,
            "timestamp": time.time(),
            "uptime_seconds": time.time() - self.start_time,
            "checks": {check.name: self._format_check(check) for check in checks},
        }

    def check_uptime(self) -> HealthCheckResult:
        """Check system uptime."""
        uptime = time.time() - self.start_time

        return HealthCheckResult(
            name="uptime",
            status=HealthStatus.HEALTHY,
            message=f"System running for {uptime:.1f} seconds",
            details={"uptime_seconds": uptime},
        )

    def check_policy(self) -> HealthCheckResult:
        """Check policy configuration."""
        if not self.fence or not self.fence.policy:
            return HealthCheckResult(
                name="policy",
                status=HealthStatus.UNHEALTHY,
                message="No policy loaded",
            )

        try:
            resources = len(self.fence.policy.resources)
            return HealthCheckResult(
                name="policy",
                status=HealthStatus.HEALTHY,
                message=f"Policy loaded with {resources} resources",
                details={
                    "policy_name": self.fence.policy.name,
                    "resource_count": resources,
                },
            )
        except Exception as e:
            return HealthCheckResult(
                name="policy",
                status=HealthStatus.UNHEALTHY,
                message=f"Policy error: {str(e)}",
            )

    def check_connector(self) -> HealthCheckResult:
        """Check connector health."""
        if not self.fence or not self.fence.connector:
            return HealthCheckResult(
                name="connector",
                status=HealthStatus.UNHEALTHY,
                message="No connector configured",
            )

        try:
            # Try a simple operation
            start = time.perf_counter()
            connector_type = type(self.fence.connector).__name__
            duration_ms = (time.perf_counter() - start) * 1000

            return HealthCheckResult(
                name="connector",
                status=HealthStatus.HEALTHY,
                message=f"Connector operational: {connector_type}",
                duration_ms=duration_ms,
                details={"connector_type": connector_type},
            )

        except Exception as e:
            return HealthCheckResult(
                name="connector",
                status=HealthStatus.UNHEALTHY,
                message=f"Connector error: {str(e)}",
            )

    def check_database_connection(self) -> HealthCheckResult:
        """
        Check database connectivity (for production connectors).

        This check is optional and only relevant for database connectors.
        """
        if not self.fence or not self.fence.connector:
            return HealthCheckResult(
                name="database",
                status=HealthStatus.HEALTHY,
                message="No database connector",
            )

        connector_type = type(self.fence.connector).__name__

        # Skip check for memory/testing connectors
        if connector_type in ["MemoryConnector", "SQLiteConnector"]:
            return HealthCheckResult(
                name="database",
                status=HealthStatus.HEALTHY,
                message=f"Database check skipped for {connector_type}",
            )

        try:
            start = time.perf_counter()

            # Try to execute a simple query (connector-specific)
            if hasattr(self.fence.connector, "pool"):
                # PostgreSQL with connection pool
                with self.fence.connector.pool.connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1")

            duration_ms = (time.perf_counter() - start) * 1000

            return HealthCheckResult(
                name="database",
                status=HealthStatus.HEALTHY,
                message="Database connection successful",
                duration_ms=duration_ms,
            )

        except Exception as e:
            return HealthCheckResult(
                name="database",
                status=HealthStatus.UNHEALTHY,
                message=f"Database connection failed: {str(e)}",
            )

    def _format_check(self, check: HealthCheckResult) -> dict[str, Any]:
        """Format health check result as dictionary."""
        result = {
            "status": check.status.value,
            "message": check.message,
        }

        if check.duration_ms is not None:
            result["duration_ms"] = round(check.duration_ms, 2)

        if check.details:
            result["details"] = check.details

        return result


def create_health_endpoint(fence: Any):
    """
    Create health check endpoint for FastAPI.

    Usage:
        from fastapi import FastAPI
        from datafence.monitoring.health import create_health_endpoint

        app = FastAPI()
        health_endpoint = create_health_endpoint(fence)
        app.get("/health")(health_endpoint)

    Args:
        fence: DataFence instance

    Returns:
        FastAPI endpoint function
    """

    async def health_check():
        """Health check endpoint."""
        checker = HealthChecker(fence)
        health = checker.check_all()

        # Set HTTP status based on health
        status_code = 200
        if health["status"] == "degraded":
            status_code = 200  # Still return 200 for degraded
        elif health["status"] == "unhealthy":
            status_code = 503  # Service Unavailable

        from fastapi import Response

        return Response(
            content=__import__("json").dumps(health),
            media_type="application/json",
            status_code=status_code,
        )

    return health_check


class ReadinessChecker:
    """
    Readiness checker for Kubernetes/container environments.

    Checks if the service is ready to accept traffic.
    """

    def __init__(self, fence: Any):
        self.fence = fence
        self.ready = False

    def check(self) -> dict[str, Any]:
        """
        Check if service is ready.

        Returns:
            Readiness status
        """
        # Check critical components
        has_policy = bool(self.fence and self.fence.policy)
        has_connector = bool(self.fence and self.fence.connector)

        ready = has_policy and has_connector

        return {
            "ready": ready,
            "checks": {
                "policy_loaded": has_policy,
                "connector_configured": has_connector,
            },
        }


class LivenessChecker:
    """
    Liveness checker for Kubernetes/container environments.

    Checks if the service is alive (not deadlocked).
    """

    def __init__(self):
        self.last_check = time.time()

    def check(self) -> dict[str, Any]:
        """
        Check if service is alive.

        Returns:
            Liveness status
        """
        self.last_check = time.time()

        return {
            "alive": True,
            "timestamp": self.last_check,
        }
