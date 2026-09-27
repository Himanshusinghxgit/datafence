"""
Metrics collection for DataFence.

Prometheus-compatible metrics for monitoring DataFence in production.
"""

import time
from typing import Any
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Counter:
    """Simple counter metric."""

    name: str
    help: str
    value: int = 0
    labels: dict[str, str] = field(default_factory=dict)

    def inc(self, amount: int = 1):
        """Increment counter."""
        self.value += amount

    def get(self) -> int:
        """Get current value."""
        return self.value


@dataclass
class Histogram:
    """Simple histogram metric."""

    name: str
    help: str
    buckets: list[float] = field(default_factory=lambda: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
    values: list[float] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)

    def observe(self, value: float):
        """Observe a value."""
        self.values.append(value)

    def get_buckets(self) -> dict[float, int]:
        """Get bucket counts."""
        bucket_counts = {}
        for bucket in self.buckets:
            bucket_counts[bucket] = sum(1 for v in self.values if v <= bucket)
        bucket_counts[float('inf')] = len(self.values)
        return bucket_counts

    def get_sum(self) -> float:
        """Get sum of all values."""
        return sum(self.values)

    def get_count(self) -> int:
        """Get count of observations."""
        return len(self.values)


class MetricsCollector:
    """
    Collect metrics for DataFence operations.

    Tracks counters and histograms for monitoring performance and usage.
    """

    def __init__(self):
        self._counters: dict[str, Counter] = {}
        self._histograms: dict[str, Histogram] = {}

        # Initialize standard metrics
        self._init_standard_metrics()

    def _init_standard_metrics(self):
        """Initialize standard DataFence metrics."""
        # Request counters
        self.register_counter(
            "datafence_requests_total",
            "Total number of requests processed",
        )
        self.register_counter(
            "datafence_requests_allowed",
            "Number of requests allowed by policy",
        )
        self.register_counter(
            "datafence_requests_denied",
            "Number of requests denied by policy",
        )
        self.register_counter(
            "datafence_requests_errors",
            "Number of requests that resulted in errors",
        )

        # Security metrics
        self.register_counter(
            "datafence_sql_firewall_blocks",
            "Number of queries blocked by SQL firewall",
        )
        self.register_counter(
            "datafence_pii_detections",
            "Number of PII instances detected",
        )
        self.register_counter(
            "datafence_pii_redactions",
            "Number of PII instances redacted",
        )

        # Performance histograms
        self.register_histogram(
            "datafence_request_duration_seconds",
            "Request processing duration in seconds",
        )
        self.register_histogram(
            "datafence_policy_eval_duration_seconds",
            "Policy evaluation duration in seconds",
        )
        self.register_histogram(
            "datafence_connector_duration_seconds",
            "Connector execution duration in seconds",
        )

    def register_counter(self, name: str, help: str) -> Counter:
        """Register a counter metric."""
        counter = Counter(name=name, help=help)
        self._counters[name] = counter
        return counter

    def register_histogram(self, name: str, help: str, buckets: list[float] | None = None) -> Histogram:
        """Register a histogram metric."""
        histogram = Histogram(
            name=name,
            help=help,
            buckets=buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
        )
        self._histograms[name] = histogram
        return histogram

    def inc_counter(self, name: str, amount: int = 1):
        """Increment a counter."""
        if name in self._counters:
            self._counters[name].inc(amount)

    def observe_histogram(self, name: str, value: float):
        """Observe a histogram value."""
        if name in self._histograms:
            self._histograms[name].observe(value)

    def record_request(self, allowed: bool, duration: float, error: bool = False):
        """Record a request execution."""
        self.inc_counter("datafence_requests_total")

        if error:
            self.inc_counter("datafence_requests_errors")
        elif allowed:
            self.inc_counter("datafence_requests_allowed")
        else:
            self.inc_counter("datafence_requests_denied")

        self.observe_histogram("datafence_request_duration_seconds", duration)

    def record_policy_evaluation(self, duration: float):
        """Record policy evaluation time."""
        self.observe_histogram("datafence_policy_eval_duration_seconds", duration)

    def record_connector_execution(self, duration: float):
        """Record connector execution time."""
        self.observe_histogram("datafence_connector_duration_seconds", duration)

    def record_sql_firewall_block(self):
        """Record SQL firewall block."""
        self.inc_counter("datafence_sql_firewall_blocks")

    def record_pii_detection(self, count: int = 1):
        """Record PII detection."""
        self.inc_counter("datafence_pii_detections", count)

    def record_pii_redaction(self, count: int = 1):
        """Record PII redaction."""
        self.inc_counter("datafence_pii_redactions", count)

    def get_counter(self, name: str) -> int:
        """Get counter value."""
        return self._counters[name].get() if name in self._counters else 0

    def get_histogram_stats(self, name: str) -> dict[str, Any]:
        """Get histogram statistics."""
        if name not in self._histograms:
            return {}

        hist = self._histograms[name]
        values = sorted(hist.values)

        if not values:
            return {"count": 0}

        return {
            "count": hist.get_count(),
            "sum": hist.get_sum(),
            "avg": hist.get_sum() / hist.get_count(),
            "min": min(values),
            "max": max(values),
            "p50": values[len(values) // 2],
            "p95": values[int(len(values) * 0.95)] if len(values) > 1 else values[0],
            "p99": values[int(len(values) * 0.99)] if len(values) > 1 else values[0],
        }

    def export_prometheus(self) -> str:
        """
        Export metrics in Prometheus text format.

        Returns:
            Prometheus-formatted metrics string
        """
        lines = []

        # Export counters
        for name, counter in self._counters.items():
            lines.append(f"# HELP {name} {counter.help}")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {counter.value}")

        # Export histograms
        for name, hist in self._histograms.items():
            lines.append(f"# HELP {name} {hist.help}")
            lines.append(f"# TYPE {name} histogram")

            # Bucket counts
            buckets = hist.get_buckets()
            for bucket, count in sorted(buckets.items()):
                if bucket == float('inf'):
                    lines.append(f'{name}_bucket{{le="+Inf"}} {count}')
                else:
                    lines.append(f'{name}_bucket{{le="{bucket}"}} {count}')

            # Sum and count
            lines.append(f"{name}_sum {hist.get_sum()}")
            lines.append(f"{name}_count {hist.get_count()}")

        return "\n".join(lines) + "\n"

    def get_all_metrics(self) -> dict[str, Any]:
        """Get all metrics as a dictionary."""
        metrics = {"counters": {}, "histograms": {}}

        for name, counter in self._counters.items():
            metrics["counters"][name] = counter.get()

        for name, hist in self._histograms.items():
            metrics["histograms"][name] = self.get_histogram_stats(name)

        return metrics

    def reset(self):
        """Reset all metrics."""
        for counter in self._counters.values():
            counter.value = 0
        for hist in self._histograms.values():
            hist.values.clear()


# Global metrics collector
_metrics_collector = MetricsCollector()


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector."""
    return _metrics_collector


class MetricsMiddleware:
    """
    Middleware for automatic metrics collection.

    Usage with DataFence:
        fence = DataFence.from_yaml(policy, connector)
        middleware = MetricsMiddleware(fence)
        result = middleware.execute(request)
    """

    def __init__(self, fence: Any, collector: MetricsCollector | None = None):
        self.fence = fence
        self.collector = collector or get_metrics_collector()

    def execute(self, request_dict: dict[str, Any]) -> Any:
        """Execute request with metrics collection."""
        start = time.perf_counter()
        error = False
        allowed = False

        try:
            result = self.fence.execute(request_dict)
            allowed = result.verified
            return result

        except Exception as e:
            error = True
            raise

        finally:
            duration = time.perf_counter() - start
            self.collector.record_request(allowed=allowed, duration=duration, error=error)
