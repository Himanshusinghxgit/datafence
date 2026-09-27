# DataFence Performance Benchmarks

Comprehensive benchmarks for measuring DataFence performance.

## Running Benchmarks

```bash
# Core benchmarks (1000 iterations)
python benchmarks/benchmark_core.py

# Core benchmarks (custom iterations)
python benchmarks/benchmark_core.py 10000

# Integration benchmarks
python benchmarks/benchmark_integrations.py

# Integration benchmarks (custom iterations)
python benchmarks/benchmark_integrations.py 5000
```

## Core Benchmarks

### Policy Evaluation
Measures the overhead of policy evaluation without any security features.

**Typical Performance:** < 1ms average

### SQL Firewall
Measures performance with SQL firewall enabled.

**Typical Performance:** 1-2ms average

### PII Detection
Measures performance with PII detection and redaction enabled.

**Typical Performance:** 3-5ms average

### Field Restriction
Measures field-level security enforcement overhead.

**Typical Performance:** < 1ms average

### Memory Connector
Tests connector performance with different data sizes:
- 100 rows
- 1000 rows

**Typical Performance:** < 1ms average

### Full Stack
All features enabled (SQL firewall + PII detection + field restrictions).

**Typical Performance:** 5-10ms average

## Integration Benchmarks

### OpenAI Adapter
Measures overhead of OpenAI function calling adapter.

**Typical Performance:** < 2ms average (on top of policy evaluation)

### Claude Adapter
Measures overhead of Claude tool use adapter.

**Typical Performance:** < 2ms average (on top of policy evaluation)

### LangChain Tool
Measures overhead of LangChain tool wrapper.

**Typical Performance:** < 2ms average (on top of policy evaluation)

### Schema Generation
Measures time to generate framework-specific schemas from policies.

**Typical Performance:** < 5ms average

## Performance Metrics

Each benchmark reports:

- **Average**: Mean execution time
- **Median (p50)**: 50th percentile
- **p95**: 95th percentile
- **p99**: 99th percentile
- **Min**: Minimum time
- **Max**: Maximum time
- **Errors**: Number of errors during execution

## Interpreting Results

### Expected Performance

For typical production workloads:

```
Component              | Average | p95
-----------------------|---------|--------
Policy Evaluation      |  < 1ms  |  < 2ms
SQL Firewall           |  1-2ms  |  3-4ms
PII Detection          |  3-5ms  |  8-10ms
Full Stack             | 5-10ms  | 15-20ms
Integration Overhead   |  < 2ms  |  < 5ms
```

### Performance Factors

**Fast (<1ms):**
- Policy evaluation (simple policies)
- Field restriction
- Memory connector (small datasets)

**Moderate (1-5ms):**
- SQL firewall (query parsing)
- Integration adapters (JSON serialization)
- Schema generation

**Slower (>5ms):**
- PII detection (regex matching on many fields)
- Large result sets
- Multiple security features combined

## Optimization Tips

### 1. Cache Schemas

Don't regenerate schemas on every request:

```python
# Bad
def handle_request():
    adapter = OpenAIAdapter(fence)
    functions = adapter.get_functions()  # Regenerates every time
    ...

# Good
adapter = OpenAIAdapter(fence)
functions = adapter.get_functions()  # Generate once

def handle_request():
    # Reuse cached functions
    ...
```

### 2. Selective PII Detection

Only scan fields that may contain PII:

```python
# Bad - scans all fields
result = fence.execute(request)  # All fields scanned

# Good - only scan email/phone fields
# Configure PII scanner to target specific fields
```

### 3. Limit Result Sets

Use appropriate limits:

```python
# Bad
request = {"limit": 10000}  # Large result set

# Good
request = {"limit": 100}  # Reasonable limit
```

### 4. Use Production Connectors

Memory connector is for testing. Use production connectors for real workloads:

```python
# Development
connector = MemoryConnector(data)

# Production
connector = PostgreSQLConnector(host="...", pool_size=10)
```

### 5. Connection Pooling

For production connectors, use appropriate pool sizes:

```python
# PostgreSQL
connector = PostgreSQLConnector(
    min_pool_size=5,
    max_pool_size=20,
    timeout=30.0
)
```

## Profiling

For detailed profiling:

```bash
# CPU profiling
python -m cProfile -o profile.stats benchmarks/benchmark_core.py

# Analyze with snakeviz
pip install snakeviz
snakeviz profile.stats

# Memory profiling
pip install memory_profiler
python -m memory_profiler benchmarks/benchmark_core.py
```

## Continuous Benchmarking

Run benchmarks in CI/CD to track performance over time:

```yaml
# .github/workflows/benchmark.yml
name: Benchmarks
on: [push, pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
      - run: pip install -e .
      - run: python benchmarks/benchmark_core.py 1000
      - run: python benchmarks/benchmark_integrations.py 1000
```

## Comparison with Baselines

Compare against baselines to detect regressions:

```bash
# Run and save baseline
python benchmarks/benchmark_core.py > baseline.txt

# After changes, compare
python benchmarks/benchmark_core.py > current.txt
diff baseline.txt current.txt
```

## Load Testing

For API load testing, use tools like:

```bash
# Apache Bench
ab -n 1000 -c 10 http://localhost:8000/execute

# wrk
wrk -t4 -c100 -d30s http://localhost:8000/health

# Locust
locust -f load_test.py --host=http://localhost:8000
```

## Performance Goals

Target performance for v1.0:

- ✅ Policy evaluation: < 1ms average
- ✅ SQL firewall: < 2ms average
- 🎯 PII detection: < 5ms average (current: 3-5ms)
- 🎯 Full stack: < 10ms average (current: 5-10ms)
- ✅ Integration overhead: < 2ms average

## Troubleshooting Slow Performance

### Check 1: Policy Complexity

Complex policies take longer to evaluate. Simplify if possible.

### Check 2: PII Detection

PII detection is regex-based and scales with field count. Disable if not needed:

```python
fence = DataFence.from_yaml(policy, connector, enable_pii_detection=False)
```

### Check 3: Result Set Size

Large result sets take longer to process. Use appropriate limits.

### Check 4: Connector Performance

Check underlying database/connector performance. DataFence adds minimal overhead.

### Check 5: System Resources

Check CPU, memory, and I/O. DataFence is lightweight but runs on your infrastructure.

## Contributing Benchmarks

To add new benchmarks:

1. Create benchmark function in appropriate file
2. Follow naming convention: `benchmark_<feature>`
3. Return `BenchmarkResult` object
4. Add to `run_all_benchmarks()`
5. Document typical performance in this README

Example:

```python
def benchmark_new_feature(iterations: int = 1000) -> BenchmarkResult:
    """Benchmark new feature."""
    result = BenchmarkResult("New Feature")
    
    # Setup
    ...
    
    # Warmup
    for _ in range(10):
        ...
    
    # Benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            # Execute feature
            elapsed = time.perf_counter() - start
            result.add_time(elapsed)
        except Exception:
            result.add_error()
    
    return result
```
