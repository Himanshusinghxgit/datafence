#!/bin/bash
cd /Users/himanshusingh/Datafence

echo "=== Git Status ==="
git status --short

echo ""
echo "=== Staging v0.3 files ==="
git add src/datafence/core/types.py
git add src/datafence/core/boundary.py
git add src/datafence/core/policy_engine.py
git add src/datafence/connectors/sqlite_connector.py
git add demos/killer_demo.py
git add demos/README.md
git add tests/test_security_invariants.py
git add pyproject.toml
git add ARCHITECTURE.md
git add README_NEW.md
git add STATUS_v0.3.md
git add REFACTOR_COMPLETE.md

echo ""
echo "=== Committing ==="
git commit -m "v0.3.0: ExecutionPlan architecture + killer demo (pre-hardening)

Core Changes:
- First-class types: Actor, Intent, ExecutionPlan, Evidence
- DataFenceBoundary.execute() - security boundary implementation
- SimplePolicyEngine - field/operation/tenant controls
- SQLite connector accepts ONLY ExecutionPlan (not raw SQL)

Demo & Tests:
- killer_demo.py - 6 scenarios proving security boundary
- test_security_invariants.py - 13+ security tests
- demos/README.md - 30-second proof

Documentation:
- Downgraded to v0.3.0 (honest prototype status)
- Removed overclaims (< 10ms, GDPR, production-ready)
- Architecture docs emphasize security boundary

Security Status: PROTOTYPE - adversarial testing needed
Next: v0.4 red-team testing before adding features"

echo ""
echo "=== Pushing to GitHub ==="
git push origin main

echo ""
echo "=== Done ==="
