#!/bin/bash
# DataFence CLI examples.
# Run from the repo root: bash examples/integrations/cli_example.sh

set -euo pipefail

echo "=========================================="
echo "DataFence CLI Examples"
echo "=========================================="

# 1. Generate a sample policy file
echo -e "\n1. Generate a sample policy..."
datafence init --output /tmp/datafence-sample.yaml
echo "✓ Created /tmp/datafence-sample.yaml"

# 2. Validate the policy
echo -e "\n2. Validate the policy..."
datafence validate /tmp/datafence-sample.yaml
echo "✓ Policy is valid"

# 3. Describe a resource from a built-in policy
echo -e "\n3. Describe 'orders' resource from policies/basic.yaml..."
datafence describe policies/basic.yaml --resource orders || true

echo -e "\n=========================================="
echo "Available commands:"
echo "  datafence init       - Generate a sample policy file"
echo "  datafence validate   - Validate a policy YAML file"
echo "  datafence describe   - Describe a resource's schema from a policy"
echo ""
echo "For full help: datafence --help"
echo "=========================================="
