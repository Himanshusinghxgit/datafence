#!/bin/bash
# DataFence CLI Examples

echo "=========================================="
echo "DataFence CLI Examples"
echo "=========================================="

# 1. Initialize a new policy
echo -e "\n1. Initialize a sample policy..."
datafence init --output sample-policy.yaml
echo "✓ Created sample-policy.yaml"

# 2. Validate policy
echo -e "\n2. Validate the policy..."
datafence validate sample-policy.yaml --verbose

# 3. Describe a resource
echo -e "\n3. Describe the 'users' resource..."
datafence describe sample-policy.yaml --resource users

# 4. Create a sample request
echo -e "\n4. Creating sample request..."
cat > sample-request.json << EOF
{
  "actor": {
    "id": "agent:test",
    "tenant_id": "acme",
    "type": "agent"
  },
  "operation": "read",
  "resource": "users",
  "fields": ["id", "email", "name"],
  "filters": {
    "tenant_id": "acme"
  },
  "limit": 10
}
EOF
echo "✓ Created sample-request.json"

# 5. Test request (dry-run)
echo -e "\n5. Test request (dry-run)..."
datafence test sample-policy.yaml sample-request.json --dry-run --verbose

# 6. Export to OpenAI format
echo -e "\n6. Export policy to OpenAI function schemas..."
datafence export sample-policy.yaml --framework openai --output openai-functions.json
echo "✓ Exported to openai-functions.json"

# 7. Export to Claude format
echo -e "\n7. Export policy to Claude tool schemas..."
datafence export sample-policy.yaml --framework claude --output claude-tools.json
echo "✓ Exported to claude-tools.json"

echo -e "\n=========================================="
echo "CLI Examples Complete"
echo "=========================================="
echo ""
echo "Available commands:"
echo "  datafence init         - Create sample policy"
echo "  datafence validate     - Validate policy file"
echo "  datafence describe     - Describe resource"
echo "  datafence test         - Test request"
echo "  datafence export       - Export to framework format"
echo ""
echo "For more info: datafence --help"
