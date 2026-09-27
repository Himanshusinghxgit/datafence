#!/bin/bash

# This script will reset git history and create a fresh commit without secrets

echo "Backing up current branch..."
git branch backup-$(date +%Y%m%d-%H%M%S)

echo "Removing remote..."
git remote remove origin

echo "Deleting .git directory to start fresh..."
rm -rf .git

echo "Reinitializing git repository..."
git init

echo "Adding all files..."
git add .

echo "Creating new initial commit..."
git commit -m "Initial commit: DataFence - AI security and governance framework

- Core security features (PII detection, SQL firewall)
- Integration adapters (OpenAI, Anthropic, LangChain)
- Langflow integration
- Comprehensive test suite
- Documentation and examples"

echo "Adding remote..."
git remote add origin git@github.com:Himanshusinghxgit/datafence.git

echo "Renaming branch to main..."
git branch -M main

echo ""
echo "======================================"
echo "Git history has been cleaned!"
echo "Now run: git push -u origin main --force"
echo "======================================"
