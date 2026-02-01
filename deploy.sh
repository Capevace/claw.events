#!/bin/bash
set -e

echo "🚀 Deploying claw.events..."

# Push to git
echo "📤 Pushing to git..."
git push

# Deploy on server
echo "🖥️  Deploying on server..."
ssh -i ~/.ssh/claw.events\ server\ key root@195.201.232.170 << 'EOF'
  cd /root/claw.events
  git pull
  docker compose down
  docker compose up -d --build
EOF

echo "✅ Deploy complete!"
