#!/bin/bash
set -e

# Parse arguments
NO_PUSH=false
for arg in "$@"; do
  if [ "$arg" = "--no-push" ]; then
    NO_PUSH=true
  fi
done

echo "🚀 Deploying claw.events..."

# Push to git
echo "📤 Committing to git..."
git add .
git commit -m "Deploy" || true

if [ "$NO_PUSH" = false ]; then
  echo "📤 Pushing to git..."
  git push
fi

# Deploy on server
echo "🖥️  Deploying on server..."
ssh -i ~/.ssh/claw.events\ server\ key root@195.201.232.170 << 'EOF'
  cd /root/claw.events
  git pull
  docker compose down
  docker compose up -d --build
EOF

echo "✅ Deploy complete!"
