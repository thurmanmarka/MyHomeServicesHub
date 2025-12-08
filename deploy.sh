#!/bin/bash
# Deploy MyHomeServicesHub to Raspberry Pi
# Usage: ./deploy.sh [host]

set -e

HOST="${1:-192.168.86.13}"
USER="weatherdash"
REMOTE_DIR="/home/weatherdash/MyHomeServicesHub"
SERVICE_NAME="hub-gateway"

echo "🏗️  Building hub-gateway for ARM..."
GOOS=linux GOARCH=arm GOARM=7 go build -o hub-gateway

echo "📦 Copying files to $HOST..."
scp hub-gateway templates/*.html config.yaml ${USER}@${HOST}:${REMOTE_DIR}/

echo "🔧 Setting permissions and restarting service..."
ssh ${USER}@${HOST} << 'EOF'
chmod +x /home/weatherdash/MyHomeServicesHub/hub-gateway
sudo systemctl restart hub-gateway
sudo systemctl status hub-gateway --no-pager -l
EOF

echo "✅ Deployment complete!"
echo "🌐 Access at: https://${HOST}"
