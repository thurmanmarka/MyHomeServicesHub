#!/bin/bash
# Installation script for Home Services Hub on Raspberry Pi
# This script should be run as the hub user (not root)

set -e

INSTALL_USER="hub"
INSTALL_DIR="/home/$INSTALL_USER/hub"
SERVICE_NAME="hub-gateway"

echo "🏠 Home Services Hub Installation Script"
echo "=========================================="
echo ""

# Check if running as correct user
if [ "$USER" != "$INSTALL_USER" ]; then
    echo "Warning: This script is designed to run as the '$INSTALL_USER' user."
    read -p "Do you want to continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Please run as the $INSTALL_USER user or create the user first:"
        echo "  sudo useradd -m -s /bin/bash $INSTALL_USER"
        echo "  sudo usermod -aG sudo $INSTALL_USER"
        exit 1
    fi
fi

echo "📦 Installing dependencies..."
sudo apt-get update
sudo apt-get install -y golang nginx openssl

echo ""
echo "🔨 Building Go application for ARM..."
GOOS=linux GOARCH=arm64 go build -o hub-gateway main.go

echo ""
echo "📁 Creating installation directory..."
mkdir -p $INSTALL_DIR
cp hub-gateway $INSTALL_DIR/
cp config.yaml $INSTALL_DIR/
cp hub-gateway.service /tmp/

echo ""
echo "⚙️  Installing systemd service..."
sudo cp /tmp/hub-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload

echo ""
echo "🌐 Installing nginx configuration..."
echo "⚠️  IMPORTANT: Your existing nginx.conf will be backed up"
if [ -f /etc/nginx/nginx.conf ]; then
    sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup.$(date +%Y%m%d_%H%M%S)
fi
sudo cp nginx.conf /etc/nginx/nginx.conf

echo ""
echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "1. Run ./setup-ssl.sh to create SSL certificates"
echo "2. Enable the gateway service: sudo systemctl enable $SERVICE_NAME"
echo "3. Start the gateway service: sudo systemctl start $SERVICE_NAME"
echo "4. Reload nginx: sudo systemctl reload nginx"
echo "5. Check status: sudo systemctl status $SERVICE_NAME"
echo ""
echo "Your Home Services Hub will be available at https://YOUR_IP"
