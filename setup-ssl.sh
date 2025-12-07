#!/bin/bash
# Self-signed SSL certificate setup for Home Services Hub
# Run this on the Raspberry Pi after installation

set -e

echo "🔒 Setting up self-signed SSL certificate for Home Services Hub..."

# Create directory for SSL certificates
SSL_DIR="/etc/nginx/ssl"
sudo mkdir -p $SSL_DIR

# Prompt for IP addresses
read -p "Enter your local IP address (default: 192.168.86.13): " LOCAL_IP
LOCAL_IP=${LOCAL_IP:-192.168.86.13}

read -p "Enter your public IP address (or press Enter to skip): " PUBLIC_IP

# Create OpenSSL config file with SAN and CA extensions
cat > /tmp/openssl-san.cnf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req
x509_extensions = v3_ca

[dn]
C=US
ST=State
L=City
O=HomeServicesHub
CN=$LOCAL_IP

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:TRUE
keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign

[v3_ca]
subjectAltName = @alt_names
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[alt_names]
IP.1 = $LOCAL_IP
DNS.1 = localhost
EOF

# Add public IP if provided
if [ -n "$PUBLIC_IP" ]; then
    echo "IP.2 = $PUBLIC_IP" >> /tmp/openssl-san.cnf
fi

# Generate self-signed CA certificate with SAN (valid for 365 days)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout $SSL_DIR/hub.key \
    -out $SSL_DIR/hub.crt \
    -config /tmp/openssl-san.cnf \
    -extensions v3_ca

# Clean up temp config
rm /tmp/openssl-san.cnf

# Set proper permissions
sudo chmod 600 $SSL_DIR/hub.key
sudo chmod 644 $SSL_DIR/hub.crt

echo "✅ SSL certificate created at $SSL_DIR/hub.crt"
echo "✅ SSL key created at $SSL_DIR/hub.key"
echo ""
echo "Next steps:"
echo "1. Copy the updated nginx.conf to /etc/nginx/nginx.conf"
echo "2. Test nginx config: sudo nginx -t"
echo "3. Reload nginx: sudo systemctl reload nginx"
echo "4. Access your hub at: https://$LOCAL_IP"
echo ""
echo "⚠️  Your browser will show a security warning because this is self-signed."
echo "    Download and install hub.crt on your devices to avoid warnings."
echo ""
echo "To download the certificate:"
echo "  sudo cp $SSL_DIR/hub.crt ~/hub.crt"
echo "  chmod 644 ~/hub.crt"
