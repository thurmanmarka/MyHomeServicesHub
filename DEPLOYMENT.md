# MyHomeServicesHub Deployment Guide

## Architecture

MyHomeServicesHub is an authentication gateway that sits between nginx and backend services (like MyWeatherDash). It provides:

- User authentication with sessions
- Role-based access control
- Service routing with auth header forwarding
- Landing page with service cards

**Request Flow:**
```
Browser → nginx (443) → Hub Gateway (8080) → Backend Services (8081+)
                                ↓
                         Adds auth headers:
                         - X-Hub-User
                         - X-Hub-Role
                         - X-Hub-Authenticated
```

## Prerequisites

- Raspberry Pi running Debian/Raspbian
- Go 1.19+ (for development/building)
- nginx 1.18+
- systemd
- User account: `weatherdash` (or adjust install script)

## Fresh Installation

### 1. Prepare the Raspberry Pi

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install nginx
sudo apt install -y nginx

# Create weatherdash user if not exists
sudo useradd -m -s /bin/bash weatherdash
sudo passwd weatherdash

# Create directories
sudo -u weatherdash mkdir -p /home/weatherdash/MyHomeServicesHub/templates
```

### 2. Generate SSL Certificates

```bash
# Create SSL directory
sudo mkdir -p /etc/nginx/ssl

# Generate self-signed certificate for hub
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/hub.key \
  -out /etc/nginx/ssl/hub.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=hub.local"

# Set permissions
sudo chmod 600 /etc/nginx/ssl/hub.key
sudo chmod 644 /etc/nginx/ssl/hub.crt
```

### 3. Build and Deploy Hub Gateway

**On your development machine:**

```bash
cd MyHomeServicesHub

# Build for Raspberry Pi
GOOS=linux GOARCH=arm GOARM=7 go build -o hub-gateway

# Copy files to Pi
scp hub-gateway templates/*.html config.yaml weatherdash@192.168.86.13:/home/weatherdash/MyHomeServicesHub/

# Set execute permissions
ssh weatherdash@192.168.86.13 "chmod +x /home/weatherdash/MyHomeServicesHub/hub-gateway"
```

### 4. Configure Authentication

**Edit config.yaml on the Pi:**

```yaml
auth:
  enabled: true
  users:
    - username: admin
      # Generate with: echo 'admin123' | bcrypt-cli -c 10
      password_hash: "$2a$10$YOUR_BCRYPT_HASH_HERE"
      role: admin
    - username: guest
      password_hash: "$2a$10$YOUR_BCRYPT_HASH_HERE"
      role: guest

services:
  - name: "Weather Dashboard"
    description: "Real-time weather data, charts, and statistics"
    icon: "☀️"
    path: "/weather"
    enabled: true
    allowed_roles: ["admin", "guest"]
```

**Generate password hashes:**

```bash
# Using Go (create tools/gen-password.go)
cd tools
go run gen-password.go admin123
go run gen-password.go guest123
```

### 5. Create systemd Service

**Create `/etc/systemd/system/hub-gateway.service`:**

```ini
[Unit]
Description=Home Services Hub Gateway
After=network.target
Wants=network.target

[Service]
Type=simple
User=weatherdash
Group=weatherdash
WorkingDirectory=/home/weatherdash/MyHomeServicesHub
ExecStart=/home/weatherdash/MyHomeServicesHub/hub-gateway
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hub-gateway

[Install]
WantedBy=multi-user.target
```

**Enable and start the service:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable hub-gateway
sudo systemctl start hub-gateway
sudo systemctl status hub-gateway
```

### 6. Configure nginx

**Create `/etc/nginx/nginx.conf`:**

```nginx
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Performance
    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout  65;
    types_hash_max_size 2048;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/rss+xml font/truetype font/opentype 
               application/vnd.ms-fontobject image/svg+xml;

    # HTTPS configuration
    server {
        listen 443 ssl;
        http2 on;
        server_name localhost;
    
        ssl_certificate /etc/nginx/ssl/hub.crt;
        ssl_certificate_key /etc/nginx/ssl/hub.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        # Main landing page
        location = / {
            proxy_pass http://localhost:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Login/Logout
        location /login {
            proxy_pass http://localhost:8080/login;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /logout {
            proxy_pass http://localhost:8080/logout;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Weather Dashboard - routed through hub gateway
        location /weather {
            proxy_pass http://localhost:8080/weather;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # WebSocket/SSE support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_buffering off;
            proxy_cache off;
        }

        # API endpoints
        location /api/ {
            proxy_pass http://localhost:8080/api/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            
            # SSE support
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
            proxy_cache off;
            chunked_transfer_encoding off;
            
            proxy_read_timeout 3600s;
            proxy_connect_timeout 75s;
            proxy_send_timeout 3600s;
        }

        # Static files
        location /static/ {
            proxy_pass http://localhost:8080/static/;
            proxy_set_header Host $host;
            
            expires 1h;
            add_header Cache-Control "public, immutable";
        }

        # Health check
        location /health {
            access_log off;
            return 200 "OK\n";
            add_header Content-Type text/plain;
        }

        # Error pages
        error_page 502 503 504 /50x.html;
        location = /50x.html {
            root html;
        }
    }

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name localhost;
        return 301 https://$host$request_uri;
    }
}
```

**Test and restart nginx:**

```bash
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl status nginx
```

## Updating/Redeployment

### Quick Update Script

Use the included `deploy.sh` script:

```bash
# From your development machine
./deploy.sh 192.168.86.13
```

### Manual Update

```bash
# Build
GOOS=linux GOARCH=arm GOARM=7 go build -o hub-gateway

# Deploy
scp hub-gateway weatherdash@192.168.86.13:/home/weatherdash/MyHomeServicesHub/
ssh weatherdash@192.168.86.13 "chmod +x /home/weatherdash/MyHomeServicesHub/hub-gateway"
ssh weatherdash@192.168.86.13 "sudo systemctl restart hub-gateway"
```

## Troubleshooting

### Check Service Status

```bash
sudo systemctl status hub-gateway
sudo journalctl -u hub-gateway -n 50 --no-pager
```

### Common Issues

**1. Permission denied (203/EXEC)**
```bash
chmod +x /home/weatherdash/MyHomeServicesHub/hub-gateway
```

**2. nginx 404 errors**
```bash
# Verify nginx is routing to hub-gateway
sudo nginx -T | grep "location /weather"
# Should show: proxy_pass http://localhost:8080/weather;
```

**3. Login redirects not working**
```bash
# Check if /login and /logout routes exist in nginx config
sudo nginx -T | grep "location /login"
```

**4. Static files 404**
```bash
# Verify hub-gateway is proxying correctly
sudo journalctl -u hub-gateway -f
# Should see: Proxying to http://localhost:8081/static/js/...
# NOT: /static/static/js/... (double path)
```

### View Logs

```bash
# Hub gateway logs
sudo journalctl -u hub-gateway -f

# nginx access logs
sudo tail -f /var/log/nginx/access.log

# nginx error logs
sudo tail -f /var/log/nginx/error.log
```

## Security Notes

1. **Change default passwords** - Update `config.yaml` with strong passwords
2. **Use proper SSL certificates** - Replace self-signed certs with Let's Encrypt in production
3. **Firewall configuration** - Only expose port 443 (HTTPS) externally
4. **Regular updates** - Keep system packages and Go dependencies updated
5. **Session security** - Sessions expire after 24 hours, stored in memory only

## Adding New Services

1. Add service definition to `config.yaml`:

```yaml
services:
  - name: "Network Monitor"
    description: "SNMP monitoring for network devices"
    icon: "🌐"
    path: "/network"
    enabled: true
    allowed_roles: ["admin"]  # Restrict to admin only
```

2. Add proxy route in `main.go`:

```go
http.HandleFunc("/network", proxyWithAuth("http://localhost:8082/"))
http.HandleFunc("/network/", proxyWithAuth("http://localhost:8082/"))
```

3. Add nginx location block in `/etc/nginx/nginx.conf`:

```nginx
location /network {
    proxy_pass http://localhost:8080/network;
    # ... same proxy settings as /weather
}
```

4. Rebuild and redeploy

## Architecture Decisions

### Why Port 8080 for Hub Gateway?

- Keeps backend services isolated (8081+)
- Single authentication point
- Easy to add new services without nginx changes

### Why Forward Auth Headers?

- Backend services can implement role-based features
- Maintains session context across services
- Enables audit logging with usernames

### Session Storage

Currently in-memory with 24-hour expiration. For production:
- Consider Redis for distributed sessions
- Implement session persistence across restarts
- Add session invalidation API

## Related Documentation

- [MyWeatherDash Deployment](../MyWeatherDash/DEPLOYMENT.md)
- [nginx SSL Setup](./setup-ssl.sh)
- [Installation Script](./install.sh)
