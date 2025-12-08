# Fresh Installation Checklist

Complete checklist for deploying MyWeatherDash + MyHomeServicesHub from scratch on a Raspberry Pi.

## ☑️ Pre-Installation

- [ ] Raspberry Pi with fresh Raspbian/Debian install
- [ ] SSH access configured
- [ ] Static IP address assigned (e.g., 192.168.86.13)
- [ ] WeeWX weather station running with MariaDB database
- [ ] Development machine with Go 1.19+ installed
- [ ] Git repository cloned on development machine

## ☑️ System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install nginx
sudo apt install -y nginx

# Create weatherdash user
sudo useradd -m -s /bin/bash weatherdash
sudo passwd weatherdash  # Set password

# Create directories
sudo -u weatherdash mkdir -p /home/weatherdash/MyHomeServicesHub/templates
sudo -u weatherdash mkdir -p /home/weatherdash/weatherdash/templates
sudo -u weatherdash mkdir -p /home/weatherdash/weatherdash/static/js
```

- [ ] System updated
- [ ] nginx installed
- [ ] weatherdash user created
- [ ] Directories created

## ☑️ SSL Certificates

```bash
# Create SSL directory
sudo mkdir -p /etc/nginx/ssl

# Generate hub certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/hub.key \
  -out /etc/nginx/ssl/hub.crt \
  -subj "/C=US/ST=State/L=City/O=Home/CN=hub.local"

# Set permissions
sudo chmod 600 /etc/nginx/ssl/hub.key
sudo chmod 644 /etc/nginx/ssl/hub.crt
```

- [ ] SSL certificates generated
- [ ] Permissions set correctly

## ☑️ MyHomeServicesHub Deployment

### Build and Deploy

**On development machine:**

```bash
cd MyHomeServicesHub

# Build for ARM
GOOS=linux GOARCH=arm GOARM=7 go build -o hub-gateway

# Or use deploy script
./deploy.sh 192.168.86.13
```

**Manually copy files:**

```bash
scp hub-gateway templates/*.html config.yaml weatherdash@192.168.86.13:/home/weatherdash/MyHomeServicesHub/
ssh weatherdash@192.168.86.13 "chmod +x /home/weatherdash/MyHomeServicesHub/hub-gateway"
```

- [ ] hub-gateway binary built and copied
- [ ] Templates copied
- [ ] config.yaml copied
- [ ] Execute permissions set

### Configure Authentication

**On the Pi, edit `/home/weatherdash/MyHomeServicesHub/config.yaml`:**

Generate password hashes first:
```bash
# On development machine
cd MyHomeServicesHub/tools
go run gen-password.go admin123
go run gen-password.go guest123
```

Update config.yaml with the hashes:
```yaml
auth:
  enabled: true
  users:
    - username: admin
      password_hash: "$2a$10$..." # Your generated hash
      role: admin
    - username: guest
      password_hash: "$2a$10$..." # Your generated hash
      role: guest

services:
  - name: "Weather Dashboard"
    description: "Real-time weather data, charts, and statistics"
    icon: "☀️"
    path: "/weather"
    enabled: true
    allowed_roles: ["admin", "guest"]
```

- [ ] Password hashes generated
- [ ] config.yaml updated with hashes
- [ ] Service definitions configured

### Create systemd Service

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
NoNewPrivileges=true
PrivateTmp=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hub-gateway

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable hub-gateway
sudo systemctl start hub-gateway
sudo systemctl status hub-gateway
```

- [ ] Service file created
- [ ] Service enabled
- [ ] Service started successfully
- [ ] No errors in `systemctl status`

## ☑️ MyWeatherDash Deployment

### Build and Deploy

**On development machine:**

```bash
cd MyWeatherDash

# Build for ARM
GOOS=linux GOARCH=arm GOARM=7 go build -o weatherdash

# Or use deploy script
./deploy.sh 192.168.86.13
```

**Manually copy files:**

```bash
scp weatherdash config.yaml weatherdash@192.168.86.13:/home/weatherdash/weatherdash/
scp templates/index.html weatherdash@192.168.86.13:/home/weatherdash/weatherdash/templates/
scp -r static/js weatherdash@192.168.86.13:/home/weatherdash/weatherdash/static/
ssh weatherdash@192.168.86.13 "chmod +x /home/weatherdash/weatherdash/weatherdash"
```

- [ ] weatherdash binary built and copied
- [ ] Template copied
- [ ] Static files copied
- [ ] config.yaml copied
- [ ] Execute permissions set

### Configure Database Connection

**Edit `/home/weatherdash/weatherdash/config.yaml` on the Pi:**

```yaml
location:
  name: "Your Location"
  latitude: 32.0853
  longitude: -110.7664
  timezone: "America/Phoenix"

database:
  host: "localhost"
  port: 3306
  user: "weewx"
  password: "your_password"
  name: "weewx"

server:
  port: 8081
  client_poll_seconds: 60

alerts:
  extreme_heat: 110.0
  extreme_cold: 32.0
```

Test database connection:
```bash
mysql -u weewx -p weewx -e "SELECT COUNT(*) FROM archive;"
```

- [ ] config.yaml configured
- [ ] Database credentials updated
- [ ] Database connection tested

### Create systemd Service

**Create `/etc/systemd/system/weatherdash.service`:**

```ini
[Unit]
Description=MyWeatherDash - Real-time Weather Dashboard
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=simple
User=weatherdash
Group=weatherdash
WorkingDirectory=/home/weatherdash/weatherdash
ExecStart=/home/weatherdash/weatherdash/weatherdash
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=weatherdash

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable weatherdash
sudo systemctl start weatherdash
sudo systemctl status weatherdash
```

- [ ] Service file created
- [ ] Service enabled
- [ ] Service started successfully
- [ ] No errors in logs

## ☑️ nginx Configuration

**Replace `/etc/nginx/nginx.conf` with:**

```nginx
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout  65;
    types_hash_max_size 2048;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss;

    server {
        listen 443 ssl;
        http2 on;
        server_name localhost;
    
        ssl_certificate /etc/nginx/ssl/hub.crt;
        ssl_certificate_key /etc/nginx/ssl/hub.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location = / {
            proxy_pass http://localhost:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /login {
            proxy_pass http://localhost:8080/login;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        location /logout {
            proxy_pass http://localhost:8080/logout;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        location /weather {
            proxy_pass http://localhost:8080/weather;
            proxy_set_header Host $host;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_buffering off;
            proxy_cache off;
        }

        location /api/ {
            proxy_pass http://localhost:8080/api/;
            proxy_set_header Host $host;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
            proxy_cache off;
            chunked_transfer_encoding off;
            proxy_read_timeout 3600s;
        }

        location /static/ {
            proxy_pass http://localhost:8080/static/;
            proxy_set_header Host $host;
            expires 1h;
        }
    }

    server {
        listen 80;
        server_name localhost;
        return 301 https://$host$request_uri;
    }
}
```

```bash
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl status nginx
```

- [ ] nginx.conf replaced
- [ ] Configuration tested (`nginx -t`)
- [ ] nginx restarted
- [ ] No errors in status

## ☑️ Verification

### Test Services

```bash
# Hub gateway listening
curl http://localhost:8080/health
# Should return something (may redirect to /login)

# MyWeatherDash listening
curl http://localhost:8081/health
# Should return: OK

# nginx routing
curl -I https://192.168.86.13
# Should return 200 or 303 (redirect to /login)
```

- [ ] Hub gateway responding on port 8080
- [ ] MyWeatherDash responding on port 8081
- [ ] nginx responding on port 443
- [ ] HTTP redirects to HTTPS

### Test Authentication

1. **Open browser:** `https://192.168.86.13`
2. **Should redirect to login page**
3. **Login as guest** (username: guest, password: guest123)
4. **Click "Weather Dashboard"**
5. **Verify:**
   - Dashboard loads with data
   - Charts display
   - NOAA Reports button visible
   - **Easy Button NOT visible**

6. **Logout and login as admin** (username: admin, password: admin123)
7. **Click "Weather Dashboard"**
8. **Verify:**
   - Dashboard loads
   - NOAA Reports button visible
   - **Easy Button IS visible**

- [ ] Login page accessible
- [ ] Guest login works
- [ ] Guest dashboard loads
- [ ] Easy Button hidden for guest
- [ ] Admin login works
- [ ] Easy Button visible for admin
- [ ] Weather data loading (charts populated)

### Check Logs

```bash
# Hub gateway
sudo journalctl -u hub-gateway -n 20

# MyWeatherDash
sudo journalctl -u weatherdash -n 20

# nginx
sudo tail -20 /var/log/nginx/error.log
```

- [ ] No errors in hub-gateway logs
- [ ] No errors in weatherdash logs
- [ ] No errors in nginx logs
- [ ] Auth headers being logged (if debug enabled)

## ☑️ Post-Installation

### Security Hardening

- [ ] Change default passwords in config.yaml
- [ ] Consider firewall rules (only allow port 443)
- [ ] Set up fail2ban for SSH protection
- [ ] Consider Let's Encrypt for production SSL

### Backup Configuration

```bash
# Backup configs
tar -czf weatherdash-config-backup.tar.gz \
  /home/weatherdash/MyHomeServicesHub/config.yaml \
  /home/weatherdash/weatherdash/config.yaml \
  /etc/nginx/nginx.conf \
  /etc/systemd/system/hub-gateway.service \
  /etc/systemd/system/weatherdash.service
```

- [ ] Configuration backed up
- [ ] Backup stored securely

### Documentation

- [ ] Document your specific configuration
- [ ] Note any customizations made
- [ ] Record IP addresses and passwords securely

## 🎉 Installation Complete!

Your MyWeatherDash hub is now fully operational at `https://192.168.86.13`

**Default credentials:**
- Admin: admin / admin123
- Guest: guest / guest123

**Next steps:**
- Change default passwords
- Customize location settings
- Add additional services to the hub
- Set up automated backups

## 📚 References

- [MyHomeServicesHub DEPLOYMENT.md](../MyHomeServicesHub/DEPLOYMENT.md)
- [MyWeatherDash DEPLOYMENT.md](../MyWeatherDash/DEPLOYMENT.md)
- [Troubleshooting Guide](#troubleshooting)
