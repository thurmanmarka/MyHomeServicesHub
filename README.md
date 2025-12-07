# Home Services Hub 🏠

A lightweight Go-based gateway service that provides a centralized landing page and reverse proxy routing for multiple home services and monitoring applications.

## Features

- 🎯 **Service Discovery Landing Page** - Dynamic service cards based on YAML configuration
- 🔒 **HTTPS Support** - Self-signed SSL certificates with proper SAN configuration
- 🚀 **Lightweight** - Single Go binary, minimal dependencies
- ⚡ **Fast** - nginx reverse proxy for efficient routing
- 🔄 **Auto-Start** - systemd integration for reliable service management
- 📱 **Responsive** - Mobile-friendly dark mode UI

## Architecture

```
Internet/Browser (HTTPS)
         ↓
    nginx (port 443)
         ↓
    ┌────┴────┬──────────┬───────────┐
    │         │          │           │
  Gateway   Weather   Network    Future
  (8080)    (8081)    (8082)    Services
```

## Prerequisites

- Raspberry Pi (or any ARM/x64 Linux system)
- Go 1.19+ (for building)
- nginx
- openssl

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/HomeServicesHub.git
cd HomeServicesHub
```

### 2. Create User (if needed)

```bash
sudo useradd -m -s /bin/bash hub
sudo usermod -aG sudo hub
sudo su - hub
```

### 3. Run Installation

```bash
cd HomeServicesHub
chmod +x install.sh setup-ssl.sh
./install.sh
```

### 4. Setup SSL Certificates

```bash
./setup-ssl.sh
# Follow prompts to enter your IP addresses
```

### 5. Start Services

```bash
sudo systemctl enable hub-gateway
sudo systemctl start hub-gateway
sudo systemctl reload nginx
```

### 6. Verify Installation

```bash
# Check gateway service
sudo systemctl status hub-gateway

# Check nginx
sudo systemctl status nginx

# Test endpoints
curl http://localhost:8080/health
```

## Configuration

Edit `config.yaml` to add or modify services:

```yaml
server:
  port: 8080

services:
  - name: "Weather Dashboard"
    description: "Real-time weather data, charts, and statistics"
    icon: "☀️"
    path: "/weather"
    enabled: true
  
  - name: "Network Monitor"
    description: "SNMP monitoring for network devices"
    icon: "🌐"
    path: "/network"
    enabled: false  # Set to true when service is ready
```

## nginx Routing

The gateway uses nginx to route requests to different services:

- `/` → Hub landing page (port 8080)
- `/weather` → Weather Dashboard (port 8081)
- `/api/` → Weather API endpoints (port 8081)
- `/static/` → Static assets (port 8081)
- `/network` → Network Monitor (port 8082)
- `/health` → Health check endpoint

## SSL Certificate Installation

To avoid browser security warnings, install the self-signed certificate on your devices:

### Download Certificate

```bash
sudo cp /etc/nginx/ssl/hub.crt ~/hub.crt
chmod 644 ~/hub.crt
```

### Install on Devices

**Windows:**
1. Double-click `hub.crt`
2. Install Certificate → Local Machine
3. Place in "Trusted Root Certification Authorities"

**macOS:**
1. Double-click `hub.crt`
2. Add to System keychain
3. Trust → Always Trust

**Linux:**
```bash
sudo cp hub.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

## Adding New Services

1. Update `config.yaml` with new service details
2. Deploy your service to run on a unique port (e.g., 8083)
3. Update `nginx.conf` to add routing for the new service
4. Reload configuration:
   ```bash
   sudo systemctl restart hub-gateway
   sudo systemctl reload nginx
   ```

## Deployment Structure

```
/home/hub/
├── hub/
│   ├── hub-gateway         # Main binary
│   └── config.yaml         # Configuration
├── MyWeatherDash/          # Weather service
│   └── weatherdash
└── NetworkMonitor/         # Future services
    └── netmonitor
```

## Development

### Building Locally

```bash
# For Raspberry Pi (ARM64)
GOOS=linux GOARCH=arm64 go build -o hub-gateway main.go

# For x64
GOOS=linux GOARCH=amd64 go build -o hub-gateway main.go
```

### Testing

```bash
# Start locally
go run main.go

# Access at http://localhost:8080
```

## Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u hub-gateway -f

# Verify binary permissions
ls -l /home/hub/hub/hub-gateway

# Check config
cat /home/hub/hub/config.yaml
```

### nginx errors

```bash
# Test nginx config
sudo nginx -t

# Check nginx logs
sudo tail -f /var/log/nginx/error.log
```

### SSL certificate issues

```bash
# Verify certificate has CA:TRUE and SAN
openssl x509 -in /etc/nginx/ssl/hub.crt -noout -text | grep -E "CA:|Subject Alternative"
```

## Project Structure

```
HomeServicesHub/
├── .github/
│   └── copilot-instructions.md
├── templates/              # Future: HTML templates
├── config.yaml            # Service configuration
├── hub-gateway.service    # systemd service file
├── install.sh             # Installation script
├── main.go                # Main application
├── nginx.conf             # nginx configuration
├── README.md              # This file
└── setup-ssl.sh           # SSL certificate setup
```

## License

MIT

## Related Projects

- [MyWeatherDash](https://github.com/thurmanmarka/MyWeatherDash) - Weather monitoring service
- NetworkMonitor (coming soon) - SNMP network monitoring

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## Author

Created as part of a home services monitoring platform.
