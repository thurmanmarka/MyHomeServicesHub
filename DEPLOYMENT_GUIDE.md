# Deployment Documentation

Complete deployment and installation guides for MyWeatherDash + MyHomeServicesHub.

## 📚 Documentation Index

### Quick Start
- **[INSTALLATION_CHECKLIST.md](./INSTALLATION_CHECKLIST.md)** - Step-by-step checklist for fresh installation from scratch

### Project-Specific Guides
- **[MyHomeServicesHub/DEPLOYMENT.md](./DEPLOYMENT.md)** - Hub gateway deployment, authentication, and service routing
- **[MyWeatherDash/DEPLOYMENT.md](../MyWeatherDash/DEPLOYMENT.md)** - Weather dashboard deployment and permission system

### Deployment Scripts
- **[MyHomeServicesHub/deploy.sh](./deploy.sh)** - Automated deployment script for hub gateway
- **[MyWeatherDash/deploy.sh](../MyWeatherDash/deploy.sh)** - Automated deployment script for weather dashboard

## 🚀 Quick Deploy (Existing Installation)

### Update Hub Gateway
```bash
cd MyHomeServicesHub
./deploy.sh 192.168.86.13
```

### Update Weather Dashboard
```bash
cd MyWeatherDash
./deploy.sh 192.168.86.13
```

## 📋 Fresh Installation

Follow the **[INSTALLATION_CHECKLIST.md](./INSTALLATION_CHECKLIST.md)** for a complete step-by-step guide.

**High-level steps:**
1. Prepare Raspberry Pi (system updates, nginx, user creation)
2. Generate SSL certificates
3. Deploy MyHomeServicesHub (hub gateway)
4. Deploy MyWeatherDash (weather dashboard)
5. Configure nginx
6. Test authentication and permissions

**Estimated time:** 30-45 minutes

## 🏗️ Architecture Overview

```
Browser
   ↓ HTTPS (443)
nginx
   ↓ HTTP (8080)
Hub Gateway (Authentication)
   ↓ HTTP (8081) + Auth Headers
MyWeatherDash
   ↓
MariaDB (WeeWX Database)
```

### Key Components

1. **nginx** - SSL termination, HTTP→HTTPS redirect, reverse proxy
2. **Hub Gateway (port 8080)** - Authentication, session management, service routing
3. **MyWeatherDash (port 8081)** - Weather data API and dashboard UI
4. **MariaDB** - WeeWX weather station database

### Authentication Flow

1. User accesses `https://192.168.86.13`
2. nginx proxies to Hub Gateway
3. Hub checks for valid session cookie
4. If no session → redirect to `/login`
5. After login → Hub creates session with username/role
6. User clicks "Weather Dashboard"
7. Hub proxies to MyWeatherDash with auth headers:
   - `X-Hub-User: guest`
   - `X-Hub-Role: guest`
   - `X-Hub-Authenticated: true`
8. MyWeatherDash reads headers and conditionally renders UI
9. Template shows/hides features based on `{{if .IsAdmin}}`

## 🔐 Permission System

### Role-Based Access Control

**Admin Role:**
- Full dashboard access
- NOAA Reports (monthly/yearly climate summaries)
- Easy Button (custom date range CSV export)

**Guest Role:**
- Dashboard viewing only
- Read-only access
- No database-intensive features (prevents SQL spam)

### Implementation

**Template Conditionals (Frontend):**
```html
{{if .IsAdmin}}
<button id="easyBtn">Easy Button</button>
{{end}}
```

**Backend Checks (API Endpoints):**
```go
func handleNOAAMonthly(w http.ResponseWriter, r *http.Request) {
    if !isAdmin(r) {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    // ... process request
}
```

## 🛠️ Common Operations

### View Logs
```bash
# Hub Gateway
sudo journalctl -u hub-gateway -f

# MyWeatherDash
sudo journalctl -u weatherdash -f

# nginx
sudo tail -f /var/log/nginx/error.log
```

### Restart Services
```bash
# Hub Gateway
sudo systemctl restart hub-gateway

# MyWeatherDash
sudo systemctl restart weatherdash

# nginx
sudo systemctl reload nginx
```

### Check Service Status
```bash
sudo systemctl status hub-gateway
sudo systemctl status weatherdash
sudo systemctl status nginx
```

### Test Endpoints
```bash
# Hub health
curl http://localhost:8080/health

# Weather health
curl http://localhost:8081/health

# nginx routing
curl -I https://192.168.86.13
```

## 🐛 Troubleshooting

See the troubleshooting sections in:
- [MyHomeServicesHub/DEPLOYMENT.md](./DEPLOYMENT.md#troubleshooting)
- [MyWeatherDash/DEPLOYMENT.md](../MyWeatherDash/DEPLOYMENT.md#troubleshooting)

### Most Common Issues

1. **Permission denied (203/EXEC)**
   ```bash
   chmod +x /home/weatherdash/MyHomeServicesHub/hub-gateway
   chmod +x /home/weatherdash/weatherdash/weatherdash
   ```

2. **Static files 404**
   - Check hub-gateway proxy routes don't double `/static` path
   - Should be: `http.HandleFunc("/static/", proxyWithAuth("http://localhost:8081/"))`

3. **Templates not updating**
   ```bash
   # Templates are parsed at startup
   sudo systemctl restart weatherdash
   ```

4. **Easy Button visible for guest users**
   - Verify template has `{{if .IsAdmin}}` conditionals
   - Check auth headers in logs: `sudo journalctl -u weatherdash | grep "Auth headers"`
   - Ensure nginx routes through hub (`:8080`) not directly to dashboard (`:8081`)

## 📦 File Locations

### On Raspberry Pi

**Hub Gateway:**
- Binary: `/home/weatherdash/MyHomeServicesHub/hub-gateway`
- Config: `/home/weatherdash/MyHomeServicesHub/config.yaml`
- Templates: `/home/weatherdash/MyHomeServicesHub/templates/*.html`
- Service: `/etc/systemd/system/hub-gateway.service`

**MyWeatherDash:**
- Binary: `/home/weatherdash/weatherdash/weatherdash`
- Config: `/home/weatherdash/weatherdash/config.yaml`
- Templates: `/home/weatherdash/weatherdash/templates/index.html`
- Static files: `/home/weatherdash/weatherdash/static/js/*.js`
- Service: `/etc/systemd/system/weatherdash.service`

**nginx:**
- Config: `/etc/nginx/nginx.conf`
- SSL Certs: `/etc/nginx/ssl/hub.{crt,key}`
- Logs: `/var/log/nginx/{access,error}.log`

## 🔄 Update Workflow

1. **Make code changes** on development machine
2. **Build for ARM**
   ```bash
   GOOS=linux GOARCH=arm GOARM=7 go build -o [binary]
   ```
3. **Deploy using script**
   ```bash
   ./deploy.sh 192.168.86.13
   ```
4. **Verify deployment**
   ```bash
   sudo systemctl status [service]
   sudo journalctl -u [service] -n 20
   ```

## 🎯 Production Checklist

Before exposing to the internet:

- [ ] Change default passwords in `config.yaml`
- [ ] Replace self-signed SSL with Let's Encrypt
- [ ] Configure firewall (only expose port 443)
- [ ] Set up fail2ban for SSH protection
- [ ] Enable nginx rate limiting
- [ ] Set up automated backups
- [ ] Configure monitoring/alerting
- [ ] Document your specific configuration
- [ ] Test disaster recovery procedure

## 📞 Support Resources

- [MyHomeServicesHub GitHub](https://github.com/thurmanmarka/MyHomeServicesHub)
- [MyWeatherDash GitHub](https://github.com/thurmanmarka/MyWeatherDash)
- [WeeWX Documentation](https://weewx.com/docs.html)
- [nginx Documentation](https://nginx.org/en/docs/)

## 📝 Version History

- **v2.0.0** - Hub integration with authentication and role-based permissions
- **v1.0.0** - Initial standalone MyWeatherDash deployment
