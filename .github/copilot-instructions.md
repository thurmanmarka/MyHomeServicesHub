# MyHomeServicesHub - Copilot Instructions

This is a Go-based gateway service that provides a landing page and reverse proxy routing for multiple microservices.

## Project Type
- Language: Go
- Framework: net/http (standard library)
- Deployment: Raspberry Pi with nginx reverse proxy
- Architecture: Microservices gateway

## Key Components
- Landing page server (port 8080 by default)
- Service routing via nginx
- Self-signed SSL certificates
- systemd integration for auto-start
- YAML configuration

## Development Guidelines
- Use Go standard library where possible
- Keep the landing page simple and lightweight
- Follow Go best practices for HTTP handlers
- Ensure compatibility with ARM architecture (Raspberry Pi)
