package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`
	Services []struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		Icon        string `yaml:"icon"`
		Path        string `yaml:"path"`
		Enabled     bool   `yaml:"enabled"`
	} `yaml:"services"`
}

var config Config

func main() {
	// Load configuration
	if err := loadConfig("config.yaml"); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Setup routes
	http.HandleFunc("/", handleLanding)
	http.HandleFunc("/health", handleHealth)

	// Start server
	addr := fmt.Sprintf(":%d", config.Server.Port)
	log.Printf("🏠 Home Services Hub starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &config)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok"}`)
}

func handleLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	tmpl := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home Services Hub</title>
    <style>
        :root {
            --bg: #e7edf4;
            --panel-bg: #ffffff;
            --panel-border: #d2d7e0;
            --accent: #2563eb;
            --accent-soft: #e0edff;
            --text-main: #1f2933;
            --text-muted: #6b7280;
        }

        [data-theme="dark"] {
            --bg: #0f172a;
            --panel-bg: #334155;
            --panel-border: #475569;
            --accent: #3b82f6;
            --accent-soft: #1e3a8a;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: var(--bg);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 32px;
            transition: background 0.3s ease, color 0.3s ease;
        }

        .container {
            max-width: 800px;
            width: 100%;
            text-align: center;
        }

        h1 {
            font-size: 3rem;
            margin-bottom: 16px;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 1.1rem;
            margin-bottom: 48px;
        }

        .modules {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 24px;
            margin-bottom: 48px;
        }

        .module-card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            padding: 32px 24px;
            text-decoration: none;
            color: inherit;
            transition: all 0.2s ease;
            cursor: pointer;
        }

        .module-card:hover {
            transform: translateY(-4px);
            border-color: var(--accent);
            box-shadow: 0 12px 24px rgba(37, 99, 235, 0.12);
        }

        .module-icon {
            font-size: 3rem;
            margin-bottom: 16px;
        }

        .module-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .module-description {
            color: var(--text-muted);
            font-size: 0.95rem;
        }

        .module-card.disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .module-card.disabled:hover {
            transform: none;
            border-color: var(--panel-border);
            box-shadow: none;
        }

        .coming-soon {
            display: inline-block;
            background: var(--accent);
            color: white;
            font-size: 0.7rem;
            padding: 2px 8px;
            border-radius: 999px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 8px;
        }

        .footer {
            margin-top: 48px;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        @media (max-width: 600px) {
            .container {
                padding: 32px 24px;
            }
            h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🏠 Home Services Hub</h1>
        <p class="subtitle">Your centralized monitoring and management platform</p>
        
        <div class="modules">`

	// Dynamically generate service cards from config
	for _, service := range config.Services {
		if service.Enabled {
			tmpl += fmt.Sprintf(`
            <a href="%s" class="module-card">
                <div class="module-icon">%s</div>
                <div class="module-title">%s</div>
                <div class="module-description">%s</div>
            </a>`, service.Path, service.Icon, service.Name, service.Description)
		} else {
			tmpl += fmt.Sprintf(`
            <div class="module-card disabled">
                <div class="module-icon">%s</div>
                <div class="module-title">%s</div>
                <div class="module-description">%s</div>
                <span class="coming-soon">Coming Soon</span>
            </div>`, service.Icon, service.Name, service.Description)
		}
	}

	tmpl += `
        </div>

        <div class="footer">
            Home Services Hub v1.0.0 | Powered by Go & nginx
        </div>
    </div>
</body>
</html>`

	fmt.Fprint(w, tmpl)
}
