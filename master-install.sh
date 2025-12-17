#!/bin/bash
# Master installer for MyHomeServicesHub ecosystem
# Allows selection and installation of WeatherDash, HomeServicesHub, and (future) modules

set -e

MODULES=("Home Services Hub" "WeatherDash" "My-SNMP-App" "MyWatchfulWoo-Woos" "Quit")
MODULE_PATHS=("MyHomeServicesHub" "MyWeatherDash" "My-SNMP-App" "MyWatchfulWoo-Woos" "quit")

function show_menu() {
    echo "\n==== MyHomeServicesHub Master Installer ===="
    echo "Select a module to install:"
    for i in "${!MODULES[@]}"; do
        echo "  $((i+1)). ${MODULES[$i]}"
    done
}

while true; do
    show_menu
    read -p "Enter number: " choice
    case $choice in
        1)
            echo "\nInstalling Home Services Hub..."
            cd "$(dirname "$0")/MyHomeServicesHub"
            bash install.sh
            cd - > /dev/null
            ;;
        2)
            echo "\nInstalling WeatherDash..."
            cd "$(dirname "$0")/MyWeatherDash"
            bash install.sh
            cd - > /dev/null
            ;;
        3)
            echo "\nInstalling My-SNMP-App..."
            cd "$(dirname "$0")/../My-SNMP-App"
            if [ -f install.sh ]; then
                bash install.sh
            else
                echo "No install.sh found for My-SNMP-App. Please install manually."
            fi
            cd - > /dev/null
            ;;
        4)
            echo "\nInstalling MyWatchfulWoo-Woos..."
            echo "(No install.sh found yet. Please install manually if needed.)"
            ;;
        5)
            echo "Exiting installer."
            exit 0
            ;;
        *)
            echo "Invalid selection. Please try again."
            ;;
    esac
done
