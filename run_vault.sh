#!/bin/bash
# Vault launcher with biometric authentication using termux-fingerprint
# Uses termux-keystore to store AES-256 key for vault encryption
# Starts Go vault service (vaultapp) on localhost:8080

VAULT_BIN="./vaultapp"
KEYSTORE_ALIAS="vault_key"
PID_FILE="$HOME/vaultapp.pid"
SERVICE_URL="http://127.0.0.1:8080"

# Function to start vault service if not running
start_vault() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Vault service already running (PID $PID)"
            return
        fi
    fi
    # Retrieve or create key from keystore
    if termux-keystore get "$KEYSTORE_ALIAS" >/dev/null 2>&1; then
        KEY_HEX=$(termux-keystore get "$KEYSTORE_ALIAS")
    else
        # Generate random 32-byte key
        KEY_HEX=$(head -c 32 /dev/urandom | hexdump -v -e '/1 "%02x"')
        termux-keystore put "$KEYSTORE_ALIAS" "$KEY_HEX"
    fi
    export VAULT_KEY="$KEY_HEX"
    # Start service
    nohup "$VAULT_BIN" > "$HOME/vaultapp.log" 2>&1 &
    echo $! > "$PID_FILE"
    echo "Vault service started (PID $!)"
    # Wait a bit for service to be ready
    sleep 2
}

# Function to stop vault service
stop_vault() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID"
            rm -f "$PID_FILE"
            echo "Vault service stopped"
        else
            rm -f "$PID_FILE"
            echo "Vault service not running"
        fi
    else
        echo "Vault service not running"
    fi
}

# Biometric authentication
authenticate() {
    echo "Please authenticate with fingerprint..."
    if termux-fingerprint; then
        echo "Authentication successful."
        return 0
    else
        echo "Authentication failed."
        return 1
    fi
}

# Menu
while true; do
    echo "=== Vault Menu ==="
    echo "1) Authenticate and start service"
    echo "2) Stop service"
    echo "3) Generate password"
    echo "4) Add to vault"
    echo "5) List vault entries"
    echo "6) Get vault entry"
    echo "7) Exit"
    read -p "Select option: " choice
    case $choice in
        1)
            if authenticate; then
                start_vault
            fi
            ;;
        2)
            stop_vault
            ;;
        3)
            read -p "Enter length (default 16): " len
            len=${len:-16}
            resp=$(curl -s "$SERVICE_URL/generate?length=$len")
            echo "$resp" | jq -r '.password // .'
            ;;
        4)
            read -p "Enter type (api_key/email): " typ
            read -p "Enter value: " val
            resp=$(curl -s -X POST "$SERVICE_URL/vault/add" \
                -H "Content-Type: application/json" \
                -d "{\"type\":\"$typ\",\"value\":\"$val\"}")
            echo "$resp" | jq -r '. // .'
            ;;
        5)
            resp=$(curl -s "$SERVICE_URL/vault/list")
            echo "$resp" | jq -r '. // .'
            ;;
        6)
            read -p "Enter entry ID: " eid
            resp=$(curl -s "$SERVICE_URL/vault/get?id=$eid")
            echo "$resp" | jq -r '. // .'
            ;;
        7)
            stop_vault
            echo "Goodbye."
            exit 0
            ;;
        *)
            echo "Invalid option"
            ;;
    esac
    echo
done
