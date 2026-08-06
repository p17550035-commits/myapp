# VaultApp

Password generator and encrypted vault with biometric authentication.

## Components

- `vaultapp`: Go binary providing HTTP API for password generation and encrypted storage (AES-256-GCM).
- `run_vault.sh`: Wrapper script that uses termux-fingerprint for authentication, manages the vault service via termux-keystore, and provides a simple terminal menu to interact with the service.

## Setup

1. Ensure you have the required packages installed:
   ```bash
   pkg install -y openjdk-17 android-tools aapt aapt2 apksigner d8 jq termux-api
   ```
   (The Go binary is already built for android/arm64 and placed in the repository.)

2. Build the Go binary (if you changed main.go):
   ```bash
   export GOOS=android GOARCH=arm64
   go build -o vaultapp main.go
   ```

3. Make the launcher executable:
   ```bash
   chmod +x run_vault.sh
   ```

## Usage

Run the launcher:
```bash
./run_vault.sh
```

Follow the prompts:
- First, authenticate with fingerprint to start the service.
- Then use the menu to:
  1. Generate a password
  2. Add an API key or e‑mail to the vault (encrypted)
  3. List stored entries
  4. Retrieve a decrypted entry by ID
  5. Stop the service
  6. Exit

The vault service runs on `http://127.0.0.1:8080` and stores the encrypted data in `./vault.enc` (relative to the working directory). The encryption key is stored securely in the Android Keystore via `termux-keystore`.

## Notes

- The service will remain running in the background until you choose to stop it.
- If you stop the service, the encrypted data persists in `vault.enc` and can be accessed again after re‑authentication.
- The Go binary is compiled for Android arm64 and should run on any modern Android device via Termux.

