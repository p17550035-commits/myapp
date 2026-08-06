// main.go – Password generator + encrypted vault (Android-ready)
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// ---------- configuration ----------
const vaultFileName = "./vault.enc" // relative to working dir (app files dir)

// AES‑256‑GCM key: 32 bytes. Expected via env var VAULT_KEY (hex string).
// If missing we generate a random key and print it once (for demo only).
func getKey() []byte {
	if hexKey := os.Getenv("VAULT_KEY"); hexKey != "" {
		b, err := hex.DecodeString(hexKey)
		if err != nil || len(b) != 32 {
			fmt.Fprintln(os.Stderr, "VAULT_KEY must be a 64‑char hex string (32 bytes). Using temporary insecure key.")
		} else {
			return b
		}
	}
	// fallback: random key (changes each run → data not persisted across restarts)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "��⚠��️  No VAULT_KEY set – using random key for this run.\n")
	fmt.Fprintf(os.Stderr, "   To persist data, set: export VAULT_KEY=%x\n", key)
	return key
}

// ---------- crypto helpers ----------
func encrypt(key []byte, plaintext string) (map[string]string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return map[string]string{
		"nonce":   hex.EncodeToString(nonce),
		"cipher":  hex.EncodeToString(ciphertext),
		"tag":     "", // GCM puts tag at end of ciphertext; we keep it inside `cipher`
	}, nil
}

func decrypt(key []byte, data map[string]string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce, err := hex.DecodeString(data["nonce"])
	if err != nil {
		return "", err
	}
	ciphertext, err := hex.DecodeString(data["cipher"])
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ---------- vault persistence ----------
type vaultEntry struct {
	ID     string `json:"id"`
	Type   string `json:"type"` // "api_key" or "email"
	Nonce  string `json:"nonce"`
	Cipher string `json:"cipher"`
}

func loadVault() []vaultEntry {
	if _, err := os.Stat(vaultFileName); os.IsNotExist(err) {
		return []vaultEntry{}
	}
	b, err := os.ReadFile(vaultFileName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read vault:", err)
		return []vaultEntry{}
	}
	var entries []vaultEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		fmt.Fprintln(os.Stderr, "cannot parse vault:", err)
		return []vaultEntry{}
	}
	return entries
}

func saveVault(entries []vaultEntry) error {
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(vaultFileName, b, 0600)
}

// ---------- PID handling ----------
func writePidFile() error {
	pidFile := filepath.Join(os.TempDir(), "vaultapp.pid")
	return os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
}

// ---------- random helpers ----------
func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	v := binary.BigEndian.Uint32(b)
	return int(v) % n
}

// ---------- HTTP handlers ----------
var vault []vaultEntry
var key []byte

func generateHandler(w http.ResponseWriter, r *http.Request) {
	length := 16
	if v := r.URL.Query().Get("length"); v != "" {
		fmt.Sscanf(v, "%d", &length)
		if length < 1 || length > 4096 {
			length = 16
		}
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-="
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[randIntn(len(charset))]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"password": string(b)})
}

func vaultAddHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Type string `json:"type"` // "api_key" or "email"
		Val  string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if payload.Type != "api_key" && payload.Type != "email" {
		http.Error(w, "type must be 'api_key' or 'email'", http.StatusBadRequest)
		return
	}
	if payload.Val == "" {
		http.Error(w, "value must be non‑empty", http.StatusBadRequest)
		return
	}
	enc, err := encrypt(key, payload.Val)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}
	entry := vaultEntry{
		ID:    fmt.Sprintf("%x", cryptoRandBytes(4)), // 8‑char hex id
		Type:  payload.Type,
		Nonce: enc["nonce"],
		Cipher: enc["cipher"],
	}
	vault = append(vault, entry)
	if err := saveVault(vault); err != nil {
		http.Error(w, "could not save vault", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": entry.ID, "type": entry.Type})
}

func vaultListHandler(w http.ResponseWriter, r *http.Request) {
	list := make([]map[string]string, len(vault))
	for i, e := range vault {
		list[i] = map[string]string{"id": e.ID, "type": e.Type}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func vaultGetHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	var entry *vaultEntry
	for i := range vault {
		if vault[i].ID == id {
			entry = &vault[i]
			break
		}
	}
	if entry == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	plain, err := decrypt(key, map[string]string{"nonce": entry.Nonce, "cipher": entry.Cipher})
	if err != nil {
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":     entry.ID,
		"type":   entry.Type,
		"value":  plain,
	})
}

// ---------- utility ----------
func cryptoRandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ---------- main ----------
func main() {
	key = getKey()
	vault = loadVault()

	// write PID file so Android can detect if we’re already up
	if err := writePidFile(); err != nil {
		fmt.Fprintln(os.Stderr, "could not write PID file:", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/generate", generateHandler)
	mux.HandleFunc("/vault/add", vaultAddHandler)
	mux.HandleFunc("/vault/list", vaultListHandler)
	mux.HandleFunc("/vault/get", vaultGetHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, `Password Generator & Encrypted Vault (Go build)

Endpoints:
 GET  /generate?length=12                → random password
 POST /vault/add   {"type":"api_key","value":"…"} → store encrypted entry
 GET  /vault/list               → list stored entries (id,type)
 GET  /vault/get?id=<id>        → decrypt and return value

Set VAULT_KEY (64‑hex) for persistent encryption across runs.
	`)
	})

	addr := "127.0.0.1:8080"
	fmt.Printf("���🚀  Vault service listening on http://%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "ListenAndServe:", err)
	}
}
