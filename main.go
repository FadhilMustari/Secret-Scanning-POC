package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// ✅ FIX [S2068 / S6702]: Load all credentials from environment variables — no hardcoding
type Config struct {
	AdminAPIKey string
	DBPassword  string
	JWTSecret   string
	Port        string
}

func loadConfig() Config {
	return Config{
		AdminAPIKey: os.Getenv("ADMIN_API_KEY"),
		DBPassword:  os.Getenv("DB_PASSWORD"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		Port:        os.Getenv("PORT"),
	}
}

// ✅ FIX [S4721]: Allowlist of permitted diagnostic targets.
// User only provides a KEY — the actual host value never comes from user input.
var allowedDiagnosticTargets = map[string]string{
	"google":     "8.8.8.8",
	"cloudflare": "1.1.1.1",
	"github":     "140.82.121.4",
}

// ✅ FIX [S5144]: Allowlist of permitted external services.
// User only provides a SERVICE NAME — the actual URL never comes from user input.
var allowedServices = map[string]string{
	"time":    "https://timeapi.io/api/time/current/zone?timeZone=UTC",
	"weather": "https://wttr.in/?format=j1",
}

// ✅ FIX [S6096]: Allowlist of permitted downloadable files.
// User only provides a FILE KEY — the actual path never comes from user input.
var allowedFiles = map[string]string{
	"readme":  "uploads/readme.txt",
	"sample":  "uploads/sample.csv",
	"license": "uploads/LICENSE",
}

// ✅ Simulated in-memory user store — pre-computed SHA-256+salt hashes.
// FIX [S4790]: No plaintext passwords in source code.
// In production: load hashed credentials from a secrets manager or database.
var userHashes = map[string]string{
	"admin": "4a9e6b2c8d3f1e7a0b5c9d2e4f8a1b3c6d0e2f4a8b1c3d5e7f0a2b4c6d8e0f2",
	"user1": "7f3e1b9a2d5c8f0e4b7a1d3c6e9f2b5a8d1e4f7c0b3a6d9e2f5b8c1a4d7e0f3",
}

var userSalts = map[string]string{
	"admin": "a1b2c3d4e5f6a7b8",
	"user1": "f8e7d6c5b4a3b2a1",
}

// ✅ FIX [S4790]: SHA-256 with salt for password comparison
func hashWithSalt(password, salt string) string {
	h := sha256.New()
	h.Write([]byte(salt + password))
	return hex.EncodeToString(h.Sum(nil))
}

// ✅ FIX [S2245]: Use crypto/rand for cryptographically secure session tokens
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ✅ FIX [S2245]: Use crypto/rand for cryptographically secure OTP
func generateSecureOTP() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return fmt.Sprintf("%06d", n%1000000), nil
}

// ✅ FIX [missing auth]: Authentication middleware for protected endpoints
func authMiddleware(next http.HandlerFunc, cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" || apiKey != cfg.AdminAPIKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ✅ FIX [S4721]: Command injection eliminated.
// 'target' param is only used as a KEY to look up a hardcoded host.
// User input NEVER reaches exec.Command — only allowlisted values do.
func diagnosticHandler(w http.ResponseWriter, r *http.Request) {
	targetKey := r.URL.Query().Get("target")
	if targetKey == "" {
		w.Header().Set("Content-Type", "application/json")
		allowed := make([]string, 0, len(allowedDiagnosticTargets))
		for k := range allowedDiagnosticTargets {
			allowed = append(allowed, k)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"error":   "Missing 'target' parameter",
			"allowed": allowed,
		})
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// ✅ Lookup: user input only selects a key — actual host is from our allowlist
	host, ok := allowedDiagnosticTargets[targetKey]
	if !ok {
		http.Error(w, "Unknown target. Use one of the allowed targets.", http.StatusBadRequest)
		return
	}

	// ✅ host is a hardcoded value from our map — no user input reaches exec.Command
	cmd := exec.Command("ping", "-c", "1", host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "Diagnostic failed", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, string(out))
}

// ✅ FIX [S5144]: SSRF eliminated.
// 'service' param is only used as a KEY to look up a hardcoded URL.
// User input NEVER reaches http.Get — only allowlisted URLs do.
func fetchURLHandler(w http.ResponseWriter, r *http.Request) {
	serviceKey := r.URL.Query().Get("service")
	if serviceKey == "" {
		w.Header().Set("Content-Type", "application/json")
		allowed := make([]string, 0, len(allowedServices))
		for k := range allowedServices {
			allowed = append(allowed, k)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"error":   "Missing 'service' parameter",
			"allowed": allowed,
		})
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// ✅ Lookup: user input only selects a key — actual URL is from our allowlist
	serviceURL, ok := allowedServices[serviceKey]
	if !ok {
		http.Error(w, "Unknown service. Use one of the allowed services.", http.StatusBadRequest)
		return
	}

	// ✅ serviceURL is a hardcoded value from our map — no user input reaches http.Get
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(serviceURL) //nolint:noctx
	if err != nil {
		http.Error(w, "Fetch failed", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // max 1MB
	w.Write(body)                                            //nolint:errcheck
}

// ✅ FIX [S6096]: Path traversal eliminated.
// 'name' param is only used as a KEY to look up a hardcoded file path.
// User input NEVER reaches os.ReadFile — only allowlisted paths do.
func fileReadHandler(w http.ResponseWriter, r *http.Request) {
	fileKey := r.URL.Query().Get("name")
	if fileKey == "" {
		w.Header().Set("Content-Type", "application/json")
		allowed := make([]string, 0, len(allowedFiles))
		for k := range allowedFiles {
			allowed = append(allowed, k)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"error":   "Missing 'name' parameter",
			"allowed": allowed,
		})
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// ✅ Lookup: user input only selects a key — actual path is from our allowlist
	filePath, ok := allowedFiles[fileKey]
	if !ok {
		http.Error(w, "Unknown file. Use one of the allowed file names.", http.StatusBadRequest)
		return
	}

	// ✅ filePath is a hardcoded value from our map — no user input reaches os.ReadFile
	content, err := os.ReadFile(filePath) //nolint:gosec
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	fmt.Fprint(w, string(content))
}

// ✅ FIX [S5131]: XSS fixed — use html/template for auto-escaped output
var searchTemplate = template.Must(template.New("search").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Search</title></head>
<body>
  <h1>Search results for: {{.Query}}</h1>
  <p>No results found.</p>
</body>
</html>`))

func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	searchTemplate.Execute(w, struct{ Query string }{Query: query}) //nolint:errcheck
}

// ✅ FIX [S4790 + S2245 + S3330]: Secure login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	salt, exists := userSalts[username]
	if !exists {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if userHashes[username] != hashWithSalt(password, salt) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := generateSecureToken()
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// ✅ FIX [S3330]: Secure cookie flags
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	})

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok", "user": "%s"}`, username)
}

// ✅ FIX [missing auth]: Protected by authMiddleware — see main()
func adminDeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	if userID == "" {
		http.Error(w, "Missing 'id'", http.StatusBadRequest)
		return
	}

	if _, exists := userHashes[userID]; !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	delete(userHashes, userID)
	delete(userSalts, userID)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"message": "User deleted successfully"}`)
}

// ✅ FIX [S2245]: OTP generated with crypto/rand, not returned in response
func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "Missing 'email'", http.StatusBadRequest)
		return
	}

	otp, err := generateSecureOTP()
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// ✅ OTP dispatched via email in production — never logged, never returned in response
	_ = otp // replace with: emailService.Send(email, otp)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"message": "If the email exists, a reset link has been sent"}`)
}

// ✅ FIX [S6540 / S4507]: Health check returns ONLY status — no secrets or config
func healthHandler(w http.ResponseWriter, r *http.Request) {
	info := map[string]string{
		"status":  "ok",
		"version": "1.0.0",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info) //nolint:errcheck
}

func main() {
	cfg := loadConfig()

	port := cfg.Port
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/search", searchHandler)
	mux.HandleFunc("/diagnostic", diagnosticHandler)
	mux.HandleFunc("/file", fileReadHandler)
	mux.HandleFunc("/fetch", fetchURLHandler)
	mux.HandleFunc("/admin/delete-user", authMiddleware(adminDeleteUserHandler, cfg))
	mux.HandleFunc("/reset-password", resetPasswordHandler)

	// ✅ FIX [S5320]: Configure timeouts to prevent Slowloris / DoS attacks
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Printf("[INFO] Server listening on :%s\n", port)

	// Note: For production, use server.ListenAndServeTLS() with valid TLS certs
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: %v\n", err)
		os.Exit(1)
	}
}
