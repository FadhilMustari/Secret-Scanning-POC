package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// CATATAN: Aplikasi ini adalah TARGET LATIHAN untuk OWASP ZAP (DAST) pada PoC ini.
// Beberapa endpoint sengaja dibuat tidak aman (header keamanan hilang, cookie tanpa
// flag, form tanpa anti-CSRF, input yang dipantulkan) supaya scanner punya temuan
// untuk dilaporkan. JANGAN pakai pola-pola ini di aplikasi produksi.

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/search", searchHandler)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// healthHandler dipakai pipeline untuk cek app sudah siap sebelum ZAP scan.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

// indexHandler: landing page. Sengaja membocorkan versi server lewat header dan
// menyetel cookie tanpa flag keamanan, agar ZAP melaporkannya.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "poc-payment-service/1.0")
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "poc-demo-session"})

	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Payment Integration Service</title></head>
<body>
  <h1>Payment Integration Service</h1>
  <ul>
    <li><a href="/login">Login</a></li>
    <li><a href="/search?q=test">Search</a></li>
    <li><a href="/health">Health</a></li>
  </ul>
</body>
</html>`)
}

// loginHandler menampilkan form login tanpa anti-CSRF token. ZAP akan menandai
// "Absence of Anti-CSRF Tokens" dan field password sebagai temuan.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h1>Login</h1>
  <form method="POST" action="/login">
    <label>Username <input type="text" name="username"></label>
    <label>Password <input type="password" name="password"></label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>`)
}

// searchHandler memantulkan parameter query ke HTML tanpa encoding. Ini sink XSS
// yang sengaja ditinggalkan sebagai target untuk ZAP full scan (active).
func searchHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body>
  <h1>Search results</h1>
  <p>You searched for: %s</p>
</body>
</html>`, q)
}
