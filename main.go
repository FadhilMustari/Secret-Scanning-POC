package main

import (
	"fmt"
	"net/http"
	"os"

	"golang.org/x/text/language"
)

// TEST ONLY - deliberately calls a vulnerable golang.org/x/text function
// (GO-2022-1059) to verify the SCA (govulncheck) step in the DevSecOps pipeline.
func parseAcceptLanguage(header string) ([]language.Tag, []float32, error) {
	return language.ParseAcceptLanguage(header)
}

// Config loads credentials from environment variables (bukan hardcode!)
type Config struct {
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSRegion          string
	Port               string
}

func loadConfig() Config {
	return Config{
		AWSAccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		AWSRegion:          os.Getenv("AWS_REGION"),
		Port:               os.Getenv("PORT"),
	}
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	if _, _, err := parseAcceptLanguage(r.Header.Get("Accept-Language")); err != nil {
		fmt.Fprintln(os.Stderr, "language parse error:", err)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, `{"status": "ok"}`)
}

func main() {
	cfg := loadConfig()

	fmt.Println("Payment integration service starting...")
	fmt.Printf("Connecting to AWS region: %s\n", cfg.AWSRegion)

	http.HandleFunc("/health", healthCheck)

	addr := ":" + cfg.Port
	if cfg.Port == "" {
		addr = ":8080"
	}

	fmt.Printf("Server listening on %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

