package main

import (
	"fmt"
	"net/http"
	"os"
)

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

