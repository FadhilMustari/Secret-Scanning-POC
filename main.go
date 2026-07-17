package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()

	// Health endpoint dipakai pipeline untuk cek app sudah siap sebelum ZAP scan.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// Endpoint utama — sengaja minimal tanpa security header tambahan,
	// jadi ZAP baseline punya sesuatu untuk dilaporkan pada PoC ini.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Payment integration service is running.")
	})

	// Timeout eksplisit: tanpa ini http.ListenAndServe rentan Slowloris DoS
	// dan ditandai sebagai security hotspot oleh SonarQube.
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
