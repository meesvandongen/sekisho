package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// version is set at release build time with -ldflags "-X main.version=…".
var version = "dev"

func newHTTPServer(cfg Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func main() {
	configPath := flag.String("config", "", "path to the JSON configuration file")
	policyTests := flag.String("test-policies", "", "run offline policy fixtures relative to the config file")
	explain := flag.Bool("explain", false, "print the effective policy of every OpenAPI operation and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("sekisho", version)
		return
	}
	if *configPath == "" || flag.NArg() != 0 || (*explain && *policyTests != "") {
		log.Fatal("usage: sekisho -config config.json [-explain | -test-policies fixtures.json] | sekisho -version")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if *explain {
		if err := explainPolicies(context.Background(), cfg, os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *policyTests != "" {
		if err := runPolicyFixtures(context.Background(), cfg, *policyTests, os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := serve(cfg); err != nil {
		log.Fatal(err)
	}
}

func serve(cfg Config) error {
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		return err
	}
	server := newHTTPServer(cfg, handler)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdownDone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownDone <- server.Shutdown(shutdownCtx)
	}()
	log.Printf("listening on %s", cfg.Listen)
	listenErr := server.ListenAndServe()
	stop()
	shutdownErr := <-shutdownDone
	if errors.Is(listenErr, http.ErrServerClosed) {
		return shutdownErr
	}
	return errors.Join(listenErr, shutdownErr)
}
