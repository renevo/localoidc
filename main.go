package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// GoReleaser replaces these values with release metadata using linker flags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Dependency error attributes can include submitted parameters. Keep only
	// fixed log messages and severity; never log requests, URLs or token payloads.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			switch attr.Key {
			case slog.TimeKey, slog.LevelKey, slog.MessageKey:
				return attr
			default:
				return slog.Attr{}
			}
		},
	}))
	slog.SetDefault(logger)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "localoidc:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cfg, err := loadSettings(ctx, args, os.Environ(), os.Stderr)
	if errors.Is(err, errVersionRequested) {
		fmt.Printf("localoidc %s (commit %s, built %s)\n", version, commit, date)
		return nil
	}
	if err != nil {
		return err
	}
	app, err := newServer(cfg)
	if err != nil {
		return fmt.Errorf("initialize provider: %w", err)
	}
	listener, err := net.Listen("tcp4", cfg.address())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.address(), err)
	}
	server := &http.Server{
		Handler:           app.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	fmt.Fprintf(os.Stderr, "DEVELOPMENT ONLY — localoidc provides synthetic identities, NOT authentication.\nIssuer: %s\nSkip ordinary confirmation: %t\n", cfg.issuer(), cfg.SkipConfirmation)
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		if err := <-result; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
