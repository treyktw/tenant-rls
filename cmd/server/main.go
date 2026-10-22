// Command server runs the demo API.
//
//	APP_DATABASE_URL=... PLATFORM_DATABASE_URL=... AUTH_HS256_SECRET=... go run ./cmd/server
//
// It refuses to start if either database URL points at a login that is not
// a plain member of its runtime role (the owner, a superuser, a BYPASSRLS
// role, or the wrong group).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/treyktw/tenant-rls/auth"
	"github.com/treyktw/tenant-rls/db"
	"github.com/treyktw/tenant-rls/httpapi"
	"github.com/treyktw/tenant-rls/internal/demoapi"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	database, err := db.Open(ctx, os.Getenv("APP_DATABASE_URL"), os.Getenv("PLATFORM_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer database.Close()

	verifier, err := auth.NewJWTVerifier(auth.Options{
		HS256Secret: []byte(os.Getenv("AUTH_HS256_SECRET")),
		Issuer:      os.Getenv("AUTH_ISSUER"),
		Audience:    os.Getenv("AUTH_AUDIENCE"),
	})
	if err != nil {
		return err
	}

	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           httpapi.Observe(log, (&demoapi.Handler{DB: database, Verifier: verifier}).Router()),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
