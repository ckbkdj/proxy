package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/audit"
	"github.com/ckbkdj/newapi-risk-control/internal/cache"
	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/ckbkdj/newapi-risk-control/internal/events"
	"github.com/ckbkdj/newapi-risk-control/internal/gateway"
	"github.com/ckbkdj/newapi-risk-control/internal/httpapi"
	"github.com/ckbkdj/newapi-risk-control/internal/pipeline"
	"github.com/ckbkdj/newapi-risk-control/internal/security"
	"github.com/ckbkdj/newapi-risk-control/internal/store"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fatal("configuration error", err)
	}
	logLevel := slog.LevelInfo
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cipher, err := security.NewCipher(cfg.MasterEncryptionKey)
	if err != nil {
		fatal("initialize encryption", err)
	}
	st, err := store.New(ctx, cfg)
	if err != nil {
		fatal("initialize PostgreSQL", err)
	}
	defer st.Close()

	migrationPath := os.Getenv("MIGRATIONS_PATH")
	if migrationPath == "" {
		migrationPath = "migrations/001_init.sql"
	}
	if err := st.Migrate(ctx, migrationPath); err != nil {
		fatal("database migration", err)
	}
	if err := st.EnsureTracePartitions(ctx, time.Now(), cfg.DefaultRetentionDays); err != nil {
		fatal("initialize trace partitions", err)
	}
	passwordHash, err := security.HashPassword(cfg.BootstrapAdminPassword)
	if err != nil {
		fatal("bootstrap admin password", err)
	}
	if err := st.BootstrapAdmin(ctx, cfg.BootstrapAdminUsername, passwordHash, cfg.BootstrapAdminRole); err != nil {
		fatal("bootstrap admin", err)
	}
	if err := st.SeedBuiltinRules(ctx, audit.BuiltinRules()); err != nil {
		fatal("seed cyber rules", err)
	}
	if err := seedDefaultAuditProfile(ctx, cfg, st, cipher); err != nil {
		fatal("seed default audit profile", err)
	}

	redisClient, err := cache.New(ctx, cfg)
	if err != nil {
		fatal("initialize Redis", err)
	}
	defer redisClient.Close()
	kafkaClient, err := events.NewKafka(cfg)
	if err != nil {
		fatal("initialize Kafka", err)
	}
	defer kafkaClient.Close()

	tracePipeline := pipeline.New(cfg, st, redisClient, kafkaClient, logger)
	tracePipeline.Start(ctx)
	auditEngine := audit.New(cfg, st, redisClient, cipher)
	auditEngine.Start(ctx)
	gatewayHandler := gateway.New(cfg, st, redisClient, cipher, auditEngine, tracePipeline, logger)
	api := httpapi.New(cfg, st, redisClient, kafkaClient, cipher, auditEngine, gatewayHandler, tracePipeline, logger)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("riskgate started", "listen", cfg.ListenAddr, "env", cfg.AppEnv)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			fatal("HTTP server", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}

func seedDefaultAuditProfile(ctx context.Context, cfg config.Config, st *store.Store, cipher *security.Cipher) error {
	endpoint := strings.TrimSpace(os.Getenv("AUDIT_MODEL_ENDPOINT"))
	model := strings.TrimSpace(os.Getenv("AUDIT_MODEL_NAME"))
	if endpoint == "" || model == "" {
		return nil
	}
	if err := gateway.ValidateUpstreamURL(ctx, endpoint, cfg.AllowPrivateUpstreams); err != nil {
		return fmt.Errorf("validate AUDIT_MODEL_ENDPOINT: %w", err)
	}
	profiles, err := st.ListAuditProfiles(ctx)
	if err != nil {
		return err
	}
	for _, profile := range profiles {
		if profile.Name == "default-small-model" {
			return nil
		}
	}
	keyCipher, err := cipher.EncryptString(os.Getenv("AUDIT_MODEL_API_KEY"))
	if err != nil {
		return err
	}
	threshold := .72
	if raw := os.Getenv("AUDIT_MODEL_BLOCK_THRESHOLD"); raw != "" {
		if value, parseErr := strconv.ParseFloat(raw, 64); parseErr == nil && value >= 0 && value <= 1 {
			threshold = value
		}
	}
	failMode := strings.ToLower(strings.TrimSpace(os.Getenv("AUDIT_MODEL_FAIL_MODE")))
	if failMode == "" {
		failMode = "closed"
	}
	if failMode != "closed" && failMode != "open" && failMode != "shadow" {
		return errors.New("AUDIT_MODEL_FAIL_MODE must be closed, open, or shadow")
	}
	_, err = st.UpsertAuditProfile(ctx, core.AuditProfile{
		Name: "default-small-model", Endpoint: endpoint, Model: model,
		APIKeyCipher: keyCipher, Enabled: true, FailMode: failMode,
		BlockThreshold: threshold, TimeoutMS: 8000,
		MaxInputChars: 32000, CacheTTLSeconds: 600,
	})
	return err
}

func healthcheck() {
	endpoint := "http://127.0.0.1:8080/healthz"
	if len(os.Args) > 2 {
		endpoint = os.Args[2]
	}
	client := http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(endpoint)
	if err != nil || response.StatusCode != http.StatusOK {
		if response != nil {
			_ = response.Body.Close()
		}
		os.Exit(1)
	}
	_ = response.Body.Close()
}

func fatal(message string, err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", message, err)
	os.Exit(1)
}
