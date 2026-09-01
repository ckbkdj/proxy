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

	"github.com/ckbkdj/proxy/newapi-risk-platform/internal/platform"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := platform.LoadConfig()
	if err != nil {
		logger.Error("configuration validation failed", "error", err)
		os.Exit(1)
	}
	logger.Info(
		"starting New API risk platform",
		"version", version,
		"commit", commit,
		"environment", cfg.Environment,
	)

	startupContext, startupCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer startupCancel()
	store, err := platform.NewStore(startupContext, cfg, logger)
	if err != nil {
		logger.Error("PostgreSQL startup failed", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	if err := store.Migrate(startupContext); err != nil {
		logger.Error("database migration failed", "error", err)
		os.Exit(1)
	}
	if err := store.MaintainPartitions(startupContext, cfg.RetentionDays); err != nil {
		logger.Error("initial partition maintenance failed", "error", err)
		os.Exit(1)
	}

	security := platform.NewSecurity(cfg)
	if err := store.Bootstrap(startupContext, cfg, security); err != nil {
		logger.Error("bootstrap failed", "error", err)
		os.Exit(1)
	}
	redisGuard := platform.NewRedisGuard(startupContext, cfg, logger)
	defer func() {
		if err := redisGuard.Close(); err != nil {
			logger.Warn("Redis close failed", "error", err)
		}
	}()
	eventSink, err := platform.NewEventSink(cfg, store, logger)
	if err != nil {
		logger.Error("Kafka configuration failed", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := eventSink.Close(); err != nil {
			logger.Warn("Kafka close failed", "error", err)
		}
	}()

	backgroundContext, backgroundCancel := context.WithCancel(context.Background())
	defer backgroundCancel()
	eventContext, eventCancel := context.WithCancel(context.Background())
	defer eventCancel()
	traceContext, traceCancel := context.WithCancel(context.Background())
	defer traceCancel()

	eventSink.Start(eventContext)
	auditEngine := platform.NewAuditEngine(cfg, store, security, logger)
	if err := auditEngine.Start(backgroundContext); err != nil {
		logger.Error("audit engine startup failed", "error", err)
		os.Exit(1)
	}
	traceWriter := platform.NewTraceWriter(cfg, store, redisGuard, eventSink, logger)
	traceWriter.Start(traceContext)
	gateway := platform.NewGateway(cfg, store, security, redisGuard, auditEngine, traceWriter, logger)
	httpService := platform.NewHTTPService(
		cfg,
		store,
		security,
		redisGuard,
		eventSink,
		auditEngine,
		gateway,
		traceWriter,
		logger,
	)

	go maintainPartitions(backgroundContext, cfg, store, logger)
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpService.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("HTTP server listening", "address", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
		close(serverErrors)
	}()

	signalContext, stopSignals := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stopSignals()
	select {
	case <-signalContext.Done():
		logger.Info("shutdown signal received")
	case err := <-serverErrors:
		if err != nil {
			logger.Error("HTTP server failed", "error", err)
		}
	}

	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		logger.Error("HTTP graceful shutdown failed", "error", err)
		_ = server.Close()
	}

	traceCancel()
	traceWriter.Wait()
	eventCancel()
	eventSink.Wait()
	backgroundCancel()
	logger.Info("New API risk platform stopped")
}

func maintainPartitions(
	ctx context.Context,
	cfg platform.Config,
	store *platform.Store,
	logger *slog.Logger,
) {
	ticker := time.NewTicker(cfg.PartitionMaintenanceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			retentionDays := store.GetIntSetting(ctx, "retention_days", cfg.RetentionDays)
			maintenanceContext, cancel := context.WithTimeout(ctx, 5*time.Minute)
			err := store.MaintainPartitions(maintenanceContext, retentionDays)
			cancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("partition maintenance failed", "error", err)
			}
		}
	}
}
