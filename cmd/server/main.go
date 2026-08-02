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

	"github.com/marlonfan/cindy-enterprise-server/internal/auth"
	"github.com/marlonfan/cindy-enterprise-server/internal/config"
	"github.com/marlonfan/cindy-enterprise-server/internal/devicelink"
	"github.com/marlonfan/cindy-enterprise-server/internal/mail"
	"github.com/marlonfan/cindy-enterprise-server/internal/media"
	"github.com/marlonfan/cindy-enterprise-server/internal/model"
	"github.com/marlonfan/cindy-enterprise-server/internal/store"
	"github.com/marlonfan/cindy-enterprise-server/internal/web"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Get("http://127.0.0.1:8080/healthz")
		if err != nil || response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		_ = response.Body.Close()
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration invalid", "error", err)
		os.Exit(1)
	}
	dataStore, err := store.Open(cfg.DataDir)
	if err != nil {
		logger.Error("open state store failed", "error", err)
		os.Exit(1)
	}
	var verificationSender mail.VerificationSender
	if cfg.SMTPHost != "" {
		verificationSender, err = mail.NewSMTPSender(mail.SMTPConfig{
			Host: cfg.SMTPHost, Port: cfg.SMTPPort, Username: cfg.SMTPUsername, Password: cfg.SMTPPassword,
			FromAddress: cfg.SMTPFromAddress, FromName: cfg.SMTPFromName, TLSMode: cfg.SMTPTLSMode,
			ServerName: cfg.SMTPServerName, Timeout: cfg.SMTPTimeout,
		})
		if err != nil {
			logger.Error("initialize SMTP sender failed", "error", err)
			os.Exit(1)
		}
	}
	authService, err := auth.New(context.Background(), cfg, dataStore, logger, verificationSender)
	if err != nil {
		logger.Error("initialize auth failed", "error", err)
		os.Exit(1)
	}
	mediaService, err := media.New(cfg)
	if err != nil {
		logger.Error("initialize media failed", "error", err)
		os.Exit(1)
	}
	modelService, err := model.New(cfg, logger)
	if err != nil {
		logger.Error("initialize model gateway failed", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	web.RegisterManifest(mux, cfg)
	authService.Register(mux)
	devicelink.New(dataStore, logger).Register(mux, authService.Require)
	mediaService.Register(mux, authService.Require)
	modelService.Register(mux, authService.Require)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		web.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /heartbeat", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	server := &http.Server{
		Addr: cfg.ListenAddr, Handler: web.Recover(logger, web.AccessLog(logger, mux)),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
	}
	go func() {
		logger.Info("server listening", "addr", cfg.ListenAddr, "public_base_url", cfg.PublicBaseURL, "region", cfg.Region)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}
