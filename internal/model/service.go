package model

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/marlonfan/cindy-enterprise-server/internal/config"
	"github.com/marlonfan/cindy-enterprise-server/internal/web"
)

type Service struct {
	cfg    config.Config
	logger *slog.Logger
	proxy  *httputil.ReverseProxy
}

func New(cfg config.Config, logger *slog.Logger) (*Service, error) {
	service := &Service{cfg: cfg, logger: logger}
	if cfg.ModelGatewayUpstream != "" {
		upstream, err := url.Parse(cfg.ModelGatewayUpstream)
		if err != nil {
			return nil, err
		}
		proxy := httputil.NewSingleHostReverseProxy(upstream)
		originalDirector := proxy.Director
		proxy.Director = func(request *http.Request) {
			incomingAuth := request.Header.Get("Authorization")
			incomingAPIKey := request.Header.Get("x-api-key")
			originalDirector(request)
			request.URL.Path = strings.TrimPrefix(request.URL.Path, "/api/gateway")
			if request.URL.Path == "" {
				request.URL.Path = "/"
			}
			if service.cfg.ModelGatewayUpstreamKey != "" {
				if incomingAPIKey != "" {
					request.Header.Set("x-api-key", service.cfg.ModelGatewayUpstreamKey)
					request.Header.Del("Authorization")
				} else {
					request.Header.Set("Authorization", "Bearer "+service.cfg.ModelGatewayUpstreamKey)
					request.Header.Del("x-api-key")
				}
			} else {
				request.Header.Set("Authorization", incomingAuth)
				request.Header.Set("x-api-key", incomingAPIKey)
			}
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			service.logger.Warn("model gateway proxy failed", "path", r.URL.Path, "error", err)
			web.Error(w, http.StatusBadGateway, "GATEWAY_UNAVAILABLE", "model gateway is unavailable")
		}
		service.proxy = proxy
	}
	return service, nil
}

func (s *Service) Register(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("GET /api/model-access/credentials", require(http.HandlerFunc(s.credentials)))
	mux.Handle("POST /api/model-access/credentials/rotate", require(http.HandlerFunc(s.credentials)))
	mux.Handle("GET /api/model-access/models", require(http.HandlerFunc(s.models)))
	mux.HandleFunc("GET /api/model-catalog/catalog", s.catalog)
	if s.proxy != nil {
		mux.HandleFunc("/api/gateway/", s.gateway)
		mux.HandleFunc("/api/gateway", s.gateway)
	}
}

func (s *Service) credentials(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.ModelGatewayEndpoint == "" || s.cfg.ModelGatewayClientKey == "" {
		web.Error(w, http.StatusServiceUnavailable, "MODEL_ACCESS_DISABLED", "enterprise model gateway is not configured")
		return
	}
	web.JSON(w, http.StatusOK, map[string]string{"endpoint": s.cfg.ModelGatewayEndpoint, "apiKey": s.cfg.ModelGatewayClientKey})
}

func (s *Service) catalog(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.ModelCatalogFile == "" {
		web.Error(w, http.StatusServiceUnavailable, "MODEL_CATALOG_DISABLED", "enterprise model catalog is not configured")
		return
	}
	file, err := os.Open(s.cfg.ModelCatalogFile)
	if err != nil {
		web.Error(w, http.StatusServiceUnavailable, "MODEL_CATALOG_UNAVAILABLE", "enterprise model catalog is unavailable")
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := io.Copy(w, file); err != nil {
		s.logger.Warn("write model catalog failed", "error", err)
	}
}

func (s *Service) models(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.ModelListFile == "" {
		web.JSON(w, http.StatusOK, map[string]any{"models": []any{}})
		return
	}
	data, err := os.ReadFile(s.cfg.ModelListFile)
	if err != nil {
		web.Error(w, http.StatusServiceUnavailable, "MODEL_LIST_UNAVAILABLE", "enterprise model list is unavailable")
		return
	}
	var payload struct {
		Models []map[string]any `json:"models"`
	}
	if json.Unmarshal(data, &payload) != nil || payload.Models == nil {
		web.Error(w, http.StatusInternalServerError, "MODEL_LIST_INVALID", "enterprise model list must be a JSON object with a models array")
		return
	}
	web.JSON(w, http.StatusOK, payload)
}

func (s *Service) gateway(w http.ResponseWriter, r *http.Request) {
	if !s.validGatewayKey(r) {
		web.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "valid model gateway key required")
		return
	}
	s.proxy.ServeHTTP(w, r)
}

func (s *Service) validGatewayKey(r *http.Request) bool {
	provided := strings.TrimSpace(r.Header.Get("x-api-key"))
	if provided == "" {
		provided = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	if len(provided) != len(s.cfg.ModelGatewayClientKey) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(s.cfg.ModelGatewayClientKey)) == 1
}
