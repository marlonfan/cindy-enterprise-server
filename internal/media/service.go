package media

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marlonfan/cindy-enterprise-server/internal/auth"
	"github.com/marlonfan/cindy-enterprise-server/internal/config"
	"github.com/marlonfan/cindy-enterprise-server/internal/store"
	"github.com/marlonfan/cindy-enterprise-server/internal/web"
)

const maxMediaBytes int64 = 2 * 1024 * 1024 * 1024

type metadata struct {
	Key         string `json:"key"`
	OwnerID     string `json:"ownerId"`
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
	Public      bool   `json:"public"`
	CreatedAt   int64  `json:"createdAt"`
}

type Service struct {
	baseURL string
	root    string
	secret  []byte
	ttl     time.Duration
}

func New(cfg config.Config) (*Service, error) {
	root := filepath.Join(cfg.DataDir, "media")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &Service{baseURL: cfg.PublicBaseURL, root: root, secret: []byte(cfg.MediaSigningSecret), ttl: cfg.MediaURLTTL}, nil
}

func (s *Service) Register(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("POST /api/device-link/media/presign-put", require(http.HandlerFunc(s.presignDevicePut)))
	mux.Handle("POST /api/device-link/media/presign-get", require(http.HandlerFunc(s.presignDeviceGet)))
	mux.Handle("DELETE /api/device-link/media", require(http.HandlerFunc(s.deleteDeviceObject)))
	mux.HandleFunc("PUT /api/device-link/media/object", s.putObject)
	mux.HandleFunc("GET /api/device-link/media/object", s.getObject)
	mux.Handle("POST /api/oss/presign-put", require(http.HandlerFunc(s.presignPublicPut)))
	mux.HandleFunc("PUT /api/oss/object", s.putObject)
	mux.HandleFunc("GET /api/oss/public", s.getPublicObject)
}

func (s *Service) presignDevicePut(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	var body struct {
		Size        int64  `json:"size"`
		Ext         string `json:"ext"`
		ContentType string `json:"contentType"`
	}
	if web.DecodeJSON(r, &body, 32<<10) != nil || !validUpload(body.Size, body.Ext, body.ContentType) {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid media upload request")
		return
	}
	key := fmt.Sprintf("users/%s/%s.%s", claims.Subject, store.RandomToken(16), sanitizeExt(body.Ext))
	putURL, expires := s.signedURL("/api/device-link/media/object", http.MethodPut, key, claims.Subject, body.ContentType, body.Size, false)
	web.JSON(w, http.StatusOK, map[string]any{"putUrl": putURL, "key": key, "expiresAt": expires.Format(time.RFC3339)})
}

func (s *Service) presignDeviceGet(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	var body struct {
		Key string `json:"key"`
	}
	if web.DecodeJSON(r, &body, 32<<10) != nil || !strings.HasPrefix(body.Key, "users/"+claims.Subject+"/") {
		web.Error(w, http.StatusForbidden, "MEDIA_FORBIDDEN", "media object does not belong to this account")
		return
	}
	meta, err := s.readMetadata(body.Key)
	if err != nil {
		web.Error(w, http.StatusNotFound, "MEDIA_NOT_FOUND", "media object not found")
		return
	}
	getURL, expires := s.signedURL("/api/device-link/media/object", http.MethodGet, body.Key, claims.Subject, meta.ContentType, meta.Size, false)
	web.JSON(w, http.StatusOK, map[string]any{"getUrl": getURL, "expiresAt": expires.Format(time.RFC3339)})
}

func (s *Service) deleteDeviceObject(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	var body struct {
		Key string `json:"key"`
	}
	if web.DecodeJSON(r, &body, 32<<10) != nil || !strings.HasPrefix(body.Key, "users/"+claims.Subject+"/") {
		web.Error(w, http.StatusForbidden, "MEDIA_FORBIDDEN", "media object does not belong to this account")
		return
	}
	objectPath, metadataPath := s.paths(body.Key)
	objectErr := os.Remove(objectPath)
	_ = os.Remove(metadataPath)
	if objectErr != nil && !errors.Is(objectErr, os.ErrNotExist) {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete media object")
		return
	}
	web.JSON(w, http.StatusOK, map[string]bool{"deleted": !errors.Is(objectErr, os.ErrNotExist)})
}

func (s *Service) presignPublicPut(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	var body struct {
		Scene       string `json:"scene"`
		ContentType string `json:"contentType"`
		Size        int64  `json:"size"`
	}
	if web.DecodeJSON(r, &body, 32<<10) != nil || body.Size <= 0 || body.Size > 5*1024*1024 || strings.TrimSpace(body.ContentType) == "" {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid public upload request")
		return
	}
	ext := extensionForContentType(body.ContentType)
	key := fmt.Sprintf("public/%s/%s.%s", claims.Subject, store.RandomToken(16), ext)
	putURL, expires := s.signedURL("/api/oss/object", http.MethodPut, key, claims.Subject, body.ContentType, body.Size, true)
	publicURL := s.baseURL + "/api/oss/public?key=" + url.QueryEscape(key)
	web.JSON(w, http.StatusOK, map[string]any{
		"putUrl": putURL, "publicUrl": publicURL, "key": key,
		"headers": map[string]string{"Content-Type": body.ContentType}, "expiresAt": expires.Format(time.RFC3339),
	})
}

func (s *Service) putObject(w http.ResponseWriter, r *http.Request) {
	params, ok := s.verifySignedRequest(r, http.MethodPut)
	if !ok {
		web.Error(w, http.StatusForbidden, "SIGNATURE_INVALID", "upload signature is invalid or expired")
		return
	}
	if params.size <= 0 || params.size > maxMediaBytes {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid upload size")
		return
	}
	if strings.TrimSpace(r.Header.Get("Content-Type")) != params.contentType {
		web.Error(w, http.StatusForbidden, "CONTENT_TYPE_MISMATCH", "Content-Type does not match signed request")
		return
	}
	objectPath, metadataPath := s.paths(params.key)
	tmp, err := os.CreateTemp(s.root, "upload-*.tmp")
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create upload")
		return
	}
	tmpName := tmp.Name()
	defer func() { _ = tmp.Close(); _ = os.Remove(tmpName) }()
	written, err := io.Copy(tmp, io.LimitReader(r.Body, params.size+1))
	if err != nil || written != params.size {
		web.Error(w, http.StatusBadRequest, "SIZE_MISMATCH", "uploaded bytes do not match signed size")
		return
	}
	if err := tmp.Sync(); err != nil || tmp.Close() != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to finalize upload")
		return
	}
	if err := os.Rename(tmpName, objectPath); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to store upload")
		return
	}
	meta := metadata{Key: params.key, OwnerID: params.owner, ContentType: params.contentType, Size: written, Public: params.public, CreatedAt: time.Now().UnixMilli()}
	data, _ := json.Marshal(meta)
	if err := os.WriteFile(metadataPath, data, 0o600); err != nil {
		_ = os.Remove(objectPath)
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to store metadata")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Service) getObject(w http.ResponseWriter, r *http.Request) {
	params, ok := s.verifySignedRequest(r, http.MethodGet)
	if !ok {
		web.Error(w, http.StatusForbidden, "SIGNATURE_INVALID", "download signature is invalid or expired")
		return
	}
	s.serveObject(w, r, params.key, false)
}

func (s *Service) getPublicObject(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if !strings.HasPrefix(key, "public/") {
		http.NotFound(w, r)
		return
	}
	s.serveObject(w, r, key, true)
}

func (s *Service) serveObject(w http.ResponseWriter, r *http.Request, key string, requirePublic bool) {
	meta, err := s.readMetadata(key)
	if err != nil || (requirePublic && !meta.Public) {
		http.NotFound(w, r)
		return
	}
	objectPath, _ := s.paths(key)
	file, err := os.Open(objectPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("Cache-Control", "private, max-age=300")
	if meta.Public {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}
	http.ServeContent(w, r, filepath.Base(key), info.ModTime(), file)
}

type signedParams struct {
	key, owner, contentType string
	size                    int64
	public                  bool
}

func (s *Service) signedURL(path, method, key, owner, contentType string, size int64, public bool) (string, time.Time) {
	expires := time.Now().Add(s.ttl).UTC()
	query := url.Values{
		"key": {key}, "owner": {owner}, "ct": {contentType}, "size": {strconv.FormatInt(size, 10)},
		"exp": {strconv.FormatInt(expires.Unix(), 10)}, "public": {strconv.FormatBool(public)},
	}
	query.Set("sig", s.signature(method, query))
	return s.baseURL + path + "?" + query.Encode(), expires
}

func (s *Service) verifySignedRequest(r *http.Request, method string) (signedParams, bool) {
	query := r.URL.Query()
	for _, key := range []string{"key", "owner", "ct", "size", "exp", "public", "sig"} {
		if len(query[key]) != 1 {
			return signedParams{}, false
		}
	}
	expires, err := strconv.ParseInt(query.Get("exp"), 10, 64)
	if err != nil || expires < time.Now().Unix() {
		return signedParams{}, false
	}
	want := s.signature(method, query)
	got, err := hex.DecodeString(query.Get("sig"))
	if err != nil {
		return signedParams{}, false
	}
	wantBytes, _ := hex.DecodeString(want)
	if !hmac.Equal(got, wantBytes) {
		return signedParams{}, false
	}
	size, err := strconv.ParseInt(query.Get("size"), 10, 64)
	if err != nil {
		return signedParams{}, false
	}
	return signedParams{key: query.Get("key"), owner: query.Get("owner"), contentType: query.Get("ct"), size: size, public: query.Get("public") == "true"}, true
}

func (s *Service) signature(method string, query url.Values) string {
	message := strings.Join([]string{method, query.Get("key"), query.Get("owner"), query.Get("ct"), query.Get("size"), query.Get("exp"), query.Get("public")}, "\n")
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) paths(key string) (string, string) {
	digest := sha256.Sum256([]byte(key))
	base := hex.EncodeToString(digest[:])
	return filepath.Join(s.root, base+".blob"), filepath.Join(s.root, base+".json")
}

func (s *Service) readMetadata(key string) (metadata, error) {
	_, path := s.paths(key)
	data, err := os.ReadFile(path)
	if err != nil {
		return metadata{}, err
	}
	var meta metadata
	if json.Unmarshal(data, &meta) != nil || meta.Key != key {
		return metadata{}, errors.New("invalid metadata")
	}
	return meta, nil
}

func validUpload(size int64, ext, contentType string) bool {
	return size > 0 && size <= maxMediaBytes && sanitizeExt(ext) != "" && strings.TrimSpace(contentType) != ""
}

func sanitizeExt(value string) string {
	value = strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
	if len(value) == 0 || len(value) > 12 {
		return ""
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return ""
		}
	}
	return value
}

func extensionForContentType(contentType string) string {
	extensions, _ := mime.ExtensionsByType(contentType)
	if len(extensions) == 0 {
		return "bin"
	}
	if ext := sanitizeExt(extensions[0]); ext != "" {
		return ext
	}
	return "bin"
}
