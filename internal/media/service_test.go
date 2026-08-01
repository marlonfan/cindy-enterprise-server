package media

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marlonfan/cindy-enterprise-server/internal/config"
)

func TestSignedPutAndGet(t *testing.T) {
	t.Parallel()
	cfg := config.Config{PublicBaseURL: "http://placeholder", DataDir: t.TempDir(), MediaSigningSecret: "01234567890123456789012345678901", MediaURLTTL: time.Minute}
	service, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/device-link/media/object", service.putObject)
	mux.HandleFunc("GET /api/device-link/media/object", service.getObject)
	server := httptest.NewServer(mux)
	defer server.Close()
	service.baseURL = server.URL

	content := []byte("private device-link attachment")
	key := "users/user-1/object.txt"
	putURL, _ := service.signedURL("/api/device-link/media/object", http.MethodPut, key, "user-1", "text/plain", int64(len(content)), false)
	request, _ := http.NewRequest(http.MethodPut, putURL, bytes.NewReader(content))
	request.Header.Set("Content-Type", "text/plain")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("put status=%d", response.StatusCode)
	}
	_ = response.Body.Close()

	getURL, _ := service.signedURL("/api/device-link/media/object", http.MethodGet, key, "user-1", "text/plain", int64(len(content)), false)
	response, err = http.Get(getURL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got, _ := io.ReadAll(response.Body)
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: %q", got)
	}
	if response.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("content type=%q", response.Header.Get("Content-Type"))
	}
}

func TestSignedURLRejectsTampering(t *testing.T) {
	t.Parallel()
	service, err := New(config.Config{PublicBaseURL: "http://example.test", DataDir: t.TempDir(), MediaSigningSecret: "01234567890123456789012345678901", MediaURLTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := service.signedURL("/api/device-link/media/object", http.MethodPut, "users/u/a.bin", "u", "application/octet-stream", 10, false)
	request := httptest.NewRequest(http.MethodPut, raw+"&size=11", nil)
	if _, ok := service.verifySignedRequest(request, http.MethodPut); ok {
		t.Fatal("tampered URL passed verification")
	}
}
