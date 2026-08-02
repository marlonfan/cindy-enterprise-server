package devicelink

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/marlonfan/cindy-enterprise-server/internal/auth"
	"github.com/marlonfan/cindy-enterprise-server/internal/config"
	"github.com/marlonfan/cindy-enterprise-server/internal/store"
)

func TestRelayRoutesOnlyWithinAccountAndHonorsRemoteToggle(t *testing.T) {
	dataStore, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	authService, err := auth.New(context.Background(), config.Config{
		Region: "global", JWTIssuer: "test", JWTSecret: "01234567890123456789012345678901",
		AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour, OIDCOrgID: "test", OIDCOrgName: "Test",
	}, dataStore, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := authService.Signer()
	hub := New(dataStore, logger)
	mux := http.NewServeMux()
	hub.Register(mux, authService.Require)
	server := httptest.NewServer(mux)
	defer server.Close()

	controller := dialPeer(t, server.URL, signer, "user-1", "controller", false)
	defer controller.Close()
	target := dialPeer(t, server.URL, signer, "user-1", "target", true)
	defer target.Close()
	readPresence(t, controller, "target", true)

	writeEnvelope(t, controller, envelope{V: 1, Kind: "link-open", ID: "req-1", Dst: "target", Payload: json.RawMessage(`{"controllerName":"phone","protocolVersion":1,"appVersion":"1"}`)})
	routed := readKind(t, target, "link-open")
	if routed.Src != "controller" || routed.Dst != "target" {
		t.Fatalf("bad routed envelope: %+v", routed)
	}

	writeEnvelope(t, target, envelope{V: 1, Kind: "presence-set", Payload: json.RawMessage(`{"remoteControlEnabled":false}`)})
	readPresence(t, controller, "target", false)
	writeEnvelope(t, controller, envelope{V: 1, Kind: "invoke", ID: "req-2", Dst: "target", Payload: json.RawMessage(`{"channel":"local-db:sessions:list","args":[]}`)})
	rejected := readKind(t, controller, "relay-error")
	var relayError map[string]string
	if json.Unmarshal(rejected.Payload, &relayError) != nil || relayError["code"] != "REMOTE_DISABLED" {
		t.Fatalf("unexpected relay error: %s", rejected.Payload)
	}
}

func dialPeer(t *testing.T, serverURL string, signer *auth.TokenSigner, userID, deviceID string, remoteEnabled bool) *websocket.Conn {
	t.Helper()
	token, err := signer.Issue(userID, "membership-1", deviceID, "user@example.test")
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{"Authorization": []string{"Bearer " + token}}
	wsURL := "ws" + strings.TrimPrefix(serverURL, "http") + "/api/device-link/ws"
	connection, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatal(err)
	}
	writeEnvelope(t, connection, envelope{V: 1, Kind: "hello", Payload: mustJSON(map[string]any{"deviceName": deviceID, "platform": "test", "appVersion": "1", "remoteControlEnabled": remoteEnabled, "busy": false})})
	readKind(t, connection, "hello-ack")
	return connection
}

func writeEnvelope(t *testing.T, connection *websocket.Conn, frame envelope) {
	t.Helper()
	if err := connection.WriteJSON(frame); err != nil {
		t.Fatal(err)
	}
}

func readKind(t *testing.T, connection *websocket.Conn, kind string) envelope {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 12; i++ {
		var frame envelope
		if err := connection.ReadJSON(&frame); err != nil {
			t.Fatal(err)
		}
		if frame.Kind == kind {
			return frame
		}
	}
	t.Fatalf("did not receive kind %s", kind)
	return envelope{}
}

func readPresence(t *testing.T, connection *websocket.Conn, deviceID string, remoteEnabled bool) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 12; i++ {
		var frame envelope
		if err := connection.ReadJSON(&frame); err != nil {
			t.Fatal(err)
		}
		if frame.Kind != "presence-changed" {
			continue
		}
		var snapshot struct {
			DeviceID             string `json:"deviceId"`
			RemoteControlEnabled bool   `json:"remoteControlEnabled"`
		}
		if json.Unmarshal(frame.Payload, &snapshot) == nil && snapshot.DeviceID == deviceID && snapshot.RemoteControlEnabled == remoteEnabled {
			return
		}
	}
	t.Fatalf("did not receive presence device=%s remoteControlEnabled=%v", deviceID, remoteEnabled)
}

func mustJSON(value any) json.RawMessage { raw, _ := json.Marshal(value); return raw }
