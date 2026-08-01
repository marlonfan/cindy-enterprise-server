package devicelink

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/marlonfan/cindy-enterprise-server/internal/auth"
	"github.com/marlonfan/cindy-enterprise-server/internal/store"
	"github.com/marlonfan/cindy-enterprise-server/internal/web"
)

const (
	protocolVersion  = 1
	maxFrameBytes    = 2 * 1024 * 1024
	wsMaxPayload     = 4 * 1024 * 1024
	duplicateCode    = 4409
	versionCloseCode = 4400
)

type envelope struct {
	V       int             `json:"v"`
	Kind    string          `json:"kind"`
	ID      string          `json:"id,omitempty"`
	Src     string          `json:"src,omitempty"`
	Dst     string          `json:"dst,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type helloPayload struct {
	DeviceName           string            `json:"deviceName"`
	Platform             string            `json:"platform"`
	AppVersion           string            `json:"appVersion"`
	RemoteControlEnabled bool              `json:"remoteControlEnabled"`
	Busy                 bool              `json:"busy"`
	DeviceInfo           *store.DeviceInfo `json:"deviceInfo"`
}

type presenceSetPayload struct {
	RemoteControlEnabled *bool `json:"remoteControlEnabled"`
	Busy                 *bool `json:"busy"`
}

type peer struct {
	hub        *Hub
	ws         *websocket.Conn
	claims     auth.Claims
	send       chan []byte
	closed     chan struct{}
	closeOnce  sync.Once
	registered bool
}

type Hub struct {
	store    *store.Store
	logger   *slog.Logger
	upgrader websocket.Upgrader
	mu       sync.RWMutex
	users    map[string]map[string]*peer
}

func New(dataStore *store.Store, logger *slog.Logger) *Hub {
	return &Hub{
		store: dataStore, logger: logger, users: map[string]map[string]*peer{},
		upgrader: websocket.Upgrader{ReadBufferSize: 32 << 10, WriteBufferSize: 32 << 10, CheckOrigin: func(*http.Request) bool { return true }},
	}
}

func (h *Hub) Register(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("GET /api/device-link/ws", require(http.HandlerFunc(h.serveWS)))
	mux.Handle("GET /api/device-link/devices", require(http.HandlerFunc(h.listDevices)))
	mux.Handle("PATCH /api/device-link/devices/{deviceID}", require(http.HandlerFunc(h.renameDevice)))
	mux.Handle("DELETE /api/device-link/devices/{deviceID}", require(http.HandlerFunc(h.deleteDevice)))
	mux.Handle("PUT /api/device-link/push-token", require(http.HandlerFunc(h.putPushToken)))
	mux.Handle("DELETE /api/device-link/push-token", require(http.HandlerFunc(h.deletePushToken)))
}

func (h *Hub) serveWS(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	ws, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(wsMaxPayload)
	connection := &peer{hub: h, ws: ws, claims: claims, send: make(chan []byte, 256), closed: make(chan struct{})}
	go connection.writeLoop()
	connection.readLoop()
}

func (p *peer) readLoop() {
	defer p.close(1000, "closed")
	if err := p.handshake(); err != nil {
		p.hub.logger.Warn("device-link handshake failed", "device", p.claims.DeviceID, "error", err)
		return
	}
	for {
		messageType, raw, err := p.ws.ReadMessage()
		if err != nil {
			return
		}
		if messageType != websocket.TextMessage {
			continue
		}
		p.handle(raw)
	}
}

func (p *peer) handshake() error {
	_ = p.ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	messageType, raw, err := p.ws.ReadMessage()
	if err != nil {
		return err
	}
	if messageType != websocket.TextMessage || len(raw) > maxFrameBytes {
		return errors.New("invalid hello frame")
	}
	var frame envelope
	if json.Unmarshal(raw, &frame) != nil || frame.Kind != "hello" {
		return errors.New("hello must be first frame")
	}
	if frame.V != protocolVersion {
		p.sendError(frame.ID, "VERSION_MISMATCH", "protocol version mismatch", "")
		_ = p.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(versionCloseCode, "protocol mismatch"), time.Now().Add(time.Second))
		return errors.New("protocol version mismatch")
	}
	var hello helloPayload
	if json.Unmarshal(frame.Payload, &hello) != nil || strings.TrimSpace(hello.DeviceName) == "" || strings.TrimSpace(hello.Platform) == "" {
		return errors.New("invalid hello payload")
	}
	device := store.Device{
		DeviceID: p.claims.DeviceID, UserID: p.claims.Subject, Name: truncate(strings.TrimSpace(hello.DeviceName), 128),
		Platform: truncate(strings.TrimSpace(hello.Platform), 64), AppVersion: truncate(strings.TrimSpace(hello.AppVersion), 64),
		LastSeenAt: time.Now().UnixMilli(), RemoteControlEnabled: hello.RemoteControlEnabled, Busy: hello.Busy, Info: hello.DeviceInfo,
	}
	if err := p.hub.store.UpsertDevice(device); err != nil {
		return err
	}
	p.hub.registerPeer(p)
	ack, _ := json.Marshal(map[string]any{"serverProtocolVersion": protocolVersion, "deviceId": p.claims.DeviceID, "userId": p.claims.Subject, "capabilities": []string{}})
	p.sendEnvelope(envelope{V: protocolVersion, Kind: "hello-ack", Payload: ack})
	_ = p.ws.SetReadDeadline(time.Time{})
	p.hub.broadcastPresence(p.claims.Subject, device, true)
	return nil
}

func (p *peer) handle(raw []byte) {
	if len(raw) > maxFrameBytes {
		p.sendError("", "PAYLOAD_TOO_LARGE", "frame exceeds 2 MiB", "")
		return
	}
	var frame envelope
	if json.Unmarshal(raw, &frame) != nil || frame.Kind == "" {
		p.sendError("", "BAD_REQUEST", "invalid JSON envelope", "")
		return
	}
	if frame.V != protocolVersion {
		p.sendError(frame.ID, "VERSION_MISMATCH", "protocol version mismatch", frame.Dst)
		return
	}
	switch frame.Kind {
	case "ping":
		_ = p.hub.store.TouchDevice(p.claims.Subject, p.claims.DeviceID, time.Now())
		p.sendEnvelope(envelope{V: protocolVersion, Kind: "pong", ID: frame.ID})
	case "presence-set":
		p.updatePresence(frame)
	case "link-open", "link-accept", "link-close", "invoke", "invoke-result", "push":
		p.route(frame)
	case "notify":
		// This server does not advertise the optional notify capability until an APNs/FCM adapter is configured.
	default:
		// Protocol v1 requires unknown client kinds to be ignored for forward compatibility.
	}
}

func (p *peer) updatePresence(frame envelope) {
	var patch presenceSetPayload
	if json.Unmarshal(frame.Payload, &patch) != nil || (patch.RemoteControlEnabled == nil && patch.Busy == nil) {
		p.sendError(frame.ID, "BAD_REQUEST", "invalid presence-set payload", "")
		return
	}
	device, ok := p.hub.store.Device(p.claims.Subject, p.claims.DeviceID)
	if !ok {
		return
	}
	if patch.RemoteControlEnabled != nil {
		device.RemoteControlEnabled = *patch.RemoteControlEnabled
	}
	if patch.Busy != nil {
		device.Busy = *patch.Busy
	}
	device.LastSeenAt = time.Now().UnixMilli()
	if p.hub.store.UpsertDevice(device) == nil {
		p.hub.broadcastPresence(p.claims.Subject, device, true)
	}
}

func (p *peer) route(frame envelope) {
	if strings.TrimSpace(frame.Dst) == "" {
		p.sendError(frame.ID, "BAD_REQUEST", "dst is required", "")
		return
	}
	target := p.hub.onlinePeer(p.claims.Subject, frame.Dst)
	if target == nil {
		p.sendError(frame.ID, "DEVICE_OFFLINE", "target device is offline", frame.Dst)
		return
	}
	if frame.Kind == "link-open" || frame.Kind == "invoke" {
		device, ok := p.hub.store.Device(p.claims.Subject, frame.Dst)
		if !ok || !device.RemoteControlEnabled {
			p.sendError(frame.ID, "REMOTE_DISABLED", "target device disabled remote control", frame.Dst)
			return
		}
	}
	frame.Src = p.claims.DeviceID
	frame.Dst = target.claims.DeviceID
	target.sendEnvelope(frame)
}

func (p *peer) sendError(id, code, message, dst string) {
	payload, _ := json.Marshal(map[string]string{"code": code, "message": message, "dst": dst})
	p.sendEnvelope(envelope{V: protocolVersion, Kind: "relay-error", ID: id, Payload: payload})
}

func (p *peer) sendEnvelope(frame envelope) {
	raw, err := json.Marshal(frame)
	if err != nil {
		return
	}
	select {
	case p.send <- raw:
	case <-p.closed:
	default:
		p.close(1013, "backpressure")
	}
}

func (p *peer) writeLoop() {
	for {
		select {
		case raw := <-p.send:
			_ = p.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := p.ws.WriteMessage(websocket.TextMessage, raw); err != nil {
				p.close(1006, "write failed")
				return
			}
		case <-p.closed:
			return
		}
	}
}

func (p *peer) close(code int, reason string) {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.hub.unregisterPeer(p)
		_ = p.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
		_ = p.ws.Close()
	})
}

func (h *Hub) registerPeer(p *peer) {
	h.mu.Lock()
	devices := h.users[p.claims.Subject]
	if devices == nil {
		devices = map[string]*peer{}
		h.users[p.claims.Subject] = devices
	}
	previous := devices[p.claims.DeviceID]
	devices[p.claims.DeviceID] = p
	p.registered = true
	h.mu.Unlock()
	if previous != nil && previous != p {
		previous.close(duplicateCode, "duplicate device connection")
	}
}

func (h *Hub) unregisterPeer(p *peer) {
	if !p.registered {
		return
	}
	h.mu.Lock()
	devices := h.users[p.claims.Subject]
	removed := false
	if devices != nil && devices[p.claims.DeviceID] == p {
		delete(devices, p.claims.DeviceID)
		removed = true
		if len(devices) == 0 {
			delete(h.users, p.claims.Subject)
		}
	}
	h.mu.Unlock()
	p.registered = false
	if !removed {
		return
	}
	device, ok := h.store.Device(p.claims.Subject, p.claims.DeviceID)
	if ok {
		device.LastSeenAt = time.Now().UnixMilli()
		_ = h.store.UpsertDevice(device)
		h.broadcastPresence(p.claims.Subject, device, false)
	}
}

func (h *Hub) onlinePeer(userID, deviceID string) *peer {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.users[userID][deviceID]
}

func (h *Hub) isOnline(userID, deviceID string) bool { return h.onlinePeer(userID, deviceID) != nil }

func (h *Hub) peers(userID string) []*peer {
	h.mu.RLock()
	defer h.mu.RUnlock()
	result := make([]*peer, 0, len(h.users[userID]))
	for _, connection := range h.users[userID] {
		result = append(result, connection)
	}
	return result
}

func (h *Hub) broadcastPresence(userID string, device store.Device, online bool) {
	payload, _ := json.Marshal(h.presence(device, online))
	frame := envelope{V: protocolVersion, Kind: "presence-changed", Src: device.DeviceID, Payload: payload}
	for _, connection := range h.peers(userID) {
		connection.sendEnvelope(frame)
	}
}

func (h *Hub) presence(device store.Device, online bool) map[string]any {
	return map[string]any{
		"deviceId": device.DeviceID, "online": online, "deviceName": device.Name, "selfName": device.ManualName,
		"deviceInfo": device.Info, "platform": device.Platform, "appVersion": device.AppVersion,
		"lastSeenAt": device.LastSeenAt, "remoteControlEnabled": device.RemoteControlEnabled, "busy": device.Busy,
	}
}

func (h *Hub) listDevices(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	devices := h.store.Devices(claims.Subject)
	sort.Slice(devices, func(i, j int) bool { return devices[i].LastSeenAt > devices[j].LastSeenAt })
	views := make([]map[string]any, 0, len(devices))
	for _, device := range devices {
		name := device.Name
		if device.ManualName != nil && strings.TrimSpace(*device.ManualName) != "" {
			name = *device.ManualName
		}
		views = append(views, map[string]any{
			"deviceId": device.DeviceID, "name": name, "selfName": device.ManualName, "deviceInfo": device.Info,
			"platform": device.Platform, "appVersion": device.AppVersion, "lastSeenAt": time.UnixMilli(device.LastSeenAt).UTC().Format(time.RFC3339Nano),
			"online": h.isOnline(claims.Subject, device.DeviceID), "busy": device.Busy,
			"remoteControlEnabled": device.RemoteControlEnabled, "isSelf": device.DeviceID == claims.DeviceID,
		})
	}
	web.JSON(w, http.StatusOK, map[string]any{"devices": views})
}

func (h *Hub) renameDevice(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	var body struct {
		Name *string `json:"name"`
	}
	if web.DecodeJSON(r, &body, 8<<10) != nil {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid name")
		return
	}
	if body.Name != nil {
		trimmed := truncate(strings.TrimSpace(*body.Name), 128)
		if trimmed == "" {
			web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name cannot be empty")
			return
		}
		body.Name = &trimmed
	}
	device, ok, err := h.store.RenameDevice(claims.Subject, r.PathValue("deviceID"), body.Name)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to rename device")
		return
	}
	if !ok {
		web.Error(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "device not found")
		return
	}
	name := device.Name
	if device.ManualName != nil {
		name = *device.ManualName
	}
	web.JSON(w, http.StatusOK, map[string]any{"deviceId": device.DeviceID, "name": name, "manualName": device.ManualName})
}

func (h *Hub) deleteDevice(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	deviceID := r.PathValue("deviceID")
	if target := h.onlinePeer(claims.Subject, deviceID); target != nil {
		target.close(4001, "device removed")
	}
	deleted, err := h.store.DeleteDevice(claims.Subject, deviceID)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete device")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"deviceId": deviceID, "deleted": deleted})
}

func (h *Hub) putPushToken(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	var body struct {
		Token      string `json:"token"`
		Platform   string `json:"platform"`
		Provider   string `json:"provider"`
		AppVariant string `json:"appVariant"`
		APNSEnv    string `json:"apnsEnv"`
	}
	if web.DecodeJSON(r, &body, 16<<10) != nil || len(strings.TrimSpace(body.Token)) == 0 || len(body.Token) > 512 {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid push token")
		return
	}
	if err := h.store.PutPushToken(store.PushToken{Token: body.Token, UserID: claims.Subject, DeviceID: claims.DeviceID, Provider: body.Provider, Platform: body.Platform, AppVariant: body.AppVariant, APNSEnv: body.APNSEnv}); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to store push token")
		return
	}
	web.JSON(w, http.StatusOK, map[string]bool{"registered": true})
}

func (h *Hub) deletePushToken(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	var body struct {
		Token string `json:"token"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		_ = web.DecodeJSON(r, &body, 16<<10)
	}
	if err := h.store.DeletePushToken(claims.Subject, claims.DeviceID, body.Token); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to delete push token")
		return
	}
	web.JSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
