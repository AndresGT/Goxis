package goxis

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	goxislog "github.com/AndresGT/Goxis/log"
	goxiscrypto "github.com/AndresGT/Goxis/security/crypto"
	"github.com/AndresGT/Goxis/security/token"
)

func testAdminPanelConfig(t *testing.T) AdminPanelConfig {
	t.Helper()
	hash, err := goxiscrypto.HashPassword("admin")
	if err != nil {
		t.Fatal(err)
	}
	manager, err := token.NewJWTManager(token.JWTConfig{SecretKey: []byte("test-secret-with-at-least-32-bytes-long"), AccessTokenDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return AdminPanelConfig{AdminUsername: "admin", AdminPasswordHash: hash, TokenManager: manager, LogFilePath: t.TempDir() + "/admin.log"}
}

func adminPanelCookie(t *testing.T, app *App) *http.Cookie {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, defaultAdminPanelPath+"/login", strings.NewReader(`{"username":"admin","password":"admin"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("admin login status=%d body=%s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a session cookie")
	}
	return cookies[0]
}

func TestAdminPanelRunsOnAppAndProtectsData(t *testing.T) {
	config := testAdminPanelConfig(t)
	config.MaxLogEntries = 20
	app := New(WithAdminPanel(config))
	defer app.Close()
	if err := app.Group("/api").RegisterRoutes([]Route{{Method: GET, Path: "/items", Handler: func(ctx *Context) error { return ctx.Text(http.StatusOK, "ok") }, RateLimit: 7}}); err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	app.ServeHTTP(page, httptest.NewRequest(http.MethodGet, defaultAdminPanelPath, nil))
	if page.Code != http.StatusOK || page.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("dashboard response: %d %q", page.Code, page.Header().Get("Content-Type"))
	}

	cookie := adminPanelCookie(t, app)
	for _, test := range []struct {
		auth bool
		want int
	}{{false, http.StatusUnauthorized}, {true, http.StatusOK}} {
		request := httptest.NewRequest(http.MethodGet, defaultAdminPanelPath+"/api/routes", nil)
		if test.auth {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Errorf("authenticated=%v status=%d want=%d", test.auth, response.Code, test.want)
		}
		if test.want == http.StatusOK {
			var payload struct {
				Routes []adminRoute `json:"routes"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if len(payload.Routes) != 1 || payload.Routes[0].Path != "/api/items" || payload.Routes[0].RateLimit != 7 {
				t.Fatalf("unexpected routes: %+v", payload.Routes)
			}
		}
	}

	adminLogs := httptest.NewRequest(http.MethodGet, defaultAdminPanelPath+"/api/logs", nil)
	adminLogs.AddCookie(cookie)
	logsResponse := httptest.NewRecorder()
	app.ServeHTTP(logsResponse, adminLogs)
	if logsResponse.Code != http.StatusOK {
		t.Fatalf("logs status=%d", logsResponse.Code)
	}
	var logs struct {
		Logs []string `json:"logs"`
	}
	if err := json.Unmarshal(logsResponse.Body.Bytes(), &logs); err != nil {
		t.Fatal(err)
	}
	if len(logs.Logs) == 0 {
		t.Fatal("expected route and request logs to be retained")
	}
}

func TestAdminPanelWithoutSessionRejectsData(t *testing.T) {
	app := New(WithAdminPanel(testAdminPanelConfig(t)))
	defer app.Close()
	req := httptest.NewRequest(http.MethodGet, defaultAdminPanelPath+"/api/logs", nil)
	res := httptest.NewRecorder()
	app.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want=%d", res.Code, http.StatusUnauthorized)
	}
}

func TestAdminPanelRestoresPersistentLogsAfterRestart(t *testing.T) {
	config := testAdminPanelConfig(t)
	logPath := config.LogFilePath
	first := New(WithAdminPanel(config))
	goxislog.Info("persistent admin panel log marker")
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	config.LogFilePath = logPath
	second := New(WithAdminPanel(config))
	defer second.Close()
	request := httptest.NewRequest(http.MethodGet, defaultAdminPanelPath+"/api/logs", nil)
	request.AddCookie(adminPanelCookie(t, second))
	response := httptest.NewRecorder()
	second.ServeHTTP(response, request)
	var payload struct {
		Logs []string `json:"logs"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || !strings.Contains(strings.Join(payload.Logs, "\n"), "persistent admin panel log marker") {
		t.Fatalf("persisted log was not restored, status=%d logs=%q", response.Code, payload.Logs)
	}
}

func TestAdminPanelMetricsSummarizeRequests(t *testing.T) {
	config := testAdminPanelConfig(t)
	config.MaxMetricSamples = 32
	app := New(WithAdminPanel(config))
	defer app.Close()
	if err := app.Group("/api").RegisterRoutes([]Route{{Method: GET, Path: "/items/:id", Handler: func(ctx *Context) error { return ctx.Text(http.StatusOK, "ok") }}}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/api/items/one", "/api/items/two", "/missing"} {
		response := httptest.NewRecorder()
		app.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	}
	request := httptest.NewRequest(http.MethodGet, defaultAdminPanelPath+"/api/metrics", nil)
	request.AddCookie(adminPanelCookie(t, app))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	var metrics metricsSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &metrics); err != nil {
		t.Fatal(err)
	}
	if metrics.TotalRequests != 3 || metrics.StatusCounts["2xx"] != 2 || metrics.StatusCounts["4xx"] != 1 {
		t.Fatalf("unexpected totals: %+v", metrics)
	}
	if metrics.RequestsLastMinute < 3 || len(metrics.Timeline) != 12 || len(metrics.TopRoutes) == 0 {
		t.Fatalf("missing recent metrics: %+v", metrics)
	}
	if metrics.TopRoutes[0].Route != "GET /api/items/:id" || metrics.TopRoutes[0].Count != 2 {
		t.Fatalf("route label should use registered pattern: %+v", metrics.TopRoutes)
	}
	if len(metrics.Methods) != 1 || metrics.Methods[0].Method != GET || metrics.Methods[0].Requests != 3 {
		t.Fatalf("unexpected method metrics: %+v", metrics.Methods)
	}
}

func TestMethodRecommendationsUseMethodSpecificReview(t *testing.T) {
	post := methodRecommendations(methodMetric{Method: POST, Requests: 8, ServerErrors: 2, AverageMS: 1250, P95MS: 1800})
	if len(post) != 2 {
		t.Fatalf("recommendations=%+v", post)
	}
	if post[0].Priority != "alta" || !strings.Contains(post[0].Review, "transacciones") {
		t.Fatalf("POST error advice not specific: %+v", post[0])
	}
	if !strings.Contains(post[1].Review, "llamadas externas") {
		t.Fatalf("POST latency advice not specific: %+v", post[1])
	}

	get := methodRecommendations(methodMetric{Method: GET, Requests: 7, AverageMS: 1400, P95MS: 2000})
	if len(get) != 1 || !strings.Contains(get[0].Review, "índices") {
		t.Fatalf("GET advice not specific: %+v", get)
	}
}

func TestAdminPanelPathCannotBeShadowedByRoutes(t *testing.T) {
	app := New(WithAdminPanel(testAdminPanelConfig(t)))
	defer app.Close()
	err := app.Group("").RegisterRoutes([]Route{{Method: GET, Path: "/_goxis/:section", Handler: func(*Context) error { return nil }}})
	if err == nil {
		t.Fatal("expected route overlapping dashboard path to be rejected")
	}
}

func TestAdminPanelSSEStreamsRequestUpdates(t *testing.T) {
	config := testAdminPanelConfig(t)
	config.MaxLogEntries = 32
	app := New(WithAdminPanel(config))
	defer app.Close()
	if err := app.Group("/api").RegisterRoutes([]Route{{Method: GET, Path: "/items", Handler: func(ctx *Context) error { return ctx.Text(http.StatusOK, "ok") }}}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+defaultAdminPanelPath+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(adminPanelCookie(t, app))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("status=%d content_type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	reader := bufio.NewReader(response.Body)
	for _, expected := range []string{"metrics", "routes", "logs"} {
		event := readAdminSSEEvent(t, reader)
		if !strings.Contains(event, "event: "+expected) {
			t.Fatalf("initial event %q, expected %q", event, expected)
		}
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/items", nil)
	clientResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, clientResponse.Body)
	_ = clientResponse.Body.Close()
	for {
		event := readAdminSSEEvent(t, reader)
		if strings.Contains(event, "event: metrics") && strings.Contains(event, `"total_requests":1`) {
			break
		}
	}
}

func readAdminSSEEvent(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	var event strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE event: %v", err)
		}
		if line == "\n" || line == "\r\n" {
			return event.String()
		}
		_, _ = fmt.Fprint(&event, line)
	}
}
