package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestPasswordHashingAndVerify(t *testing.T) {
	h, err := hashPassword("Sup3rSecret!")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(h, "pbkdf2$100000$") {
		t.Fatalf("unexpected hash format: %s", h)
	}
	if !verifyPassword("Sup3rSecret!", h) {
		t.Fatal("expected valid password to verify")
	}
	if verifyPassword("WrongPassword", h) {
		t.Fatal("expected wrong password to fail")
	}
}

func TestSessionSignAndVerify(t *testing.T) {
	app := &App{cfg: Config{SessionSecret: "0123456789abcdef0123456789abcdef"}}
	tok := app.signSession("9m2pju", time.Now().Add(time.Hour).Unix())
	u, ok := app.verifySession(tok)
	if !ok || u != "9m2pju" {
		t.Fatalf("expected valid session for 9m2pju, got ok=%v user=%q", ok, u)
	}
	if _, ok := app.verifySession(tok + "x"); ok {
		t.Fatal("expected tampered token to fail")
	}
	expired := app.signSession("9m2pju", time.Now().Add(-time.Minute).Unix())
	if _, ok := app.verifySession(expired); ok {
		t.Fatal("expected expired token to fail")
	}
}

func TestMapSiteFromDatasource(t *testing.T) {
	siteMap := map[string]string{
		"/blog_":     "blog.example.com",
		"/blog_api_": "api.blog.example.com",
	}
	keys := make([]string, 0, len(siteMap))
	for k := range siteMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })

	app := &App{cfg: Config{SiteMap: siteMap}, siteKeys: keys}

	if got := app.mapSiteFromDatasource("/var/log/nginx/blog_api_access.log", "", "http"); got != "api.blog.example.com" {
		t.Fatalf("longest key match failed, got %q", got)
	}
	if got := app.mapSiteFromDatasource("/var/log/nginx/other_access.log", "fqdn.example.org", "http"); got != "fqdn.example.org" {
		t.Fatalf("targetFQDN precedence failed, got %q", got)
	}
	if got := app.mapSiteFromDatasource("/var/log/maillog", "", "syslog"); got != "mail (postfix/dovecot)" {
		t.Fatalf("maillog mapping failed, got %q", got)
	}
	if got := app.mapSiteFromDatasource("/var/log/auth.log", "", "syslog"); got != "ssh (sshd)" {
		t.Fatalf("auth.log mapping failed, got %q", got)
	}
}

func setupTestApp(t *testing.T) *App {
	t.Helper()
	td := t.TempDir()
	dbPath := filepath.Join(td, "crowdsec.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open test sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`
		CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, scenario TEXT NOT NULL, events_count INTEGER DEFAULT 0, source_ip TEXT, source_range TEXT, source_as_number TEXT, source_as_name TEXT, source_country TEXT);
		CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, until TEXT, scenario TEXT NOT NULL, type TEXT NOT NULL, scope TEXT NOT NULL, value TEXT NOT NULL, origin TEXT NOT NULL, alert_decisions INTEGER);
		CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, time TEXT NOT NULL, serialized TEXT NOT NULL, alert_events INTEGER);
		CREATE TABLE bouncers (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, name TEXT NOT NULL, api_key TEXT NOT NULL, revoked INTEGER NOT NULL);
	`)
	if err != nil {
		t.Fatalf("create tables: %v", err)
	}

	nowStr := time.Now().UTC().Format("2006-01-02 15:04:05 +0000 UTC")
	untilStr := time.Now().UTC().Add(2 * time.Hour).Format("2006-01-02 15:04:05 +0000 UTC")
	_, _ = db.Exec(`INSERT INTO alerts (id, created_at, updated_at, scenario, events_count, source_ip, source_as_number, source_as_name, source_country) VALUES (1, ?, ?, 'crowdsecurity/http-probing', 4, '198.51.100.10', '64512', 'ExampleNet', 'MY')`, nowStr, nowStr)
	_, _ = db.Exec(`INSERT INTO decisions (created_at, updated_at, until, scenario, type, scope, value, origin, alert_decisions) VALUES (?, ?, ?, 'crowdsecurity/http-probing', 'ban', 'Ip', '198.51.100.10', 'crowdsec', 1)`, nowStr, nowStr, untilStr)
	_, _ = db.Exec(`INSERT INTO events (created_at, updated_at, time, serialized, alert_events) VALUES (?, ?, ?, '[{"key":"site","value":"blog.example.com"},{"key":"http_path","value":"/.env"},{"key":"http_verb","value":"GET"},{"key":"http_status","value":"404"},{"key":"datasource_path","value":"/var/log/nginx/blog_access.log"}]', 1)`, nowStr, nowStr, nowStr)

	adminHash, _ := hashPassword("AdminPass123!")
	viewerHash, _ := hashPassword("ViewerPass123!")
	cfg := Config{
		ListenAddr:    "127.0.0.1:0",
		DBPath:        dbPath,
		MetricsURL:    "http://127.0.0.1:1/unused",
		SessionSecret: "abcdef0123456789abcdef0123456789",
		SessionTTLMin: 60,
		Timezone:      "UTC",
		Users: []User{
			{Username: "admin", PasswordHash: adminHash, Role: "admin", CreatedAt: "2026-01-01 00:00:00"},
			{Username: "viewer", PasswordHash: viewerHash, Role: "viewer", CreatedAt: "2026-01-01 00:00:00"},
		},
	}

	loginT := template.Must(template.ParseFS(webFS, "web/login.html"))
	indexT := template.Must(template.ParseFS(webFS, "web/index.html"))
	app := &App{
		cfgPath:  filepath.Join(td, "config.json"),
		cfg:      cfg,
		loc:      time.UTC,
		hostname: "test-host",
		db:       db,
		limiter:  NewRateLimiter(),
		loginT:   loginT,
		indexT:   indexT,
	}
	return app
}

func loginCookie(t *testing.T, h http.Handler, user, pass string) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {user}, "password": {pass}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("login failed for %s: status=%d", user, rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == "cs_ui_session" {
			return c
		}
	}
	t.Fatal("missing session cookie")
	return nil
}

func TestEndToEndAuthRBACExportAndDetail(t *testing.T) {
	app := setupTestApp(t)
	h := app.handler()

	// Unauth favicon returns 200
	reqFav := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	rrFav := httptest.NewRecorder()
	h.ServeHTTP(rrFav, reqFav)
	if rrFav.Code != http.StatusOK {
		t.Fatalf("expected /favicon.ico 200, got %d", rrFav.Code)
	}

	// Unauth API returns 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	rrUnauth := httptest.NewRecorder()
	h.ServeHTTP(rrUnauth, reqUnauth)
	if rrUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rrUnauth.Code)
	}

	adminCookie := loginCookie(t, h, "admin", "AdminPass123!")
	viewerCookie := loginCookie(t, h, "viewer", "ViewerPass123!")

	// Viewer allowed on overview, forbidden on /api/users
	reqOv := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	reqOv.AddCookie(viewerCookie)
	rrOv := httptest.NewRecorder()
	h.ServeHTTP(rrOv, reqOv)
	if rrOv.Code != http.StatusOK {
		t.Fatalf("expected viewer overview 200, got %d", rrOv.Code)
	}
	var ov OverviewResponse
	if err := json.Unmarshal(rrOv.Body.Bytes(), &ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if ov.TotalAlerts != 1 || ov.ActiveBouncers != 0 || ov.TopSite24h != "blog.example.com" {
		t.Fatalf("unexpected overview payload: %+v", ov)
	}

	reqUsersV := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	reqUsersV.AddCookie(viewerCookie)
	rrUsersV := httptest.NewRecorder()
	h.ServeHTTP(rrUsersV, reqUsersV)
	if rrUsersV.Code != http.StatusForbidden {
		t.Fatalf("expected viewer /api/users 403, got %d", rrUsersV.Code)
	}

	// Country filter + CSV export
	reqExp := httptest.NewRequest(http.MethodGet, "/api/alerts/export?country=MY&format=csv", nil)
	reqExp.AddCookie(adminCookie)
	rrExp := httptest.NewRecorder()
	h.ServeHTTP(rrExp, reqExp)
	if rrExp.Code != http.StatusOK || !strings.Contains(rrExp.Body.String(), "198.51.100.10") {
		t.Fatalf("unexpected export response: code=%d body=%s", rrExp.Code, rrExp.Body.String())
	}

	// Cross-origin POST blocked
	reqCSRF := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBufferString(`{"username":"evil","password":"Password123","role":"admin"}`))
	reqCSRF.Host = "sec.example.com"
	reqCSRF.Header.Set("Origin", "https://evil.example.net")
	reqCSRF.AddCookie(adminCookie)
	rrCSRF := httptest.NewRecorder()
	h.ServeHTTP(rrCSRF, reqCSRF)
	if rrCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin POST 403, got %d", rrCSRF.Code)
	}

	// Detail endpoint
	reqDet := httptest.NewRequest(http.MethodGet, "/api/alert/1", nil)
	reqDet.AddCookie(adminCookie)
	rrDet := httptest.NewRecorder()
	h.ServeHTTP(rrDet, reqDet)
	if rrDet.Code != http.StatusOK || !strings.Contains(rrDet.Body.String(), "/.env") {
		t.Fatalf("unexpected detail response: code=%d", rrDet.Code)
	}
}
