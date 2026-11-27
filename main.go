package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	_ "modernc.org/sqlite"
)

//go:embed web/*
var webFS embed.FS

type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"` // "admin" or "viewer"
	CreatedAt    string `json:"created_at"`
}

type PublicUser struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

type Config struct {
	ListenAddr    string            `json:"listen_addr"`
	DBPath        string            `json:"db_path"`
	MetricsURL    string            `json:"metrics_url"`
	Username      string            `json:"username,omitempty"`
	PasswordHash  string            `json:"password_hash,omitempty"` // format: pbkdf2$iterations$saltHex$hashHex
	Users         []User            `json:"users"`
	SessionSecret string            `json:"session_secret"`
	SessionTTLMin int               `json:"session_ttl_min"`
	Timezone      string            `json:"timezone"`
	SiteMap       map[string]string `json:"site_map,omitempty"`
}

type EventKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type EventDetail struct {
	Time           string `json:"time"`
	Site           string `json:"site"`
	TargetURI      string `json:"target_uri"`
	Method         string `json:"method"`
	Status         string `json:"status"`
	UserAgent      string `json:"user_agent"`
	DatasourcePath string `json:"datasource_path"`
	Service        string `json:"service"`
	TargetUser     string `json:"target_user"`
}

type DecisionItem struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	Origin    string `json:"origin"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Scenario  string `json:"scenario"`
	CreatedAt string `json:"created_at"`
	Until     string `json:"until"`
	Remaining string `json:"remaining"`
	Active    bool   `json:"active"`
}

type AlertItem struct {
	ID            int64         `json:"id"`
	CreatedAt     string        `json:"created_at"`
	CreatedTS     int64         `json:"created_ts"`
	Age           string        `json:"age"`
	Scenario      string        `json:"scenario"`
	EventsCount   int64         `json:"events_count"`
	SourceIP      string        `json:"source_ip"`
	SourceRange   string        `json:"source_range"`
	ASNNumber     string        `json:"source_as_number"`
	ASNName       string        `json:"source_as_name"`
	Country       string        `json:"source_country"`
	Sites         []string      `json:"sites"`
	TargetURIs    []string      `json:"target_uris"`
	Methods       []string      `json:"methods"`
	Statuses      []string      `json:"statuses"`
	UserAgents    []string      `json:"user_agents"`
	Datasources   []string      `json:"datasources"`
	ActiveBan     bool          `json:"active_ban"`
	BanRemaining  string        `json:"ban_remaining"`
	BanCount      int           `json:"ban_count"`
	Events        []EventDetail `json:"events,omitempty"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type HourBucket struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

type MetricsSummary struct {
	Available       bool                 `json:"available"`
	CAPIBans        int64                `json:"capi_bans"`
	LocalBansMetric int64                `json:"local_bans_metric"`
	CAPIBreakdown   []NameCount          `json:"capi_breakdown"`
	Sources         []SourceMetricItem   `json:"sources"`
	DBSizeBytes     int64                `json:"db_size_bytes"`
	Error           string               `json:"error,omitempty"`
}

type SourceMetricItem struct {
	Source   string `json:"source"`
	Site     string `json:"site"`
	Read     int64  `json:"read"`
	Parsed   int64  `json:"parsed"`
	Unparsed int64  `json:"unparsed"`
}

type OverviewResponse struct {
	GeneratedAt     string           `json:"generated_at"`
	Hostname        string           `json:"hostname"`
	TotalAlerts     int64            `json:"total_alerts"`
	Alerts24h       int64            `json:"alerts_24h"`
	UniqueIPs24h    int64            `json:"unique_ips_24h"`
	ActiveLocalBans int64            `json:"active_local_bans"`
	ActiveBouncers  int64            `json:"active_bouncers"`
	CAPIBans        int64            `json:"capi_bans"`
	TopSite24h      string           `json:"top_site_24h"`
	TopSites        []NameCount      `json:"top_sites"`
	TopScenarios    []NameCount      `json:"top_scenarios"`
	TopCountries    []NameCount      `json:"top_countries"`
	TopIPs          []NameCount      `json:"top_ips"`
	Hourly24h       []HourBucket     `json:"hourly_24h"`
	FilterSites     []string         `json:"filter_sites"`
	FilterScenarios []string         `json:"filter_scenarios"`
	Metrics         MetricsSummary   `json:"metrics"`
}

type AlertsResponse struct {
	Total    int         `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
	Items    []AlertItem `json:"items"`
}

type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{attempts: make(map[string][]time.Time)}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-5 * time.Minute)
	var recent []time.Time
	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 12 {
		rl.attempts[ip] = recent
		return false
	}
	rl.attempts[ip] = recent
	return true
}

func (rl *RateLimiter) RecordFail(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
}

func (rl *RateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(key, data []byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write(data)
		return h.Sum(nil)
	}
	numBlocks := (keyLen + 31) / 32
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		u := make([]byte, len(salt)+4)
		copy(u, salt)
		u[len(salt)] = byte(block >> 24)
		u[len(salt)+1] = byte(block >> 16)
		u[len(salt)+2] = byte(block >> 8)
		u[len(salt)+3] = byte(block)
		u = prf(password, u)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 2; i <= iter; i++ {
			u = prf(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	iter := 100000
	dk := pbkdf2SHA256([]byte(password), salt, iter, 32)
	return fmt.Sprintf("pbkdf2$%d$%s$%s", iter, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

func verifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 10000 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), salt, iter, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

type App struct {
	cfgMu    sync.RWMutex
	cfgPath  string
	cfg      Config
	siteKeys []string
	loc      *time.Location
	hostname string
	db       *sql.DB
	limiter  *RateLimiter
	loginT   *template.Template
	indexT   *template.Template
}

func parseCrowdSecTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	layouts := []string{
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 48*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m > 0 {
			return fmt.Sprintf("%dh%dm", h, m)
		}
		return fmt.Sprintf("%dh", h)
	}
	days := int(d.Hours()) / 24
	hrs := int(d.Hours()) % 24
	return fmt.Sprintf("%dd%dh", days, hrs)
}

func (a *App) mapSiteFromDatasource(ds, targetFQDN, service string) string {
	if targetFQDN != "" {
		return targetFQDN
	}
	for _, k := range a.siteKeys {
		if k != "" && strings.Contains(ds, k) {
			return a.cfg.SiteMap[k]
		}
	}
	switch {
	case strings.HasPrefix(ds, "/var/log/nginx/"):
		return strings.TrimPrefix(ds, "/var/log/nginx/")
	case strings.HasPrefix(ds, "/var/log/apache2/"):
		return strings.TrimPrefix(ds, "/var/log/apache2/")
	case strings.HasPrefix(ds, "/var/log/httpd/"):
		return strings.TrimPrefix(ds, "/var/log/httpd/")
	case ds == "/var/log/maillog" || ds == "/var/log/mail.log":
		return "mail (postfix/dovecot)"
	case ds == "/var/log/auth.log" || ds == "/var/log/secure":
		return "ssh (sshd)"
	case service != "":
		return service
	case ds != "":
		return ds
	default:
		return "unknown"
	}
}

func (a *App) parseEventSerialized(raw string) EventDetail {
	var kvs []EventKV
	_ = json.Unmarshal([]byte(raw), &kvs)
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	site := m["site"]
	if site == "" {
		site = a.mapSiteFromDatasource(m["datasource_path"], m["target_fqdn"], m["service"])
	}
	return EventDetail{
		Time:           m["timestamp"],
		Site:           site,
		TargetURI:      m["http_path"],
		Method:         m["http_verb"],
		Status:         m["http_status"],
		UserAgent:      m["http_user_agent"],
		DatasourcePath: m["datasource_path"],
		Service:        m["service"],
		TargetUser:     m["target_user"],
	}
}

func appendUnique(slice []string, val string) []string {
	if val == "" {
		return slice
	}
	for _, existing := range slice {
		if existing == val {
			return slice
		}
	}
	return append(slice, val)
}

func (a *App) fetchPrometheusMetrics() MetricsSummary {
	res := MetricsSummary{}
	if st, err := os.Stat(a.cfg.DBPath); err == nil {
		res.DBSizeBytes = st.Size()
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(a.cfg.MetricsURL)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return res
	}
	res.Available = true

	capiReasons := make(map[string]int64)
	sourcesMap := make(map[string]*SourceMetricItem)

	getSrc := func(src string) *SourceMetricItem {
		clean := strings.TrimPrefix(src, "file:")
		if item, ok := sourcesMap[clean]; ok {
			return item
		}
		item := &SourceMetricItem{
			Source: clean,
			Site:   a.mapSiteFromDatasource(clean, "", ""),
		}
		sourcesMap[clean] = item
		return item
	}

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		metricName, labels, val, ok := parsePromLine(line)
		if !ok {
			continue
		}
		switch metricName {
		case "cs_active_decisions":
			origin := labels["origin"]
			reason := labels["reason"]
			if origin == "CAPI" {
				res.CAPIBans += val
				capiReasons[reason] += val
			} else if origin == "crowdsec" {
				res.LocalBansMetric += val
			}
		case "cs_reader_hits_total":
			if src := labels["source"]; src != "" {
				getSrc(src).Read += val
			}
		case "cs_parser_hits_ok_total":
			if src := labels["source"]; src != "" {
				getSrc(src).Parsed += val
			}
		case "cs_parser_hits_ko_total":
			if src := labels["source"]; src != "" {
				getSrc(src).Unparsed += val
			}
		}
	}

	for k, v := range capiReasons {
		res.CAPIBreakdown = append(res.CAPIBreakdown, NameCount{Name: k, Count: v})
	}
	sort.Slice(res.CAPIBreakdown, func(i, j int) bool {
		return res.CAPIBreakdown[i].Count > res.CAPIBreakdown[j].Count
	})

	for _, item := range sourcesMap {
		if item.Read > 0 || item.Parsed > 0 || item.Unparsed > 0 {
			res.Sources = append(res.Sources, *item)
		}
	}
	sort.Slice(res.Sources, func(i, j int) bool {
		return res.Sources[i].Read > res.Sources[j].Read
	})
	return res
}

func parsePromLine(line string) (string, map[string]string, int64, bool) {
	labels := make(map[string]string)
	var namePart, valPart string
	if idx := strings.IndexByte(line, '{'); idx != -1 {
		end := strings.LastIndexByte(line, '}')
		if end <= idx {
			return "", nil, 0, false
		}
		namePart = line[:idx]
		labelStr := line[idx+1 : end]
		rest := strings.TrimSpace(line[end+1:])
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return "", nil, 0, false
		}
		valPart = fields[0]
		for _, pair := range splitPromLabels(labelStr) {
			eq := strings.IndexByte(pair, '=')
			if eq <= 0 {
				continue
			}
			k := strings.TrimSpace(pair[:eq])
			v := strings.Trim(strings.TrimSpace(pair[eq+1:]), `"`)
			labels[k] = v
		}
	} else {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", nil, 0, false
		}
		namePart = fields[0]
		valPart = fields[1]
	}
	f, err := strconv.ParseFloat(valPart, 64)
	if err != nil {
		return "", nil, 0, false
	}
	return namePart, labels, int64(f), true
}

func splitPromLabels(s string) []string {
	var out []string
	var cur strings.Builder
	inQuotes := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			cur.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			cur.WriteByte(c)
			continue
		}
		if c == '"' {
			inQuotes = !inQuotes
			cur.WriteByte(c)
			continue
		}
		if c == ',' && !inQuotes {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func (a *App) loadAllAlerts(includeEvents bool) ([]AlertItem, error) {
	now := time.Now()

	// Load active local decisions indexed by alert_decisions
	decRows, err := a.db.Query(`SELECT alert_decisions, until, type FROM decisions WHERE origin = 'crowdsec'`)
	if err != nil {
		return nil, err
	}
	defer decRows.Close()
	type banInfo struct {
		count     int
		maxUntil  time.Time
		hasActive bool
	}
	bansByAlert := make(map[int64]*banInfo)
	for decRows.Next() {
		var alertID sql.NullInt64
		var untilStr, decType string
		if err := decRows.Scan(&alertID, &untilStr, &decType); err != nil || !alertID.Valid {
			continue
		}
		t, ok := parseCrowdSecTime(untilStr)
		if !ok || !t.After(now) {
			continue
		}
		bi := bansByAlert[alertID.Int64]
		if bi == nil {
			bi = &banInfo{}
			bansByAlert[alertID.Int64] = bi
		}
		bi.count++
		bi.hasActive = true
		if t.After(bi.maxUntil) {
			bi.maxUntil = t
		}
	}

	// Load events indexed by alert_events
	evRows, err := a.db.Query(`SELECT alert_events, serialized FROM events ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer evRows.Close()
	eventsByAlert := make(map[int64][]EventDetail)
	for evRows.Next() {
		var alertID sql.NullInt64
		var serialized string
		if err := evRows.Scan(&alertID, &serialized); err != nil || !alertID.Valid {
			continue
		}
		ev := a.parseEventSerialized(serialized)
		eventsByAlert[alertID.Int64] = append(eventsByAlert[alertID.Int64], ev)
	}

	rows, err := a.db.Query(`
		SELECT id, created_at, scenario, COALESCE(events_count,0),
		       COALESCE(source_ip,''), COALESCE(source_range,''),
		       COALESCE(source_as_number,''), COALESCE(source_as_name,''),
		       COALESCE(source_country,'')
		FROM alerts
		ORDER BY id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AlertItem
	for rows.Next() {
		var it AlertItem
		var createdStr string
		if err := rows.Scan(&it.ID, &createdStr, &it.Scenario, &it.EventsCount,
			&it.SourceIP, &it.SourceRange, &it.ASNNumber, &it.ASNName, &it.Country); err != nil {
			continue
		}
		if t, ok := parseCrowdSecTime(createdStr); ok {
			it.CreatedTS = t.Unix()
			it.CreatedAt = t.In(a.loc).Format("2006-01-02 15:04:05")
			it.Age = humanDuration(now.Sub(t)) + " ago"
		} else {
			it.CreatedAt = createdStr
		}
		if bi := bansByAlert[it.ID]; bi != nil && bi.hasActive {
			it.ActiveBan = true
			it.BanCount = bi.count
			it.BanRemaining = humanDuration(bi.maxUntil.Sub(now))
		}
		evs := eventsByAlert[it.ID]
		for _, ev := range evs {
			it.Sites = appendUnique(it.Sites, ev.Site)
			it.TargetURIs = appendUnique(it.TargetURIs, ev.TargetURI)
			it.Methods = appendUnique(it.Methods, ev.Method)
			it.Statuses = appendUnique(it.Statuses, ev.Status)
			it.UserAgents = appendUnique(it.UserAgents, ev.UserAgent)
			it.Datasources = appendUnique(it.Datasources, ev.DatasourcePath)
		}
		if len(it.Sites) == 0 {
			it.Sites = []string{"unknown"}
		}
		if includeEvents {
			it.Events = evs
		}
		items = append(items, it)
	}
	return items, nil
}

func topNFromMap(m map[string]int64, limit int) []NameCount {
	var out []NameCount
	for k, v := range m {
		if k == "" {
			k = "unknown"
		}
		out = append(out, NameCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (a *App) buildOverview() (OverviewResponse, error) {
	alerts, err := a.loadAllAlerts(false)
	if err != nil {
		return OverviewResponse{}, err
	}
	now := time.Now()
	cutoff24h := now.Add(-24 * time.Hour).Unix()

	siteCounts := make(map[string]int64)
	scenarioCounts := make(map[string]int64)
	countryCounts := make(map[string]int64)
	ipCounts := make(map[string]int64)
	uniqueIPs := make(map[string]struct{})
	allSites := make(map[string]struct{})
	allScenarios := make(map[string]struct{})

	// Prepare 24 hourly buckets ending at current hour
	curHour := time.Now().In(a.loc).Truncate(time.Hour)
	hourlyMap := make(map[int64]int64, 24)
	var hourly []HourBucket
	for i := 23; i >= 0; i-- {
		h := curHour.Add(-time.Duration(i) * time.Hour)
		hourly = append(hourly, HourBucket{Label: h.Format("15:00"), Count: 0})
	}

	var alerts24h, activeBans int64
	for _, al := range alerts {
		allScenarios[al.Scenario] = struct{}{}
		for _, s := range al.Sites {
			allSites[s] = struct{}{}
		}
		if al.ActiveBan {
			activeBans += int64(al.BanCount)
		}
		if al.CreatedTS >= cutoff24h {
			alerts24h++
			if al.SourceIP != "" {
				uniqueIPs[al.SourceIP] = struct{}{}
				ipCounts[al.SourceIP]++
			}
			scenarioCounts[al.Scenario]++
			if al.Country != "" {
				countryCounts[al.Country]++
			}
			for _, s := range al.Sites {
				siteCounts[s]++
			}
			t := time.Unix(al.CreatedTS, 0).In(a.loc).Truncate(time.Hour).Unix()
			hourlyMap[t]++
		}
	}
	for i := 23; i >= 0; i-- {
		h := curHour.Add(-time.Duration(i) * time.Hour)
		hourly[23-i].Count = hourlyMap[h.Unix()]
	}

	topSites := topNFromMap(siteCounts, 10)
	topSite := "-"
	if len(topSites) > 0 {
		topSite = topSites[0].Name
	}

	var filterSites, filterScenarios []string
	for s := range allSites {
		filterSites = append(filterSites, s)
	}
	sort.Strings(filterSites)
	for sc := range allScenarios {
		filterScenarios = append(filterScenarios, sc)
	}
	sort.Strings(filterScenarios)

	metrics := a.fetchPrometheusMetrics()

	var activeBouncers int64
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM bouncers WHERE revoked = 0`).Scan(&activeBouncers)

	return OverviewResponse{
		GeneratedAt:     time.Now().In(a.loc).Format("2006-01-02 15:04:05 MST"),
		Hostname:        a.hostname,
		TotalAlerts:     int64(len(alerts)),
		Alerts24h:       alerts24h,
		UniqueIPs24h:    int64(len(uniqueIPs)),
		ActiveLocalBans: activeBans,
		ActiveBouncers:  activeBouncers,
		CAPIBans:        metrics.CAPIBans,
		TopSite24h:      topSite,
		TopSites:        topSites,
		TopScenarios:    topNFromMap(scenarioCounts, 10),
		TopCountries:    topNFromMap(countryCounts, 8),
		TopIPs:          topNFromMap(ipCounts, 10),
		Hourly24h:       hourly,
		FilterSites:     filterSites,
		FilterScenarios: filterScenarios,
		Metrics:         metrics,
	}, nil
}

func (a *App) loadDecisions() ([]DecisionItem, error) {
	now := time.Now()
	rows, err := a.db.Query(`
		SELECT id, created_at, COALESCE(until,''), scenario, type, scope, value, origin
		FROM decisions
		WHERE origin = 'crowdsec'
		ORDER BY id DESC
		LIMIT 300
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []DecisionItem
	for rows.Next() {
		var d DecisionItem
		var createdStr, untilStr string
		if err := rows.Scan(&d.ID, &createdStr, &untilStr, &d.Scenario, &d.Type, &d.Scope, &d.Value, &d.Origin); err != nil {
			continue
		}
		if t, ok := parseCrowdSecTime(createdStr); ok {
			d.CreatedAt = t.In(a.loc).Format("2006-01-02 15:04:05")
		} else {
			d.CreatedAt = createdStr
		}
		if t, ok := parseCrowdSecTime(untilStr); ok {
			d.Until = t.In(a.loc).Format("2006-01-02 15:04:05")
			if t.After(now) {
				d.Active = true
				d.Remaining = humanDuration(t.Sub(now))
			} else {
				d.Remaining = "expired"
			}
		}
		items = append(items, d)
	}
	return items, nil
}

func (a *App) signSession(username string, exp int64) string {
	payload := fmt.Sprintf("%s|%d", username, exp)
	mac := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + "|" + sig
}

func (a *App) verifySession(cookieVal string) (string, bool) {
	parts := strings.Split(cookieVal, "|")
	if len(parts) != 3 {
		return "", false
	}
	username := parts[0]
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	expected := a.signSession(username, exp)
	if subtle.ConstantTimeCompare([]byte(cookieVal), []byte(expected)) != 1 {
		return "", false
	}
	return username, true
}

func clientIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return strings.TrimSpace(cf)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:;")
}

func validUsername(u string) bool {
	if len(u) < 2 || len(u) > 32 {
		return false
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func (a *App) findUser(username string) (User, bool) {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	for _, u := range a.cfg.Users {
		if strings.EqualFold(u.Username, username) {
			return u, true
		}
	}
	return User{}, false
}

func (a *App) saveConfigLocked() error {
	if a.cfgPath == "" {
		return errors.New("config path not set")
	}
	data, err := json.MarshalIndent(a.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.cfgPath + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.cfgPath)
}

func (a *App) requireAuth(next func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		c, err := r.Cookie("cs_ui_session")
		if err != nil {
			a.unauthorized(w, r)
			return
		}
		uname, ok := a.verifySession(c.Value)
		if !ok {
			a.unauthorized(w, r)
			return
		}
		u, exists := a.findUser(uname)
		if !exists {
			a.unauthorized(w, r)
			return
		}
		next(w, r, u)
	}
}

func (a *App) requireAdmin(next func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return a.requireAuth(func(w http.ResponseWriter, r *http.Request, u User) {
		if u.Role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
			return
		}
		next(w, r, u)
	})
}

func (a *App) unauthorized(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if r.Method == http.MethodGet {
		if c, err := r.Cookie("cs_ui_session"); err == nil {
			if uname, ok := a.verifySession(c.Value); ok {
				if _, exists := a.findUser(uname); exists {
					http.Redirect(w, r, "/", http.StatusFound)
					return
				}
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = a.loginT.Execute(w, map[string]any{"Error": "", "Hostname": a.hostname})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if !a.limiter.Allow(ip) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = a.loginT.Execute(w, map[string]any{"Error": "Too many failed attempts. Wait 5 minutes.", "Hostname": a.hostname})
		return
	}
	_ = r.ParseForm()
	user := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	u, exists := a.findUser(user)
	passOK := exists && verifyPassword(pass, u.PasswordHash)
	if !passOK {
		a.limiter.RecordFail(ip)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = a.loginT.Execute(w, map[string]any{"Error": "Invalid username or password.", "Hostname": a.hostname})
		return
	}
	a.limiter.Reset(ip)
	ttl := time.Duration(a.cfg.SessionTTLMin) * time.Minute
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	exp := time.Now().Add(ttl)
	http.SetCookie(w, &http.Cookie{
		Name:     "cs_ui_session",
		Value:    a.signSession(u.Username, exp.Unix()),
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	http.SetCookie(w, &http.Cookie{
		Name:     "cs_ui_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request, u User) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = a.indexT.Execute(w, map[string]any{
		"Username": u.Username,
		"Role":     u.Role,
		"IsAdmin":  u.Role == "admin",
		"Hostname": a.hostname,
		"TZName":   time.Now().In(a.loc).Format("MST"),
	})
}

func decodeJSONBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 16384))
	return dec.Decode(dst)
}

func (a *App) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request, u User) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if len(req.NewPassword) < 8 {
		writeJSON(w, 400, map[string]string{"error": "new password must be at least 8 characters"})
		return
	}
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	idx := -1
	for i := range a.cfg.Users {
		if strings.EqualFold(a.cfg.Users[i].Username, u.Username) {
			idx = i
			break
		}
	}
	if idx < 0 || !verifyPassword(req.CurrentPassword, a.cfg.Users[idx].PasswordHash) {
		writeJSON(w, 403, map[string]string{"error": "current password is incorrect"})
		return
	}
	h, err := hashPassword(req.NewPassword)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "failed to hash password"})
		return
	}
	a.cfg.Users[idx].PasswordHash = h
	if err := a.saveConfigLocked(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "failed to save config"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleUsers(w http.ResponseWriter, r *http.Request, current User) {
	switch r.Method {
	case http.MethodGet:
		a.cfgMu.RLock()
		out := make([]PublicUser, 0, len(a.cfg.Users))
		for _, u := range a.cfg.Users {
			out = append(out, PublicUser{
				Username:  u.Username,
				Role:      u.Role,
				CreatedAt: u.CreatedAt,
			})
		}
		a.cfgMu.RUnlock()
		writeJSON(w, 200, map[string]any{"items": out})
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		if !validUsername(req.Username) {
			writeJSON(w, 400, map[string]string{"error": "username must be 2-32 chars (letters, digits, _, ., -)"})
			return
		}
		if len(req.Password) < 8 {
			writeJSON(w, 400, map[string]string{"error": "password must be at least 8 characters"})
			return
		}
		role := strings.ToLower(strings.TrimSpace(req.Role))
		if role != "admin" && role != "viewer" {
			role = "viewer"
		}
		h, err := hashPassword(req.Password)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to hash password"})
			return
		}
		a.cfgMu.Lock()
		defer a.cfgMu.Unlock()
		for _, existing := range a.cfg.Users {
			if strings.EqualFold(existing.Username, req.Username) {
				writeJSON(w, 409, map[string]string{"error": "username already exists"})
				return
			}
		}
		a.cfg.Users = append(a.cfg.Users, User{
			Username:     req.Username,
			PasswordHash: h,
			Role:         role,
			CreatedAt:    time.Now().In(a.loc).Format("2006-01-02 15:04:05"),
		})
		if err := a.saveConfigLocked(); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to save config"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (a *App) handleAdminSetPassword(w http.ResponseWriter, r *http.Request, current User) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if len(req.NewPassword) < 8 {
		writeJSON(w, 400, map[string]string{"error": "password must be at least 8 characters"})
		return
	}
	h, err := hashPassword(req.NewPassword)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "failed to hash password"})
		return
	}
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	for i := range a.cfg.Users {
		if strings.EqualFold(a.cfg.Users[i].Username, strings.TrimSpace(req.Username)) {
			a.cfg.Users[i].PasswordHash = h
			if err := a.saveConfigLocked(); err != nil {
				writeJSON(w, 500, map[string]string{"error": "failed to save config"})
				return
			}
			writeJSON(w, 200, map[string]any{"ok": true})
			return
		}
	}
	writeJSON(w, 404, map[string]string{"error": "user not found"})
}

func (a *App) handleDeleteUser(w http.ResponseWriter, r *http.Request, current User) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	target := strings.TrimSpace(req.Username)
	if strings.EqualFold(target, current.Username) {
		writeJSON(w, 400, map[string]string{"error": "cannot delete currently signed-in user"})
		return
	}
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	idx := -1
	admins := 0
	for i, u := range a.cfg.Users {
		if u.Role == "admin" {
			admins++
		}
		if strings.EqualFold(u.Username, target) {
			idx = i
		}
	}
	if idx < 0 {
		writeJSON(w, 404, map[string]string{"error": "user not found"})
		return
	}
	if a.cfg.Users[idx].Role == "admin" && admins <= 1 {
		writeJSON(w, 400, map[string]string{"error": "cannot delete the last admin user"})
		return
	}
	a.cfg.Users = append(a.cfg.Users[:idx], a.cfg.Users[idx+1:]...)
	if err := a.saveConfigLocked(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "failed to save config"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *App) handleOverview(w http.ResponseWriter, r *http.Request, _ User) {
	ov, err := a.buildOverview()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, ov)
}

func (a *App) handleAlerts(w http.ResponseWriter, r *http.Request, _ User) {
	q := r.URL.Query()
	siteF := strings.TrimSpace(q.Get("site"))
	scenF := strings.TrimSpace(q.Get("scenario"))
	searchF := strings.ToLower(strings.TrimSpace(q.Get("q")))
	winF := strings.TrimSpace(q.Get("window"))
	hideRBL := q.Get("hide_rbl") == "1"
	onlyActive := q.Get("active_only") == "1"

	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if pageSize < 10 || pageSize > 200 {
		pageSize = 50
	}

	var minTS int64
	switch winF {
	case "1h":
		minTS = time.Now().Add(-1 * time.Hour).Unix()
	case "24h":
		minTS = time.Now().Add(-24 * time.Hour).Unix()
	case "7d":
		minTS = time.Now().Add(-7 * 24 * time.Hour).Unix()
	}

	all, err := a.loadAllAlerts(false)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}

	var filtered []AlertItem
	for _, al := range all {
		if minTS > 0 && al.CreatedTS < minTS {
			continue
		}
		if hideRBL && strings.Contains(al.Scenario, "postscreen-rbl") {
			continue
		}
		if onlyActive && !al.ActiveBan {
			continue
		}
		if scenF != "" && al.Scenario != scenF {
			continue
		}
		if siteF != "" {
			matched := false
			for _, s := range al.Sites {
				if s == siteF {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if searchF != "" {
			hay := strings.ToLower(strings.Join([]string{
				al.SourceIP, al.Country, al.ASNName, al.ASNNumber, al.Scenario,
				strings.Join(al.Sites, " "),
				strings.Join(al.TargetURIs, " "),
				strings.Join(al.UserAgents, " "),
			}, " "))
			if !strings.Contains(hay, searchF) {
				continue
			}
		}
		filtered = append(filtered, al)
	}

	total := len(filtered)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	writeJSON(w, 200, AlertsResponse{
		Total:    total,
		Page:     page,
		PageSize: pageSize,
		Items:    filtered[start:end],
	})
}

func (a *App) handleAlertDetail(w http.ResponseWriter, r *http.Request, _ User) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/alert/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, 400, map[string]string{"error": "invalid alert id"})
		return
	}
	all, err := a.loadAllAlerts(true)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	for _, al := range all {
		if al.ID == id {
			writeJSON(w, 200, al)
			return
		}
	}
	writeJSON(w, 404, map[string]string{"error": "alert not found"})
}

func (a *App) handleDecisions(w http.ResponseWriter, r *http.Request, _ User) {
	items, err := a.loadDecisions()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func randomPassword(n int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, v := range b {
		out[i] = chars[int(v)%len(chars)]
	}
	return string(out), nil
}

func main() {
	cfgPath := flag.String("c", "config.json", "Path to config.json")
	genPass := flag.String("hash-password", "", "Generate PBKDF2 password hash and exit")
	genSecret := flag.Bool("gen-secret", false, "Generate random 32-byte hex secret and exit")
	initConfig := flag.Bool("init-config", false, "Create a new config.json at -c with a random admin password and exit")
	initUser := flag.String("init-user", "admin", "Initial admin username for -init-config")
	initListen := flag.String("init-listen", "127.0.0.1:8082", "Initial listen_addr for -init-config")
	initDB := flag.String("init-db", "/var/lib/crowdsec/data/crowdsec.db", "Initial db_path for -init-config")
	initMetrics := flag.String("init-metrics", "http://127.0.0.1:6060/metrics", "Initial metrics_url for -init-config")
	initTZ := flag.String("init-tz", "UTC", "Initial timezone for -init-config")
	flag.Parse()

	if *genPass != "" {
		h, err := hashPassword(*genPass)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(h)
		return
	}
	if *genSecret {
		b := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(b))
		return
	}
	if *initConfig {
		if _, err := os.Stat(*cfgPath); err == nil {
			log.Fatalf("refusing to overwrite existing %s", *cfgPath)
		}
		pw, err := randomPassword(20)
		if err != nil {
			log.Fatal(err)
		}
		ph, err := hashPassword(pw)
		if err != nil {
			log.Fatal(err)
		}
		secB := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, secB); err != nil {
			log.Fatal(err)
		}
		cfg := Config{
			ListenAddr:    *initListen,
			DBPath:        *initDB,
			MetricsURL:    *initMetrics,
			SessionSecret: hex.EncodeToString(secB),
			SessionTTLMin: 720,
			Timezone:      *initTZ,
			Users: []User{{
				Username:     *initUser,
				PasswordHash: ph,
				Role:         "admin",
				CreatedAt:    time.Now().UTC().Format("2006-01-02 15:04:05"),
			}},
			SiteMap: map[string]string{},
		}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*cfgPath, append(data, '\n'), 0600); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Created %s (mode 0600)\nUsername: %s\nPassword: %s\n", *cfgPath, *initUser, pw)
		return
	}

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("read config %s: %v", *cfgPath, err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	if v := strings.TrimSpace(os.Getenv("CROWDSEC_UI_LISTEN")); v != "" {
		cfg.ListenAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("CROWDSEC_UI_DB")); v != "" {
		cfg.DBPath = v
	}
	if v := strings.TrimSpace(os.Getenv("CROWDSEC_UI_METRICS")); v != "" {
		cfg.MetricsURL = v
	}
	if v := strings.TrimSpace(os.Getenv("CROWDSEC_UI_TIMEZONE")); v != "" {
		cfg.Timezone = v
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:8082"
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "/var/lib/crowdsec/data/crowdsec.db"
	}
	if cfg.MetricsURL == "" {
		cfg.MetricsURL = "http://127.0.0.1:6060/metrics"
	}

	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil || cfg.Timezone == "" {
		loc = time.UTC
	}

	migrated := false
	if len(cfg.Users) == 0 && cfg.Username != "" && cfg.PasswordHash != "" {
		cfg.Users = []User{{
			Username:     cfg.Username,
			PasswordHash: cfg.PasswordHash,
			Role:         "admin",
			CreatedAt:    time.Now().In(loc).Format("2006-01-02 15:04:05"),
		}}
		cfg.Username = ""
		cfg.PasswordHash = ""
		migrated = true
	}
	if len(cfg.Users) == 0 || cfg.SessionSecret == "" {
		log.Fatal("at least one user and session_secret must be set")
	}

	dsn := fmt.Sprintf("file:%s?mode=ro&_busy_timeout=5000&_query_only=on", cfg.DBPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		log.Fatalf("ping sqlite: %v", err)
	}

	loginT, err := template.ParseFS(webFS, "web/login.html")
	if err != nil {
		log.Fatalf("parse login.html: %v", err)
	}
	indexT, err := template.ParseFS(webFS, "web/index.html")
	if err != nil {
		log.Fatalf("parse index.html: %v", err)
	}

	hostname := strings.TrimSpace(os.Getenv("CROWDSEC_UI_HOSTNAME"))
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if hostname == "" {
		hostname = "localhost"
	}

	siteKeys := make([]string, 0, len(cfg.SiteMap))
	for k := range cfg.SiteMap {
		siteKeys = append(siteKeys, k)
	}
	sort.Slice(siteKeys, func(i, j int) bool {
		if len(siteKeys[i]) == len(siteKeys[j]) {
			return siteKeys[i] < siteKeys[j]
		}
		return len(siteKeys[i]) > len(siteKeys[j])
	})

	app := &App{
		cfgPath:  *cfgPath,
		cfg:      cfg,
		siteKeys: siteKeys,
		loc:      loc,
		hostname: hostname,
		db:       db,
		limiter:  NewRateLimiter(),
		loginT:   loginT,
		indexT:   indexT,
	}
	if migrated {
		app.cfgMu.Lock()
		if err := app.saveConfigLocked(); err != nil {
			log.Printf("warning: failed to persist migrated users config: %v", err)
		}
		app.cfgMu.Unlock()
	}

	mux := http.NewServeMux()
	serveEmbedded := func(path, contentType string) http.HandlerFunc {
		data, err := webFS.ReadFile(path)
		return func(w http.ResponseWriter, r *http.Request) {
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Cache-Control", "public, max-age=86400")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = w.Write(data)
		}
	}
	mux.HandleFunc("/favicon.ico", serveEmbedded("web/favicon.ico", "image/x-icon"))
	mux.HandleFunc("/favicon.svg", serveEmbedded("web/favicon.svg", "image/svg+xml"))
	mux.HandleFunc("/apple-touch-icon.png", serveEmbedded("web/apple-touch-icon.png", "image/png"))
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := app.db.Ping(); err != nil && !errors.Is(err, sql.ErrConnDone) {
			http.Error(w, "db error", 500)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", app.requireAuth(app.handleIndex))
	mux.HandleFunc("/api/overview", app.requireAuth(app.handleOverview))
	mux.HandleFunc("/api/alerts", app.requireAuth(app.handleAlerts))
	mux.HandleFunc("/api/alert/", app.requireAuth(app.handleAlertDetail))
	mux.HandleFunc("/api/decisions", app.requireAuth(app.handleDecisions))
	mux.HandleFunc("/api/account/password", app.requireAuth(app.handleChangeOwnPassword))
	mux.HandleFunc("/api/users", app.requireAdmin(app.handleUsers))
	mux.HandleFunc("/api/users/password", app.requireAdmin(app.handleAdminSetPassword))
	mux.HandleFunc("/api/users/delete", app.requireAdmin(app.handleDeleteUser))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("crowdsec-ui listening on http://%s (db=%s)", cfg.ListenAddr, cfg.DBPath)
	log.Fatal(srv.ListenAndServe())
}
