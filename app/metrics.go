package goxis

import (
	"fmt"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultMetricSamples = 2048
	maxMetricSamples     = 100000
)

type requestSample struct {
	at       time.Time
	duration time.Duration
	status   int
	route    string
	group    string
	detail   requestRecord
}

type requestRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Route      string    `json:"route"`
	Group      string    `json:"group"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	DurationMS float64   `json:"duration_ms"`
	ClientIP   string    `json:"client_ip"`
	RequestID  string    `json:"request_id"`
}

type requestMetrics struct {
	mu          sync.RWMutex
	startedAt   time.Time
	active      int64
	total       uint64
	statusCount map[string]uint64
	samples     []requestSample
	start       int
	length      int
	onUpdate    func()
}

type metricBucket struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type routeMetric struct {
	Route string `json:"route"`
	Count int    `json:"count"`
}

type methodMetric struct {
	Method       string  `json:"method"`
	Requests     int     `json:"requests"`
	ClientErrors int     `json:"client_errors"`
	ServerErrors int     `json:"server_errors"`
	AverageMS    float64 `json:"average_latency_ms"`
	P95MS        float64 `json:"p95_latency_ms"`
}

type panelRecommendation struct {
	Priority string `json:"priority"`
	Method   string `json:"method"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
	Review   string `json:"review"`
}

type metricsSnapshot struct {
	UptimeSeconds      float64               `json:"uptime_seconds"`
	TotalRequests      uint64                `json:"total_requests"`
	ActiveRequests     int64                 `json:"active_requests"`
	RequestsLastMinute int                   `json:"requests_last_minute"`
	AverageLatencyMS   float64               `json:"average_latency_ms"`
	P95LatencyMS       float64               `json:"p95_latency_ms"`
	StatusCounts       map[string]uint64     `json:"status_counts"`
	Timeline           []metricBucket        `json:"timeline"`
	TopRoutes          []routeMetric         `json:"top_routes"`
	Methods            []methodMetric        `json:"methods"`
	Recommendations    []panelRecommendation `json:"recommendations"`
}

type runtimeSnapshot struct {
	CollectedAt         time.Time  `json:"collected_at"`
	GoVersion           string     `json:"go_version"`
	GOOS                string     `json:"goos"`
	GOARCH              string     `json:"goarch"`
	LogicalCPUs         int        `json:"logical_cpus"`
	GOMAXPROCS          int        `json:"gomaxprocs"`
	Goroutines          int        `json:"goroutines"`
	HeapAllocBytes      uint64     `json:"heap_alloc_bytes"`
	TotalAllocBytes     uint64     `json:"total_alloc_bytes"`
	HeapInuseBytes      uint64     `json:"heap_inuse_bytes"`
	HeapIdleBytes       uint64     `json:"heap_idle_bytes"`
	HeapSysBytes        uint64     `json:"heap_sys_bytes"`
	RuntimeSysBytes     uint64     `json:"runtime_sys_bytes"`
	StackInuseBytes     uint64     `json:"stack_inuse_bytes"`
	NextGCBytes         uint64     `json:"next_gc_bytes"`
	NumGC               uint32     `json:"num_gc"`
	LastGCPauseNS       uint64     `json:"last_gc_pause_ns"`
	TotalGCPauseNS      uint64     `json:"total_gc_pause_ns"`
	LastGCAt            *time.Time `json:"last_gc_at,omitempty"`
	ReadHeaderTimeoutMS int64      `json:"http_read_header_timeout_ms"`
	ReadTimeoutMS       int64      `json:"http_read_timeout_ms"`
	WriteTimeoutMS      int64      `json:"http_write_timeout_ms"`
	IdleTimeoutMS       int64      `json:"http_idle_timeout_ms"`
	MaxHeaderBytes      int        `json:"http_max_header_bytes"`
}

func snapshotRuntime(app *App) runtimeSnapshot {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	var lastPause uint64
	if memory.NumGC > 0 {
		lastPause = memory.PauseNs[(memory.NumGC-1)%uint32(len(memory.PauseNs))]
	}
	var lastGC *time.Time
	if memory.LastGC > 0 {
		at := time.Unix(0, int64(memory.LastGC))
		lastGC = &at
	}
	snapshot := runtimeSnapshot{
		CollectedAt: time.Now(), GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		LogicalCPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), Goroutines: runtime.NumGoroutine(),
		HeapAllocBytes: memory.HeapAlloc, TotalAllocBytes: memory.TotalAlloc, HeapInuseBytes: memory.HeapInuse,
		HeapIdleBytes: memory.HeapIdle, HeapSysBytes: memory.HeapSys, RuntimeSysBytes: memory.Sys,
		StackInuseBytes: memory.StackInuse, NextGCBytes: memory.NextGC, NumGC: memory.NumGC,
		LastGCPauseNS: lastPause, TotalGCPauseNS: memory.PauseTotalNs, LastGCAt: lastGC,
	}
	if app != nil {
		app.mu.RLock()
		config := app.serverConfig
		app.mu.RUnlock()
		snapshot.ReadHeaderTimeoutMS = config.ReadHeaderTimeout.Milliseconds()
		snapshot.ReadTimeoutMS = config.ReadTimeout.Milliseconds()
		snapshot.WriteTimeoutMS = config.WriteTimeout.Milliseconds()
		snapshot.IdleTimeoutMS = config.IdleTimeout.Milliseconds()
		snapshot.MaxHeaderBytes = config.MaxHeaderBytes
	}
	return snapshot
}

func newRequestMetrics(capacity int) *requestMetrics {
	if capacity <= 0 {
		capacity = defaultMetricSamples
	}
	if capacity > maxMetricSamples {
		capacity = maxMetricSamples
	}
	return &requestMetrics{
		startedAt: time.Now(), statusCount: make(map[string]uint64),
		samples: make([]requestSample, capacity),
	}
}

func (m *requestMetrics) begin() {
	m.mu.Lock()
	m.active++
	m.mu.Unlock()
}

func (m *requestMetrics) finish(detail requestRecord) {
	m.mu.Lock()
	if m.active > 0 {
		m.active--
	}
	m.total++
	m.statusCount[statusClass(detail.Status)]++
	duration := time.Duration(detail.DurationMS * float64(time.Millisecond))
	item := requestSample{at: detail.Timestamp, duration: duration, status: detail.Status, route: detail.Route, group: detail.Group, detail: detail}
	if m.length < len(m.samples) {
		index := (m.start + m.length) % len(m.samples)
		m.samples[index] = item
		m.length++
	} else {
		m.samples[m.start] = item
		m.start = (m.start + 1) % len(m.samples)
	}
	callback := m.onUpdate
	m.mu.Unlock()
	if callback != nil {
		callback()
	}
}

func (m *requestMetrics) recentRequests(limit int) []requestRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > m.length {
		limit = m.length
	}
	result := make([]requestRecord, 0, limit)
	for i := m.length - 1; i >= 0 && len(result) < limit; i-- {
		sample := m.samples[(m.start+i)%len(m.samples)]
		result = append(result, sample.detail)
	}
	return result
}

func statusClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500:
		return "5xx"
	default:
		return "other"
	}
}

func (m *requestMetrics) snapshot() metricsSnapshot {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := metricsSnapshot{
		UptimeSeconds: now.Sub(m.startedAt).Seconds(), TotalRequests: m.total,
		ActiveRequests: m.active, StatusCounts: make(map[string]uint64, len(m.statusCount)),
		Timeline: make([]metricBucket, 12), TopRoutes: make([]routeMetric, 0, 5),
	}
	for key, value := range m.statusCount {
		result.StatusCounts[key] = value
	}
	minute := now.Truncate(time.Minute)
	countsByMinute := make(map[int64]int, len(result.Timeline))
	routeCounts := make(map[string]int)
	byMethod := make(map[string][]requestSample)
	durations := make([]float64, 0, m.length)
	var durationSum float64
	for i := 0; i < m.length; i++ {
		sample := m.samples[(m.start+i)%len(m.samples)]
		age := now.Sub(sample.at)
		if age >= 0 && age < time.Minute {
			result.RequestsLastMinute++
			latency := float64(sample.duration) / float64(time.Millisecond)
			durations = append(durations, latency)
			durationSum += latency
			routeCounts[sample.route]++
		}
		if age >= 0 && age < 5*time.Minute {
			method, _, ok := strings.Cut(sample.route, " ")
			if ok {
				byMethod[method] = append(byMethod[method], sample)
			}
		}
		bucketTime := sample.at.Truncate(time.Minute)
		minutesAgo := int(minute.Sub(bucketTime) / time.Minute)
		if minutesAgo >= 0 && minutesAgo < len(result.Timeline) {
			countsByMinute[int64(minutesAgo)]++
		}
	}
	for i := range result.Timeline {
		at := minute.Add(-time.Duration(i) * time.Minute)
		result.Timeline[len(result.Timeline)-1-i] = metricBucket{Label: at.Format("15:04"), Count: countsByMinute[int64(i)]}
	}
	if len(durations) > 0 {
		result.AverageLatencyMS = roundMetric(durationSum / float64(len(durations)))
		sort.Float64s(durations)
		index := int(math.Ceil(float64(len(durations))*0.95)) - 1
		if index < 0 {
			index = 0
		}
		result.P95LatencyMS = roundMetric(durations[index])
	}
	for route, count := range routeCounts {
		result.TopRoutes = append(result.TopRoutes, routeMetric{Route: route, Count: count})
	}
	sort.Slice(result.TopRoutes, func(i, j int) bool {
		if result.TopRoutes[i].Count == result.TopRoutes[j].Count {
			return result.TopRoutes[i].Route < result.TopRoutes[j].Route
		}
		return result.TopRoutes[i].Count > result.TopRoutes[j].Count
	})
	if len(result.TopRoutes) > 5 {
		result.TopRoutes = result.TopRoutes[:5]
	}
	for method, samples := range byMethod {
		item := methodMetric{Method: method, Requests: len(samples)}
		latencies := make([]float64, 0, len(samples))
		var total float64
		for _, sample := range samples {
			latency := float64(sample.duration) / float64(time.Millisecond)
			latencies = append(latencies, latency)
			total += latency
			if sample.status >= 400 && sample.status < 500 {
				item.ClientErrors++
			}
			if sample.status >= 500 {
				item.ServerErrors++
			}
		}
		sort.Float64s(latencies)
		item.AverageMS = roundMetric(total / float64(len(samples)))
		item.P95MS = roundMetric(latencies[int(math.Ceil(float64(len(latencies))*0.95))-1])
		result.Methods = append(result.Methods, item)
		result.Recommendations = append(result.Recommendations, methodRecommendations(item)...)
	}
	sort.Slice(result.Methods, func(i, j int) bool {
		if result.Methods[i].Requests == result.Methods[j].Requests {
			return result.Methods[i].Method < result.Methods[j].Method
		}
		return result.Methods[i].Requests > result.Methods[j].Requests
	})
	sort.Slice(result.Recommendations, func(i, j int) bool {
		priority := map[string]int{"alta": 0, "media": 1, "baja": 2}
		if priority[result.Recommendations[i].Priority] != priority[result.Recommendations[j].Priority] {
			return priority[result.Recommendations[i].Priority] < priority[result.Recommendations[j].Priority]
		}
		return result.Recommendations[i].Method < result.Recommendations[j].Method
	})
	return result
}

func methodRecommendations(metric methodMetric) []panelRecommendation {
	recommendations := make([]panelRecommendation, 0, 3)
	if metric.ServerErrors >= 2 {
		recommendations = append(recommendations, panelRecommendation{
			Priority: "alta", Method: metric.Method, Title: "Revisar respuestas 5xx",
			Evidence: fmt.Sprintf("%d de %d solicitudes de este método terminaron en 5xx en los últimos 5 min.", metric.ServerErrors, metric.Requests),
			Review:   methodErrorReview(metric.Method),
		})
	}
	if metric.Requests >= 5 && metric.P95MS >= 1000 {
		recommendations = append(recommendations, panelRecommendation{
			Priority: "media", Method: metric.Method, Title: "Revisar latencia de respuesta",
			Evidence: fmt.Sprintf("p95 %.0f ms y media %.0f ms en %d solicitudes recientes.", metric.P95MS, metric.AverageMS, metric.Requests),
			Review:   methodLatencyReview(metric.Method),
		})
	}
	if metric.Requests >= 10 && float64(metric.ClientErrors)/float64(metric.Requests) >= 0.3 {
		recommendations = append(recommendations, panelRecommendation{
			Priority: "baja", Method: metric.Method, Title: "Revisar respuestas 4xx",
			Evidence: fmt.Sprintf("%d de %d solicitudes recientes devolvieron 4xx.", metric.ClientErrors, metric.Requests),
			Review:   "Revisa validaciones, autenticación, permisos y el cliente que consume estas rutas; confirma que los 4xx sean esperados.",
		})
	}
	if metric.Requests >= 300 {
		recommendations = append(recommendations, panelRecommendation{
			Priority: "baja", Method: metric.Method, Title: "Validar límites de capacidad",
			Evidence: fmt.Sprintf("%d solicitudes de este método en los últimos 5 min.", metric.Requests),
			Review:   methodCapacityReview(metric.Method),
		})
	}
	return recommendations
}

func methodCapacityReview(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return "Si las rutas son públicas o dependen de recursos limitados, revisa RateLimit y el costo de lectura; configura límites por ruta según la capacidad real."
	case http.MethodPost:
		return "Si las rutas crean trabajo costoso, revisa RateLimit, MaxConcurrent y QueueLimit para proteger dependencias y evitar acumulación."
	case http.MethodPut, http.MethodPatch:
		return "Si estas actualizaciones compiten por los mismos registros, revisa RateLimit, MaxConcurrent y QueueLimit junto con los bloqueos de base de datos."
	case http.MethodDelete:
		return "Si el borrado es costoso, revisa RateLimit y concurrencia; limita la cola para que las cascadas no saturen la base de datos."
	default:
		return "Revisa RateLimit, MaxConcurrent y QueueLimit de las rutas de mayor tráfico frente a la capacidad de sus dependencias."
	}
}

func methodLatencyReview(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return "Revisa consultas e índices de lectura, tamaño de las respuestas y uso de caché; comprueba también las dependencias llamadas por estas rutas."
	case http.MethodPost:
		return "Revisa validaciones, transacciones y llamadas externas; mueve trabajo no esencial a una cola cuando sea seguro hacerlo."
	case http.MethodPut, http.MethodPatch:
		return "Revisa consultas de actualización, bloqueos y duración de transacciones; verifica si el handler realiza trabajo externo en línea."
	case http.MethodDelete:
		return "Revisa cascadas, limpieza y bloqueos en base de datos; considera separar tareas de borrado pesado en un trabajo en segundo plano."
	default:
		return "Revisa el handler, las dependencias externas y la configuración de concurrencia/colas de las rutas más lentas."
	}
}

func methodErrorReview(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return "Correlaciona las rutas de lectura con los logs de error y revisa timeouts de base de datos, caché y dependencias externas."
	case http.MethodPost:
		return "Revisa fallos de validación interna, transacciones y servicios externos; confirma que los reintentos no dupliquen operaciones."
	case http.MethodPut, http.MethodPatch:
		return "Inspecciona errores de persistencia, conflictos de concurrencia y transacciones parciales en las rutas de actualización."
	case http.MethodDelete:
		return "Revisa restricciones, dependencias y errores de cascada; comprueba que la operación sea reintentable de forma segura."
	default:
		return "Correlaciona los 5xx con los logs del handler y revisa límites de tiempo, dependencias y capacidad de la cola."
	}
}

func roundMetric(value float64) float64 { return math.Round(value*100) / 100 }

func (app *App) requestRecord(request *http.Request, status int, duration time.Duration) requestRecord {
	path := cleanPath(request.URL.Path)
	route := request.Method + " unmatched"
	group := ""
	app.mu.RLock()
	isAdmin := app.adminPanel != nil && app.adminPanel.matches(path)
	if !isAdmin {
		entry, _, _ := app.findRoute(path, request.Method)
		if entry != nil {
			route = entry.method + " " + entry.path
			group = entry.group
		}
	}
	app.mu.RUnlock()
	if isAdmin {
		route = "admin panel"
	}
	return requestRecord{
		Timestamp: time.Now(), Method: request.Method, Route: route, Group: group,
		Path: safeRequestURI(request.URL), Status: status,
		DurationMS: roundMetric(float64(duration) / float64(time.Millisecond)),
		ClientIP:   remoteIP(request.RemoteAddr), RequestID: requestIDFromRequest(request),
	}
}
