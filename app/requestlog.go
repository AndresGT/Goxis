package goxis

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	goxislog "github.com/AndresGT/Goxis/log"
)

// responseRecorder observes the final response code while forwarding common
// optional ResponseWriter capabilities to the wrapped writer.
type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (w *responseRecorder) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	if status >= 200 || status == http.StatusSwitchingProtocols {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseRecorder) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *responseRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseRecorder) Flush() { _ = w.FlushError() }
func (w *responseRecorder) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(interface{ FlushError() error }); ok {
		return flusher.FlushError()
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
		return nil
	}
	return http.ErrNotSupported
}

func (w *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return hijacker.Hijack()
}

func (w *responseRecorder) Push(target string, options *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

func (w *responseRecorder) ReadFrom(reader io.Reader) (int64, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if from, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return from.ReadFrom(reader)
	}
	return io.Copy(responseWriterOnly{ResponseWriter: w.ResponseWriter}, reader)
}

type responseWriterOnly struct{ http.ResponseWriter }

func logRequest(request *http.Request, status int, duration time.Duration) {
	goxislog.HTTPRequest(request.Method, safeRequestURI(request.URL), status, remoteIP(request.RemoteAddr), duration)
}

var sensitiveQueryKeys = map[string]struct{}{
	"token": {}, "jwt": {}, "access_token": {}, "accesstoken": {}, "refresh_token": {}, "refreshtoken": {}, "id_token": {},
	"password": {}, "passwd": {}, "secret": {}, "client_secret": {},
	"api_key": {}, "apikey": {}, "authorization": {},
}

func safeRequestURI(u *url.URL) string {
	if u == nil {
		return "/"
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil && u.RawQuery != "" {
		return u.EscapedPath() + "?[REDACTED]"
	}
	for key := range query {
		if _, sensitive := sensitiveQueryKeys[strings.ToLower(key)]; sensitive {
			query[key] = []string{"[REDACTED]"}
		}
	}
	uri := u.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	if encoded := query.Encode(); encoded != "" {
		uri += "?" + encoded
	}
	return uri
}
