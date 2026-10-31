package goxis

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"sync/atomic"
	"time"
)

// RequestIDHeader is the response header carrying Goxis' generated request ID.
const RequestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

var requestIDFallbackCounter atomic.Uint64

func attachRequestID(request *http.Request, writer http.ResponseWriter) (*http.Request, string) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		binary.BigEndian.PutUint64(raw[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(raw[8:], requestIDFallbackCounter.Add(1))
	}
	id := hex.EncodeToString(raw[:])
	request = request.WithContext(context.WithValue(request.Context(), requestIDContextKey{}, id))
	writer.Header().Set(RequestIDHeader, id)
	return request, id
}

func requestIDFromRequest(request *http.Request) string {
	if request == nil {
		return ""
	}
	id, _ := request.Context().Value(requestIDContextKey{}).(string)
	return id
}
