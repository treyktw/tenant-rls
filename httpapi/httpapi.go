// Package httpapi holds the JSON plumbing every handler shares: the error
// envelope, body decoding, and the request middleware.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// MaxBodyBytes bounds every request body. Every edit the demo API takes is a
// few hundred bytes.
const MaxBodyBytes = 64 << 10

// Error is an API error with the status and stable code it maps to. Message
// is safe to show a user; it never contains another tenant's data.
type Error struct {
	Status  int
	Code    string
	Message string
	// RetryAfter, when set, becomes a Retry-After header (seconds).
	RetryAfter int
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf builds an *Error.
func Errorf(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// Common errors.
var (
	ErrUnauthenticated = &Error{Status: http.StatusUnauthorized, Code: "unauthenticated", Message: "Sign in to continue"}
	ErrNoTenant        = &Error{Status: http.StatusForbidden, Code: "no_tenant", Message: "No active tenant account is bound to this session"}
	ErrForbidden       = &Error{Status: http.StatusForbidden, Code: "forbidden", Message: "Insufficient permissions"}
	ErrNotFound        = &Error{Status: http.StatusNotFound, Code: "not_found", Message: "Not found"}
)

// Invalid is a 400 with the given message.
func Invalid(format string, args ...any) *Error {
	return Errorf(http.StatusBadRequest, "invalid_input", format, args...)
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId,omitempty"`
}

// WriteJSON writes v with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes err as the error envelope. Anything that is not an
// *Error is logged by kind and answered as a 500 without detail.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		if errors.Is(err, context.Canceled) {
			// The caller went away; nobody reads this response.
			apiErr = &Error{Status: 499, Code: "canceled", Message: "Request canceled"}
		} else {
			Logger(r.Context()).Error("request failed", "error_kind", errorKind(err))
			apiErr = &Error{Status: http.StatusInternalServerError, Code: "internal", Message: "Something went wrong"}
		}
	}
	if apiErr.RetryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(apiErr.RetryAfter))
	}
	WriteJSON(w, apiErr.Status, errorBody{Error: errorDetail{
		Code: apiErr.Code, Message: apiErr.Message, RequestID: RequestID(r.Context()),
	}})
}

// DecodeJSON reads a bounded JSON object body into v, rejecting unknown
// fields so a misspelt key fails loudly instead of being ignored.
func DecodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, MaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return Errorf(http.StatusRequestEntityTooLarge, "too_large", "Request body is too large")
		}
		var fieldErr *json.UnmarshalTypeError
		if errors.As(err, &fieldErr) && fieldErr.Field != "" {
			return Invalid("Invalid %s", fieldErr.Field)
		}
		return Invalid("Request body must be a JSON object")
	}
	if dec.More() {
		return Invalid("Request body must be a single JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Invalid("Request body must be a single JSON object")
	}
	return nil
}

// HandlerFunc is a handler that returns its error instead of writing it.
type HandlerFunc func(w http.ResponseWriter, r *http.Request) error

// Handle adapts a HandlerFunc.
func Handle(h HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			WriteError(w, r, err)
		}
	})
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

type ctxKey int

const (
	requestIDKey ctxKey = iota
	loggerKey
)

// RequestID is the id assigned to the current request.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// Logger returns the request-scoped logger, or the default logger.
func Logger(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Observe assigns a request id, recovers panics, and writes one access log
// line per request (route pattern, status, duration; never the path or body).
func Observe(base *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newRequestID()
		logger := base.With("request_id", id)
		ctx := context.WithValue(context.WithValue(r.Context(), requestIDKey, id), loggerKey, logger)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-Id", id)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		defer func() {
			if p := recover(); p != nil {
				logger.Error("panic", "stack", string(debug.Stack()))
				WriteError(rec, r, errors.New("panic"))
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			logger.Info("request",
				"route", route,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		}()
		next.ServeHTTP(rec, r)
	})
}

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// errorKind names an error's type for the log without its message, which can
// carry SQL, ids or user input.
func errorKind(err error) string {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return "postgres:" + pgErr.SQLState()
	}
	return fmt.Sprintf("%T", err)
}
