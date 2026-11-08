package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"

	"threat-exchange/internal/api/generated"
	"threat-exchange/internal/service"
	"threat-exchange/internal/store"
)

const (
	maxBodyBytes = 1 << 20 // 1 МиБ
	readyTimeout = 2 * time.Second
)

// NewRouter собирает роутер с валидацией, логами, recover, лимитом тела и health
func NewRouter(threatService *service.Service, threatStore store.ThreatStore, logger *slog.Logger) (http.Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	handler := NewHandler(threatService, logger)

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(requestLogger(logger))
	router.Use(recoverer(logger))
	router.Use(limitBody(maxBodyBytes))

	router.Get("/livez", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	})
	router.Get("/readyz", readinessHandler(threatStore, logger))
	router.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, generated.ErrorResponse{
			Message: "Not found",
			Details: ptr("route not found"),
		})
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusMethodNotAllowed, generated.ErrorResponse{
			Message: "Method not allowed",
		})
	})

	spec, err := generated.GetSwagger()
	if err != nil {
		return nil, fmt.Errorf("load embedded OpenAPI spec: %w", err)
	}
	spec.Servers = nil

	validator := nethttpmiddleware.OapiRequestValidatorWithOptions(spec, &nethttpmiddleware.Options{
		Options: openapi3filter.Options{MultiError: true},
		ErrorHandlerWithOpts: func(_ context.Context, err error, w http.ResponseWriter, _ *http.Request, opts nethttpmiddleware.ErrorHandlerOpts) {
			status := opts.StatusCode
			if status < http.StatusBadRequest {
				status = http.StatusBadRequest
			}
			writeJSON(w, status, generated.ErrorResponse{
				Message: "Invalid request",
				Details: ptr(validationDetails(err)),
			})
		},
	})

	router.Group(func(apiRouter chi.Router) {
		apiRouter.Use(validator)
		generated.HandlerFromMux(generated.NewStrictHandlerWithOptions(
			handler,
			nil,
			generated.StrictHTTPServerOptions{
				RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
					writeJSON(w, http.StatusBadRequest, generated.ErrorResponse{
						Message: "Invalid request",
						Details: ptr(err.Error()),
					})
				},
				ResponseErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
					logger.Error("failed to write response", "error", err)
					writeJSON(w, http.StatusInternalServerError, generated.ErrorResponse{
						Message: "Internal server error",
					})
				},
			},
		), apiRouter)
	})

	return router, nil
}

type healthResponse struct {
	Status string `json:"status"`
}

func readinessHandler(threatStore store.ThreatStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
		defer cancel()

		if err := threatStore.Ping(ctx); err != nil {
			logger.WarnContext(ctx, "readiness check failed", "error", err)
			writeJSON(w, http.StatusServiceUnavailable, healthResponse{Status: "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	}
}

func limitBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes {
				writeJSON(w, http.StatusRequestEntityTooLarge, generated.ErrorResponse{
					Message: "Request body too large",
					Details: ptr(fmt.Sprintf("maximum allowed size is %d bytes", maxBytes)),
				})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			recorder := &responseRecorder{ResponseWriter: w}

			next.ServeHTTP(recorder, r)

			status := recorder.status
			if status == 0 {
				status = http.StatusOK
			}
			logger.InfoContext(r.Context(), "http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", status,
				"bytes", recorder.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", middleware.GetReqID(r.Context()),
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}

func recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				recovered := recover()
				if recovered == nil {
					return
				}
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				logger.ErrorContext(r.Context(), "panic recovered",
					"panic", recovered,
					"request_id", middleware.GetReqID(r.Context()),
				)
				writeJSON(w, http.StatusInternalServerError, generated.ErrorResponse{
					Message: "Internal server error",
				})
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func validationDetails(err error) string {
	var requestErr *openapi3filter.RequestError
	if errors.As(err, &requestErr) {
		reason := schemaDetails(requestErr.Err)
		if reason == "" {
			reason = requestErr.Reason
		}
		if requestErr.Parameter != nil {
			return fmt.Sprintf("parameter %q: %s", requestErr.Parameter.Name, reason)
		}
		return reason
	}
	return schemaDetails(err)
}

func schemaDetails(err error) string {
	if err == nil {
		return ""
	}

	switch multi := err.(type) {
	case openapi3.MultiError:
		parts := make([]string, 0, len(multi))
		for _, inner := range multi {
			if details := schemaDetails(inner); details != "" {
				parts = append(parts, details)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	case *openapi3.MultiError:
		return schemaDetails(*multi)
	}

	var schemaErr *openapi3.SchemaError
	if errors.As(err, &schemaErr) {
		reason := schemaErr.Reason
		if reason == "" {
			reason = schemaErr.Error()
		}
		if path := strings.Join(schemaErr.JSONPointer(), "."); path != "" {
			return path + ": " + reason
		}
		return reason
	}
	return err.Error()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	written, err := r.ResponseWriter.Write(body)
	r.bytes += written
	return written, err
}

func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
