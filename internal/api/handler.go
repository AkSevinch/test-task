// Package api связывает сгенерированный сервер с сервисом и ошибками HTTP
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"threat-exchange/internal/api/generated"
	"threat-exchange/internal/domain"
	"threat-exchange/internal/service"
	"threat-exchange/internal/store"
)

// Handler реализует сгенерированный StrictServerInterface
type Handler struct {
	service *service.Service
	logger  *slog.Logger
}

func NewHandler(threatService *service.Service, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{service: threatService, logger: logger}
}

// CreateThreat обрабатывает POST /info
func (h *Handler) CreateThreat(ctx context.Context, request generated.CreateThreatRequestObject) (generated.CreateThreatResponseObject, error) {
	if request.Body == nil {
		return generated.CreateThreat400JSONResponse(errorBody("Invalid request", "request body is required")), nil
	}

	threat, err := h.service.Create(ctx, toCreateInput(*request.Body))
	if err != nil {
		apiErr := h.mapError(ctx, err)
		switch apiErr.status {
		case http.StatusBadRequest:
			return generated.CreateThreat400JSONResponse(apiErr.body), nil
		case http.StatusConflict:
			return generated.CreateThreat409JSONResponse(apiErr.body), nil
		default:
			return generated.CreateThreat500JSONResponse(apiErr.body), nil
		}
	}
	return generated.CreateThreat201JSONResponse(toThreatResponse(threat)), nil
}

// GetInfoByMd5 обрабатывает GET /info/{md5}
func (h *Handler) GetInfoByMd5(ctx context.Context, request generated.GetInfoByMd5RequestObject) (generated.GetInfoByMd5ResponseObject, error) {
	threat, err := h.service.Get(ctx, request.Md5)
	if err != nil {
		apiErr := h.mapError(ctx, err)
		switch apiErr.status {
		case http.StatusBadRequest:
			return generated.GetInfoByMd5400JSONResponse(apiErr.body), nil
		case http.StatusNotFound:
			return generated.GetInfoByMd5404JSONResponse(apiErr.body), nil
		default:
			return generated.GetInfoByMd5500JSONResponse(apiErr.body), nil
		}
	}
	return generated.GetInfoByMd5200JSONResponse(toThreatResponse(threat)), nil
}

// UpdateThreat обрабатывает PUT /info/{md5}
func (h *Handler) UpdateThreat(ctx context.Context, request generated.UpdateThreatRequestObject) (generated.UpdateThreatResponseObject, error) {
	if request.Body == nil {
		return generated.UpdateThreat400JSONResponse(errorBody("Invalid request", "request body is required")), nil
	}

	threat, err := h.service.Update(ctx, request.Md5, toUpdateInput(*request.Body))
	if err != nil {
		apiErr := h.mapError(ctx, err)
		switch apiErr.status {
		case http.StatusBadRequest:
			return generated.UpdateThreat400JSONResponse(apiErr.body), nil
		case http.StatusNotFound:
			return generated.UpdateThreat404JSONResponse(apiErr.body), nil
		default:
			return generated.UpdateThreat500JSONResponse(apiErr.body), nil
		}
	}
	return generated.UpdateThreat200JSONResponse(toThreatResponse(threat)), nil
}

type apiError struct {
	status int
	body   generated.ErrorResponse
}

func (h *Handler) mapError(ctx context.Context, err error) apiError {
	var validationErr *domain.ValidationError
	switch {
	case errors.As(err, &validationErr):
		return apiError{
			status: http.StatusBadRequest,
			body:   errorBody("Invalid request", validationErr.Error()),
		}
	case errors.Is(err, store.ErrNotFound):
		return apiError{
			status: http.StatusNotFound,
			body:   errorBody("Threat not found", "No threat with the requested MD5 found"),
		}
	case errors.Is(err, store.ErrConflict):
		return apiError{
			status: http.StatusConflict,
			body:   errorBody("Threat already exists", "A threat with the requested MD5 already exists"),
		}
	default:
		h.logger.ErrorContext(ctx, "unhandled service error", "error", err)
		return apiError{
			status: http.StatusInternalServerError,
			body:   errorBody("Internal server error", ""),
		}
	}
}

func errorBody(message, details string) generated.ErrorResponse {
	body := generated.ErrorResponse{Message: message}
	if details != "" {
		body.Details = ptr(details)
	}
	return body
}

func toThreatResponse(threat *domain.Threat) generated.ThreatResponse {
	return generated.ThreatResponse{
		Md5:         threat.MD5,
		Name:        threat.Name,
		ThreatType:  generated.ThreatType(threat.ThreatType),
		Severity:    generated.Severity(threat.Severity),
		Status:      generated.Status(threat.Status),
		Description: threat.Description,
		FileType:    threat.FileType,
		FileSize:    threat.FileSize,
		Confidence:  threat.Confidence,
		Tags:        append([]string{}, threat.Tags...),
		Source:      threat.Source,
		FirstSeen:   threat.FirstSeen,
		LastSeen:    threat.LastSeen,
		CreatedAt:   threat.CreatedAt,
		UpdatedAt:   threat.UpdatedAt,
	}
}

func toCreateInput(body generated.ThreatCreateRequest) service.CreateInput {
	return service.CreateInput{
		MD5:         body.Md5,
		Name:        body.Name,
		ThreatType:  convertEnum[generated.ThreatType, domain.ThreatType](body.ThreatType),
		Severity:    convertEnum[generated.Severity, domain.Severity](body.Severity),
		Status:      convertEnum[generated.Status, domain.Status](body.Status),
		Description: body.Description,
		FileType:    body.FileType,
		FileSize:    body.FileSize,
		Confidence:  body.Confidence,
		Tags:        body.Tags,
		Source:      body.Source,
		FirstSeen:   body.FirstSeen,
		LastSeen:    body.LastSeen,
	}
}

func toUpdateInput(body generated.ThreatUpdateRequest) service.UpdateInput {
	return service.UpdateInput{
		Name:        body.Name,
		ThreatType:  convertEnum[generated.ThreatType, domain.ThreatType](body.ThreatType),
		Severity:    convertEnum[generated.Severity, domain.Severity](body.Severity),
		Status:      convertEnum[generated.Status, domain.Status](body.Status),
		Description: body.Description,
		FileType:    body.FileType,
		FileSize:    body.FileSize,
		Confidence:  body.Confidence,
		Tags:        body.Tags,
		Source:      body.Source,
		FirstSeen:   body.FirstSeen,
		LastSeen:    body.LastSeen,
	}
}

func convertEnum[T ~string, D ~string](value *T) *D {
	if value == nil {
		return nil
	}
	converted := D(*value)
	return &converted
}

func ptr[T any](value T) *T {
	return &value
}
