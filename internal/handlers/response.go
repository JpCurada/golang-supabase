// internal/handlers/response.go
package handlers

import (
    "encoding/json"
    "net/http"
)

type ErrorResponse struct {
    Error string `json:"error"`
}

func JSON(w http.ResponseWriter, status int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(data)
}

func ErrorJSON(w http.ResponseWriter, status int, message string) {
    JSON(w, status, ErrorResponse{Error: message})
}