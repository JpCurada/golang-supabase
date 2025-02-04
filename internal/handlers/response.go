// internal/handlers/response.go
package handlers
	
import (
	"encoding/json"
	"net/http"
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// JSON writes a JSON response with given status code and data
func JSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}

// ErrorJSON writes a JSON error response with given status code and message
func ErrorJSON(w http.ResponseWriter, status int, message string) {
	JSON(w, status, ErrorResponse{Error: message})
}