// internal/middleware/csrf.go
package middleware

import (
    "crypto/rand"
    "encoding/base64"
    "net/http"
    "sync"
    "time"
)

var csrfTokens sync.Map

func CSRF(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            token := generateCSRFToken()
            csrfTokens.Store(token, time.Now().Add(24*time.Hour))
            w.Header().Set("X-CSRF-Token", token)
            next.ServeHTTP(w, r)
            return
        }

        token := r.Header.Get("X-CSRF-Token")
        if token == "" {
            http.Error(w, "missing CSRF token", http.StatusForbidden)
            return
        }

        if !validateCSRFToken(token) {
            http.Error(w, "invalid CSRF token", http.StatusForbidden)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func generateCSRFToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

func validateCSRFToken(token string) bool {
    expiryTime, exists := csrfTokens.Load(token)
    if !exists {
        return false
    }

    if time.Now().After(expiryTime.(time.Time)) {
        csrfTokens.Delete(token)
        return false
    }

    return true
}