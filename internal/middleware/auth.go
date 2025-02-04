// internal/middleware/auth.go
package middleware

import (
    "context"
    "net/http"
    "strings"

    "github.com/JpCurada/golang-supabase/internal/auth"
)

func RequireAuth(jwtSecret string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }

            tokenParts := strings.Split(authHeader, " ")
            if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
                http.Error(w, "invalid token format", http.StatusUnauthorized)
                return
            }

            claims, err := auth.ValidateToken(tokenParts[1], jwtSecret)
            if err != nil {
                http.Error(w, "invalid token", http.StatusUnauthorized)
                return
            }

            ctx := context.WithValue(r.Context(), "user", claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

