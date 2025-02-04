// cmd/api/main.go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/JpCurada/golang-supabase/internal/config"
    "github.com/JpCurada/golang-supabase/internal/database"
    "github.com/JpCurada/golang-supabase/internal/email"
    "github.com/JpCurada/golang-supabase/internal/handlers"
    "github.com/JpCurada/golang-supabase/internal/middleware"
    "github.com/go-chi/chi/v5"
    chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/swaggo/http-swagger"
    _ "github.com/JpCurada/golang-supabase/docs" // Import Swagger docs
	"github.com/go-chi/cors"
)





func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatal("Failed to load configuration:", err)
    }

    // Initialize database
    db, err := database.New(cfg.DatabaseURL)
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()

    // Initialize mailer
    mailer := email.NewMailer(cfg.SMTP)

    // Initialize router
    r := chi.NewRouter()

	if os.Getenv("ENV") == "production" { 
		r.Use(middleware.CSRF) // Enable CSRF only in production
	}

	// Inside main() function, before defining routes
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // Allow all origins
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"X-CSRF-Token"}, // Allow client to read CSRF token
		AllowCredentials: true,
		MaxAge:           300, // Maximum value for preflight request cache
	}))

    // Apply middleware
    r.Use(chimiddleware.Logger)
    r.Use(chimiddleware.Recoverer)

	r.Get("/swagger/*", httpSwagger.WrapHandler)

    // Initialize handlers
    authHandler := handlers.NewAuthHandler(db, mailer, cfg.JWTSecret)

    // Routes
    r.Route("/api/v1", func(r chi.Router) {
        r.Route("/auth", func(r chi.Router) {
            r.Post("/register", authHandler.Register)
            r.Post("/login", authHandler.Login)
            r.Get("/verify-email", authHandler.VerifyEmail)
            r.Post("/forgot-password", authHandler.ForgotPassword)
            r.Post("/reset-password", authHandler.ResetPassword)
        })

        // Protected routes
        r.Group(func(r chi.Router) {
            r.Use(middleware.RequireAuth(cfg.JWTSecret))
            // Add protected routes here
        })
    })

    // Create server
    server := &http.Server{
        Addr:         ":" + cfg.Port,
        Handler:      r,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    // Start server
    go func() {
        log.Printf("Starting server on port %s\n", cfg.Port)
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatal("Server failed:", err)
        }
    }()

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Server is shutting down...")

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := server.Shutdown(ctx); err != nil {
        log.Fatal("Server forced to shutdown:", err)
    }

    log.Println("Server exited properly")
}