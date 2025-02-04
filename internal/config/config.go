// internal/config/config.go
package config

import (
    "errors"
    "os"

    "github.com/joho/godotenv"
)

type Config struct {
    Port        string
    DatabaseURL string
    JWTSecret   string
    SMTP        SMTPConfig
}

type SMTPConfig struct {
    Host     string
    Port     string
    Username string
    Password string
    From     string
}

func Load() (*Config, error) {
    if err := godotenv.Load(); err != nil {
        return nil, errors.New("error loading .env file")
    }

    config := &Config{
        Port:        getEnv("PORT", "8080"),
        DatabaseURL: os.Getenv("DATABASE_URL"),
        JWTSecret:   os.Getenv("JWT_SECRET"),
        SMTP: SMTPConfig{
            Host:     os.Getenv("SMTP_HOST"),
            Port:     os.Getenv("SMTP_PORT"),
            Username: os.Getenv("SMTP_USERNAME"),
            Password: os.Getenv("SMTP_PASSWORD"),
            From:     os.Getenv("SMTP_FROM"),
        },
    }

    if config.DatabaseURL == "" {
        return nil, errors.New("DATABASE_URL is required")
    }

    if config.JWTSecret == "" {
        return nil, errors.New("JWT_SECRET is required")
    }

    return config, nil
}

func getEnv(key, fallback string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return fallback
}

