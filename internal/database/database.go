// internal/database/database.go
package database

import (
    "database/sql"
    "time"
    _ "github.com/lib/pq"
)

func New(dsn string) (*sql.DB, error) {
    db, err := sql.Open("postgres", dsn)
    if err != nil {
        return nil, err
    }

    // Configure connection pool
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(25)
    db.SetConnMaxLifetime(5 * time.Minute)

    // Verify connection
    if err := db.Ping(); err != nil {
        return nil, err
    }

    return db, nil
}



