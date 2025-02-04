// internal/models/user.go
package models

import (
    "time"
)

type User struct {
    ID                  string    `json:"id"`
    FirstName           string    `json:"first_name"`
    LastName            string    `json:"last_name"`
    StudentNumber       string    `json:"student_number"`
    Email               string    `json:"email"`
    PasswordHash        []byte    `json:"-"`
    EmailVerified       bool      `json:"email_verified"`
    VerificationToken   *string   `json:"-"`
    ResetToken         *string   `json:"-"`
    CreatedAt          time.Time `json:"created_at"`
    UpdatedAt          time.Time `json:"updated_at"`
}