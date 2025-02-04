// internal/models/auth.go
package models

type RegisterRequest struct {
    FirstName           string `json:"first_name" validate:"required"`
    LastName            string `json:"last_name" validate:"required"`
    StudentNumber       string `json:"student_number" validate:"required"`
    Email               string `json:"email" validate:"required,email"`
    Password           string `json:"password" validate:"required,min=8"`
    ConfirmPassword    string `json:"confirm_password" validate:"required,eqfield=Password"`
    AcceptPrivacyPolicy bool   `json:"accept_privacy_policy" validate:"required,eq=true"`
}

type LoginRequest struct {
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required"`
}

type AuthResponse struct {
    User  *User  `json:"user"`
    Token string `json:"token,omitempty"`
}

type PasswordResetRequest struct {
    Email string `json:"email" validate:"required,email"`
}

type PasswordUpdateRequest struct {
    Token           string `json:"token" validate:"required"`
    NewPassword     string `json:"new_password" validate:"required,min=8"`
    ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword"`
}