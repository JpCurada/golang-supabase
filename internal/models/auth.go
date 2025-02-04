// internal/models/auth.go
package models

// RegisterRequest defines the body for user registration
type RegisterRequest struct {
    FirstName           string `json:"first_name" validate:"required" example:"John"`
    LastName            string `json:"last_name" validate:"required" example:"Doe"`
    StudentNumber       string `json:"student_number" validate:"required" example:"2020-12345"`
    Email              string `json:"email" validate:"required,email" example:"john.doe@example.com"`
    Password           string `json:"password" validate:"required,min=8" example:"SecurePass123!"`
    ConfirmPassword    string `json:"confirm_password" validate:"required,eqfield=Password" example:"SecurePass123!"`
    AcceptPrivacyPolicy bool   `json:"accept_privacy_policy" validate:"required,eq=true"`
}

// LoginRequest defines the body for user login
type LoginRequest struct {
    Email    string `json:"email" validate:"required,email" example:"john.doe@example.com"`
    Password string `json:"password" validate:"required" example:"SecurePass123!"`
}

// AuthResponse defines the response for successful auth operations
type AuthResponse struct {
    User  *User  `json:"user"`
    Token string `json:"token,omitempty"`
}

// PasswordResetRequest defines the body for requesting a password reset
type PasswordResetRequest struct {
    Email string `json:"email" validate:"required,email" example:"john.doe@example.com"`
}

// PasswordUpdateRequest defines the body for resetting the password
type PasswordUpdateRequest struct {
    Token           string `json:"token" validate:"required" example:"550e8400-e29b-41d4-a716-446655440000"`
    NewPassword     string `json:"new_password" validate:"required,min=8" example:"NewSecurePass123!"`
    ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword" example:"NewSecurePass123!"`
}

// SuccessResponse defines a generic success response
type SuccessResponse struct {
    Message string `json:"message"`
}