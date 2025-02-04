// internal/handlers/auth.go
package handlers

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "time"

    "github.com/JpCurada/golang-supabase/internal/auth"
    "github.com/JpCurada/golang-supabase/internal/email"
    "github.com/JpCurada/golang-supabase/internal/models"
    "github.com/go-playground/validator/v10"
    "github.com/google/uuid"
)

type AuthHandler struct {
    db        *sql.DB
    mailer    *email.Mailer
    validate  *validator.Validate
    jwtSecret string
}

func NewAuthHandler(db *sql.DB, mailer *email.Mailer, jwtSecret string) *AuthHandler {
    return &AuthHandler{
        db:        db,
        mailer:    mailer,
        validate:  validator.New(),
        jwtSecret: jwtSecret,
    }
}

// Register a new user
// @Summary Register a new user
// @Description Register a new user with email, password, and details
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "User registration payload"
// @Success 201 {object} models.AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
    var input models.RegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        ErrorJSON(w, http.StatusBadRequest, "Invalid request payload")
        return
    }

    if err := h.validate.Struct(input); err != nil {
        ErrorJSON(w, http.StatusBadRequest, "Validation failed")
        return
    }

    // Start transaction
    tx, err := h.db.Begin()
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }
    defer tx.Rollback()

    // Check if email exists
    var exists bool
    err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM user_credentials WHERE email = $1)", input.Email).Scan(&exists)
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }
    if exists {
        ErrorJSON(w, http.StatusConflict, "Email already registered")
        return
    }

    // Hash password
    hashedPassword, err := auth.HashPassword(input.Password)
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Error processing password")
        return
    }

    // Generate verification token
    verificationToken := uuid.New()
    expiresAt := time.Now().Add(24 * time.Hour)

    // Create user credentials
    var credentialID string
    err = tx.QueryRow(`
        INSERT INTO user_credentials (email, password_hash, verification_token, verification_token_expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id
    `, input.Email, hashedPassword, verificationToken, expiresAt).Scan(&credentialID)
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Error creating user")
        return
    }

    // Create user profile
    var userID string
    err = tx.QueryRow(`
        INSERT INTO users (credential_id, first_name, last_name, student_number, accepted_privacy_policy)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
    `, credentialID, input.FirstName, input.LastName, input.StudentNumber, input.AcceptPrivacyPolicy).Scan(&userID)
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Error creating user profile")
        return
    }

    if err = tx.Commit(); err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Error completing registration")
        return
    }

    // Send verification email
    go h.mailer.SendVerificationEmail(input.Email, input.FirstName, verificationToken.String())

    JSON(w, http.StatusCreated, models.AuthResponse{
        User: &models.User{
            ID:           userID,
            FirstName:    input.FirstName,
            LastName:     input.LastName,
            StudentNumber: input.StudentNumber,
            Email:        input.Email,
        },
    })
}


// @Summary Login user
// @Description Authenticate user and return JWT token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "User login payload"
// @Success 200 {object} models.AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    var input models.LoginRequest
    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        ErrorJSON(w, http.StatusBadRequest, "Invalid request payload")
        return
    }

    if err := h.validate.Struct(input); err != nil {
        ErrorJSON(w, http.StatusBadRequest, "Validation failed")
        return
    }

    var user models.User
    var hashedPassword []byte

    err := h.db.QueryRow(`
        SELECT u.id, u.first_name, u.last_name, u.student_number, 
               uc.email, uc.password_hash, uc.email_verified
        FROM users u
        JOIN user_credentials uc ON u.credential_id = uc.id
        WHERE uc.email = $1
    `, input.Email).Scan(
        &user.ID, &user.FirstName, &user.LastName, &user.StudentNumber,
        &user.Email, &hashedPassword, &user.EmailVerified,
    )

    if err == sql.ErrNoRows {
        ErrorJSON(w, http.StatusUnauthorized, "Invalid credentials")
        return
    }
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }

    if err := auth.ComparePasswords(hashedPassword, input.Password); err != nil {
        ErrorJSON(w, http.StatusUnauthorized, "Invalid credentials")
        return
    }

    if !user.EmailVerified {
        ErrorJSON(w, http.StatusForbidden, "Email not verified")
        return
    }

    // Generate JWT token
    token, err := auth.GenerateToken(user.ID, user.Email, h.jwtSecret)
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Error generating token")
        return
    }

    JSON(w, http.StatusOK, models.AuthResponse{
        User:  &user,
        Token: token,
    })
}

// @Summary Verify email
// @Description Verify user email via token
// @Tags auth
// @Accept json
// @Produce json
// @Param token query string true "Verification token"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/verify-email [get]
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    if token == "" {
        ErrorJSON(w, http.StatusBadRequest, "Missing verification token")
        return
    }

    result, err := h.db.Exec(`
        UPDATE user_credentials 
        SET email_verified = true, 
            verification_token = NULL, 
            verification_token_expires_at = NULL
        WHERE verification_token = $1 
        AND verification_token_expires_at > NOW()
    `, token)

    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }

    rows, err := result.RowsAffected()
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }

    if rows == 0 {
        ErrorJSON(w, http.StatusBadRequest, "Invalid or expired verification token")
        return
    }

    JSON(w, http.StatusOK, map[string]string{"message": "Email verified successfully"})
}

// @Summary Request password reset
// @Description Send password reset link to email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.PasswordResetRequest true "Password reset request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
    var input struct {
        Email string `json:"email" validate:"required,email"`
    }

    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        ErrorJSON(w, http.StatusBadRequest, "Invalid request payload")
        return
    }

    if err := h.validate.Struct(input); err != nil {
        ErrorJSON(w, http.StatusBadRequest, "Validation failed")
        return
    }

    resetToken := uuid.New()
    expiresAt := time.Now().Add(1 * time.Hour)

    // Get user's name first
    var firstName string
    err := h.db.QueryRow(`
        SELECT u.first_name
        FROM users u
        JOIN user_credentials uc ON u.credential_id = uc.id
        WHERE uc.email = $1
    `, input.Email).Scan(&firstName)

    if err != nil && err != sql.ErrNoRows {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }

    result, err := h.db.Exec(`
        UPDATE user_credentials 
        SET reset_token = $1, 
            reset_token_expires_at = $2
        WHERE email = $3
    `, resetToken, expiresAt, input.Email)

    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }

    rowsAffected, err := result.RowsAffected()
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }

    if rowsAffected > 0 {
        // Pass the first name to the email function
        go h.mailer.SendPasswordResetEmail(input.Email, firstName, resetToken.String())
    }

    // Always return success to prevent email enumeration
    JSON(w, http.StatusOK, map[string]string{
        "message": "If an account exists with that email, a password reset link has been sent",
    })
}

// @Summary Reset user password
// @Description Reset password using provided token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.PasswordUpdateRequest true "Password reset payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/reset-password [post]
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
    var input struct {
        Token           string `json:"token" validate:"required"`
        Password        string `json:"password" validate:"required,min=8"`
        ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=Password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        ErrorJSON(w, http.StatusBadRequest, "Invalid request payload")
        return
    }

    if err := h.validate.Struct(input); err != nil {
        ErrorJSON(w, http.StatusBadRequest, "Validation failed")
        return
    }

    hashedPassword, err := auth.HashPassword(input.Password)
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Error processing password")
        return
    }

    tx, err := h.db.Begin()
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }
    defer tx.Rollback()

    result, err := tx.Exec(`
        UPDATE user_credentials 
        SET password_hash = $1,
            reset_token = NULL,
            reset_token_expires_at = NULL
        WHERE reset_token = $2
        AND reset_token_expires_at > NOW()
    `, hashedPassword, input.Token)

    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }

    rowsAffected, err := result.RowsAffected()
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }

    if rowsAffected == 0 {
        ErrorJSON(w, http.StatusBadRequest, "Invalid or expired reset token")
        return
    }

    if err = tx.Commit(); err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }

    JSON(w, http.StatusOK, map[string]string{
        "message": "Password has been reset successfully",
    })
}