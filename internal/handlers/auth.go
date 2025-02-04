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

// Register godoc
// @Summary Register new user
// @Description Register a new user with email verification
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "Registration credentials"
// @Success 201 {object} models.AuthResponse "Successfully registered"
// @Failure 400 {object} ErrorResponse "Invalid input"
// @Failure 409 {object} ErrorResponse "Email already exists"
// @Failure 500 {object} ErrorResponse "Server error"
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

    tx, err := h.db.Begin()
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Database error")
        return
    }
    defer tx.Rollback()

    // Check for existing email
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

    // Send verification email asynchronously
    go h.mailer.SendVerificationEmail(input.Email, input.FirstName, verificationToken.String())

    // Generate initial JWT token
    token, err := auth.GenerateToken(userID, input.Email, h.jwtSecret)
    if err != nil {
        ErrorJSON(w, http.StatusInternalServerError, "Error generating token")
        return
    }

    JSON(w, http.StatusCreated, models.AuthResponse{
        User: &models.User{
            ID:            userID,
            FirstName:     input.FirstName,
            LastName:      input.LastName,
            StudentNumber: input.StudentNumber,
            Email:         input.Email,
            EmailVerified: false,
        },
        Token: token,
    })
}

// Login godoc
// @Summary Authenticate user
// @Description Authenticate user and return JWT token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.AuthResponse "Successfully authenticated"
// @Failure 400 {object} ErrorResponse "Invalid input"
// @Failure 401 {object} ErrorResponse "Invalid credentials"
// @Failure 403 {object} ErrorResponse "Email not verified"
// @Failure 500 {object} ErrorResponse "Server error"
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

// VerifyEmail godoc
// @Summary Verify email address
// @Description Verify user's email address using verification token
// @Tags auth
// @Accept json
// @Produce json
// @Param token query string true "Verification token" Format(uuid)
// @Success 200 {object} models.SuccessResponse "Email verified"
// @Failure 400 {object} ErrorResponse "Invalid token"
// @Failure 500 {object} ErrorResponse "Server error"
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

    JSON(w, http.StatusOK, models.SuccessResponse{
        Message: "Email verified successfully",
    })
}

// ForgotPassword godoc
// @Summary Request password reset
// @Description Send password reset link to user's email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.PasswordResetRequest true "Password reset request"
// @Success 200 {object} models.SuccessResponse "Reset email sent"
// @Failure 400 {object} ErrorResponse "Invalid input"
// @Failure 500 {object} ErrorResponse "Server error"
// @Router /api/v1/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
    var input models.PasswordResetRequest
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
        go h.mailer.SendPasswordResetEmail(input.Email, firstName, resetToken.String())
    }

    JSON(w, http.StatusOK, models.SuccessResponse{
        Message: "If an account exists with that email, a password reset link has been sent",
    })
}

// ResetPassword godoc
// @Summary Reset password
// @Description Reset user's password using reset token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.PasswordUpdateRequest true "Password update request"
// @Success 200 {object} models.SuccessResponse "Password reset successful"
// @Failure 400 {object} ErrorResponse "Invalid input or token"
// @Failure 500 {object} ErrorResponse "Server error"
// @Router /api/v1/auth/reset-password [post]
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
    var input models.PasswordUpdateRequest
    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        ErrorJSON(w, http.StatusBadRequest, "Invalid request payload")
        return
    }

    if err := h.validate.Struct(input); err != nil {
        ErrorJSON(w, http.StatusBadRequest, "Validation failed")
        return
    }

    hashedPassword, err := auth.HashPassword(input.NewPassword)
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
	
		JSON(w, http.StatusOK, models.SuccessResponse{
			Message: "Password has been reset successfully",
		})
	}
	
	