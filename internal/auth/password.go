// internal/auth/password.go
package auth

import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) ([]byte, error) {
    return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func ComparePasswords(hashedPassword []byte, plainPassword string) error {
    return bcrypt.CompareHashAndPassword(hashedPassword, []byte(plainPassword))
}