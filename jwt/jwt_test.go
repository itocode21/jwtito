package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAndParseToken(t *testing.T) {
	secretKey := "my-secret-key"
	userID := 123
	customClaims := map[string]interface{}{
		"role":  "admin",
		"email": "user@example.com",
	}

	// Генерация токена.
	token, err := GenerateToken(userID, secretKey, time.Hour, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Парсинг токена.
	claims, err := ParseToken(token, secretKey)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "admin", claims.CustomClaims["role"])
	assert.Equal(t, "user@example.com", claims.CustomClaims["email"])
}

func TestExpiredToken(t *testing.T) {
	secretKey := "my-secret-key"
	userID := 123
	customClaims := map[string]interface{}{
		"role":  "admin",
		"email": "user@example.com",
	}

	// Генерация истёкшего токена.
	token, err := GenerateToken(userID, secretKey, -time.Hour, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Парсинг токена.
	_, err = ParseToken(token, secretKey)
	assert.Equal(t, ErrExpiredToken, err)
}

func TestInvalidToken(t *testing.T) {
	secretKey := "my-secret-key"
	invalidToken := "invalid.token.here"

	// Парсинг невалидного токена.
	_, err := ParseToken(invalidToken, secretKey)
	assert.Equal(t, ErrInvalidToken, err)
}
