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

	token, err := GenerateToken(userID, secretKey, time.Hour, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

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

	token, err := GenerateToken(userID, secretKey, -time.Hour, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	_, err = ParseToken(token, secretKey)
	assert.Equal(t, ErrExpiredToken, err)
}

func TestInvalidToken(t *testing.T) {
	secretKey := "my-secret-key"
	invalidToken := "invalid.token.here"

	_, err := ParseToken(invalidToken, secretKey)
	assert.Equal(t, ErrInvalidToken, err)
}

func TestRefreshToken(t *testing.T) {
	secretKey := "my-secret-key"
	userID := 123
	customClaims := map[string]interface{}{
		"role":  "admin",
		"email": "user@example.com",
	}

	// Генерация токена с коротким сроком действия
	token, err := GenerateToken(userID, secretKey, time.Minute, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Обновление токена
	newToken, err := RefreshToken(token, secretKey, time.Hour)
	assert.NoError(t, err)
	assert.NotEmpty(t, newToken)

	// Проверка нового токена
	claims, err := ParseToken(newToken, secretKey)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "admin", claims.CustomClaims["role"])
	assert.Equal(t, "user@example.com", claims.CustomClaims["email"])
}

func TestRefreshExpiredToken(t *testing.T) {
	secretKey := "my-secret-key"
	userID := 123
	customClaims := map[string]interface{}{
		"role":  "admin",
		"email": "user@example.com",
	}

	// Генерация токена с истекшим сроком действия
	token, err := GenerateToken(userID, secretKey, -time.Minute, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Попытка обновить истекший токен
	_, err = RefreshToken(token, secretKey, time.Hour)
	assert.Equal(t, ErrExpiredToken, err)
}
