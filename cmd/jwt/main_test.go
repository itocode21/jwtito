package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateToken(t *testing.T) {
	secretKey := "my-secret-key"
	userID := 123
	customClaims := map[string]interface{}{
		"role":  "admin",
		"email": "user@example.com",
	}

	// Генерация токена
	token, err := GenerateToken(userID, secretKey, time.Hour, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestParseToken_ValidToken(t *testing.T) {
	secretKey := "my-secret-key"
	userID := 123
	customClaims := map[string]interface{}{
		"role":  "admin",
		"email": "user@example.com",
	}

	// Генерация токена
	token, err := GenerateToken(userID, secretKey, time.Hour, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Парсинг токена
	claims, err := ParseToken(token, secretKey)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "admin", claims.CustomClaims["role"])
	assert.Equal(t, "user@example.com", claims.CustomClaims["email"])
}

func TestParseToken_ExpiredToken(t *testing.T) {
	secretKey := "my-secret-key"
	userID := 123
	customClaims := map[string]interface{}{
		"role":  "admin",
		"email": "user@example.com",
	}

	// Генерация токена с истекшим сроком действия
	token, err := GenerateToken(userID, secretKey, -time.Hour, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Парсинг истекшего токена
	claims, err := ParseToken(token, secretKey)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Equal(t, ErrExpiredToken, err)
}

func TestParseToken_InvalidToken(t *testing.T) {
	secretKey := "my-secret-key"
	invalidToken := "invalid.token.here"

	// Парсинг невалидного токена
	claims, err := ParseToken(invalidToken, secretKey)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Equal(t, ErrInvalidToken, err)
}

func TestParseToken_InvalidSecretKey(t *testing.T) {
	secretKey := "my-secret-key"
	userID := 123
	customClaims := map[string]interface{}{
		"role":  "admin",
		"email": "user@example.com",
	}

	// Генерация токена
	token, err := GenerateToken(userID, secretKey, time.Hour, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Парсинг токена с неверным секретным ключом
	claims, err := ParseToken(token, "wrong-secret-key")
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Equal(t, ErrInvalidToken, err)
}

// Новые тесты для refresh-токенов

func TestGenerateRefreshToken(t *testing.T) {
	secretKey := "my-refresh-secret-key"
	userID := 123

	// Генерация refresh-токена
	refreshToken, err := GenerateRefreshToken(userID, secretKey, time.Hour*24*7) // 7 дней
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
}

func TestParseRefreshToken_ValidToken(t *testing.T) {
	secretKey := "my-refresh-secret-key"
	userID := 123

	// Генерация refresh-токена
	refreshToken, err := GenerateRefreshToken(userID, secretKey, time.Hour*24*7)
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	// Парсинг refresh-токена
	claims, err := ParseToken(refreshToken, secretKey)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
}

func TestParseRefreshToken_ExpiredToken(t *testing.T) {
	secretKey := "my-refresh-secret-key"
	userID := 123

	// Генерация refresh-токена с истекшим сроком действия
	refreshToken, err := GenerateRefreshToken(userID, secretKey, -time.Hour)
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	// Парсинг истекшего refresh-токена
	claims, err := ParseToken(refreshToken, secretKey)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Equal(t, ErrExpiredToken, err)
}

func TestParseRefreshToken_InvalidToken(t *testing.T) {
	secretKey := "my-refresh-secret-key"
	invalidToken := "invalid.refresh.token.here"

	// Парсинг невалидного refresh-токена
	claims, err := ParseToken(invalidToken, secretKey)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Equal(t, ErrInvalidToken, err)
}

func TestParseRefreshToken_InvalidSecretKey(t *testing.T) {
	secretKey := "my-refresh-secret-key"
	userID := 123

	// Генерация refresh-токена
	refreshToken, err := GenerateRefreshToken(userID, secretKey, time.Hour*24*7)
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	// Парсинг refresh-токена с неверным секретным ключом
	claims, err := ParseToken(refreshToken, "wrong-refresh-secret-key")
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Equal(t, ErrInvalidToken, err)
}
