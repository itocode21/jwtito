package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAndParseToken(t *testing.T) {
	secretKey := "my-secret-key"
	userID := 123
	expiresIn := time.Hour

	token, err := GenerateToken(userID, secretKey, expiresIn)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := ParseToken(token, secretKey)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
}

func TestExpiredToken(t *testing.T) {
	secretKey := "my-secret-key"
	userID := 123
	expiresIn := -time.Hour

	token, err := GenerateToken(userID, secretKey, expiresIn)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	_, err = ParseToken(token, secretKey)
	assert.Equal(t, ErrExpiredToken, err)
}
