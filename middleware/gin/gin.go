package gin

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/itocode21/jwtito/jwt"
)

// Config содержит конфигурацию для middleware.
type Config struct {
	SecretKey string
	ExpiresIn time.Duration
}

// Middleware проверяет access-токен и добавляет claims в контекст.
func Middleware(config Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Проверяем формат токена (должен быть "Bearer <token>")
		parts := strings.Split(tokenString, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		// Парсим токен
		claims, err := jwt.ParseToken(parts[1], config.SecretKey)
		if err != nil {
			if errors.Is(err, jwt.ErrExpiredToken) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			}
			c.Abort()
			return
		}

		// Добавляем claims в контекст
		c.Set("user_id", claims.UserID)
		c.Set("custom_claims", claims.CustomClaims)

		c.Next()
	}
}

// RefreshTokenHandler обрабатывает запрос на обновление access-токена.
func RefreshTokenHandler(accessSecretKey, refreshSecretKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		// Проверяем формат токена (должен быть "Bearer <token>")
		parts := strings.Split(tokenString, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			return
		}

		// Парсим refresh-токен
		claims, err := jwt.ParseToken(parts[1], refreshSecretKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
			return
		}

		// Генерируем новый access-токен
		accessToken, err := jwt.GenerateToken(claims.UserID, accessSecretKey, time.Hour, claims.CustomClaims)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token": accessToken,
		})
	}
}
