package gin

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/itocode21/jwtito/jwt"
)

// Config содержит настройки для middleware.
type Config struct {
	SecretKey string        // Секретный ключ для подписи токенов
	ExpiresIn time.Duration // Время жизни токена
}

// Middleware возвращает middleware для Gin.
func Middleware(config Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Получаем заголовок Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		// Проверяем формат заголовка (Bearer <token>)
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			return
		}

		// Парсим токен
		claims, err := jwt.ParseToken(tokenParts[1], config.SecretKey)
		if err != nil {
			if errors.Is(err, jwt.ErrExpiredToken) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Сохраняем данные из токена в контекст
		c.Set("user_id", claims.UserID)
		c.Set("custom_claims", claims.CustomClaims)
		c.Next()
	}
}
