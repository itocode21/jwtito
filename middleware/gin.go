package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/itocode21/jwtito/jwt"
)

func GinMiddleware(secretKey string) gin.HandlerFunc {
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
		claims, err := jwt.ParseToken(tokenParts[1], secretKey)
		if err != nil {
			switch err {
			case jwt.ErrExpiredToken:
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
			case jwt.ErrInvalidToken:
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			default:
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			}
			return
		}

		// Сохраняем данные из токена в контекст
		c.Set("user_id", claims.UserID)
		c.Set("custom_claims", claims.CustomClaims)

		// Передаем управление следующему обработчику
		c.Next()
	}
}
