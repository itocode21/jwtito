package middleware

import (
	"net/http"
	"strings"

	"github.com/itocode21/jwtito/jwt"
	"github.com/labstack/echo/v4"
)

func EchoMiddleware(secretKey string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Получаем заголовок Authorization
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Authorization header is required"})
			}

			// Проверяем формат заголовка (Bearer <token>)
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid authorization header format"})
			}

			// Парсим токен
			claims, err := jwt.ParseToken(tokenParts[1], secretKey)
			if err != nil {
				switch err {
				case jwt.ErrExpiredToken:
					return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Token has expired"})
				case jwt.ErrInvalidToken:
					return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
				default:
					return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
				}
			}

			// Сохраняем данные из токена в контекст
			c.Set("user_id", claims.UserID)
			c.Set("custom_claims", claims.CustomClaims)

			// Передаем управление следующему обработчику
			return next(c)
		}
	}
}
