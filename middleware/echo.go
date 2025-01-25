package middleware

import (
	"net/http"
	"strings"

	"github.com/itocode21/jwtito/jwt"
	"github.com/labstack/echo/v4"
)

// EchoMiddleware возвращает middleware для Echo, которое проверяет JWT токен.
func EchoMiddleware(secretKey string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Authorization header is required"})
			}

			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid authorization header format"})
			}

			claims, err := jwt.ParseToken(tokenParts[1], secretKey)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
			}

			c.Set("user_id", claims.UserID)
			return next(c)
		}
	}
}
