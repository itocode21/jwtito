package echo

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/itocode21/jwtito/cmd/jwt"
	"github.com/labstack/echo/v4"
)

// Config содержит настройки для middleware.
type Config struct {
	SecretKey string        // Секретный ключ для подписи токенов
	ExpiresIn time.Duration // Время жизни токена
}

// Middleware возвращает middleware для Echo.
func Middleware(config Config) echo.MiddlewareFunc {
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
			claims, err := jwt.ParseToken(tokenParts[1], config.SecretKey)
			if err != nil {
				if errors.Is(err, jwt.ErrExpiredToken) {
					return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Token has expired"})
				}
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
			}

			// Сохраняем данные из токена в контекст
			c.Set("user_id", claims.UserID)
			c.Set("custom_claims", claims.CustomClaims)
			return next(c)
		}
	}
}

// RefreshTokenHandler обрабатывает запрос на обновление access-токена.
func RefreshTokenHandler(accessSecretKey, refreshSecretKey string) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Получаем refresh-токен из заголовка Authorization
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Authorization header is required"})
		}

		// Проверяем формат заголовка (Bearer <token>)
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid authorization header format"})
		}

		// Парсим refresh-токен
		claims, err := jwt.ParseToken(tokenParts[1], refreshSecretKey)
		if err != nil {
			if errors.Is(err, jwt.ErrExpiredToken) {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Refresh token has expired"})
			}
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid refresh token"})
		}

		// Генерируем новый access-токен
		accessToken, err := jwt.GenerateToken(claims.UserID, accessSecretKey, time.Hour, claims.CustomClaims)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate access token"})
		}

		// Возвращаем новый access-токен
		return c.JSON(http.StatusOK, map[string]string{
			"access_token": accessToken,
		})
	}
}
