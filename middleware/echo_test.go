package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/itocode21/jwtito/jwt"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestEchoMiddleware_Success(t *testing.T) {
	// Настройка Echo и middleware.
	e := echo.New()
	secretKey := "my-secret-key"
	e.Use(EchoMiddleware(secretKey))

	// Роут для тестирования.
	e.GET("/test", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "success"})
	})

	// Генерация валидного токена.
	token, err := jwt.GenerateToken(123, secretKey, time.Hour, nil)
	assert.NoError(t, err)

	// Создание запроса с валидным токеном.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	// Выполнение запроса.
	e.ServeHTTP(rec, req)

	// Проверка результата.
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "success")
}

func TestEchoMiddleware_NoToken(t *testing.T) {
	// Настройка Echo и middleware.
	e := echo.New()
	secretKey := "my-secret-key"
	e.Use(EchoMiddleware(secretKey))

	// Роут для тестирования.
	e.GET("/test", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "success"})
	})

	// Создание запроса без токена.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Выполнение запроса.
	e.ServeHTTP(rec, req)

	// Проверка результата.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Authorization header is required")
}

func TestEchoMiddleware_InvalidTokenFormat(t *testing.T) {
	// Настройка Echo и middleware.
	e := echo.New()
	secretKey := "my-secret-key"
	e.Use(EchoMiddleware(secretKey))

	// Роут для тестирования.
	e.GET("/test", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "success"})
	})

	// Создание запроса с неверным форматом токена.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "InvalidTokenFormat")
	rec := httptest.NewRecorder()

	// Выполнение запроса.
	e.ServeHTTP(rec, req)

	// Проверка результата.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid authorization header format")
}

func TestEchoMiddleware_ExpiredToken(t *testing.T) {
	// Настройка Echo и middleware.
	e := echo.New()
	secretKey := "my-secret-key"
	e.Use(EchoMiddleware(secretKey))

	// Роут для тестирования.
	e.GET("/test", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "success"})
	})

	// Генерация истёкшего токена.
	token, err := jwt.GenerateToken(123, secretKey, -time.Hour, nil)
	assert.NoError(t, err)

	// Создание запроса с истёкшим токеном.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	// Выполнение запроса.
	e.ServeHTTP(rec, req)

	// Проверка результата.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "token has expired")
}
