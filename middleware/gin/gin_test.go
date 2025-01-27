package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/itocode21/jwtito/cmd/jwt"
	"github.com/stretchr/testify/assert"
)

func TestGinMiddleware_Success(t *testing.T) {
	// Инициализация Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	secretKey := "my-secret-key"
	config := Config{
		SecretKey: secretKey,
		ExpiresIn: time.Hour,
	}
	r.Use(Middleware(config))

	// Тестовый маршрут
	r.GET("/test", func(c *gin.Context) {
		userID := c.MustGet("user_id").(int)
		customClaims := c.MustGet("custom_claims").(map[string]interface{})
		c.JSON(http.StatusOK, gin.H{
			"message":       "success",
			"user_id":       userID,
			"custom_claims": customClaims,
		})
	})

	// Генерация токена с кастомными claims
	customClaims := map[string]interface{}{
		"role":  "admin",
		"email": "user@example.com",
	}
	token, err := jwt.GenerateToken(123, secretKey, time.Hour, customClaims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Создаем запрос с валидным токеном
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	// Выполняем запрос
	r.ServeHTTP(rec, req)

	// Проверяем ответ
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{
		"message": "success",
		"user_id": 123,
		"custom_claims": {
			"role": "admin",
			"email": "user@example.com"
		}
	}`, rec.Body.String())
}

func TestGinMiddleware_NoToken(t *testing.T) {
	// Инициализация Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	secretKey := "my-secret-key"
	config := Config{
		SecretKey: secretKey,
		ExpiresIn: time.Hour,
	}
	r.Use(Middleware(config))

	// Тестовый маршрут
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Создаем запрос без токена
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Выполняем запрос
	r.ServeHTTP(rec, req)

	// Проверяем ответ
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"Authorization header is required"}`, rec.Body.String())
}

func TestGinMiddleware_InvalidTokenFormat(t *testing.T) {
	// Инициализация Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	secretKey := "my-secret-key"
	config := Config{
		SecretKey: secretKey,
		ExpiresIn: time.Hour,
	}
	r.Use(Middleware(config))

	// Тестовый маршрут
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Создаем запрос с некорректным форматом токена
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "InvalidTokenFormat")
	rec := httptest.NewRecorder()

	// Выполняем запрос
	r.ServeHTTP(rec, req)

	// Проверяем ответ
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"Invalid authorization header format"}`, rec.Body.String())
}

func TestGinMiddleware_ExpiredToken(t *testing.T) {
	// Инициализация Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	secretKey := "my-secret-key"
	config := Config{
		SecretKey: secretKey,
		ExpiresIn: time.Hour,
	}
	r.Use(Middleware(config))

	// Тестовый маршрут
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Генерация токена с истекшим сроком действия
	token, err := jwt.GenerateToken(123, secretKey, -time.Hour, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Создаем запрос с истекшим токеном
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	// Выполняем запрос
	r.ServeHTTP(rec, req)

	// Проверяем ответ
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"Token has expired"}`, rec.Body.String())
}

func TestGinMiddleware_InvalidToken(t *testing.T) {
	// Инициализация Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	secretKey := "my-secret-key"
	config := Config{
		SecretKey: secretKey,
		ExpiresIn: time.Hour,
	}
	r.Use(Middleware(config))

	// Тестовый маршрут
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Создаем запрос с невалидным токеном
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rec := httptest.NewRecorder()

	// Выполняем запрос
	r.ServeHTTP(rec, req)

	// Проверяем ответ
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"Invalid token"}`, rec.Body.String())
}

// Новые тесты для refresh-токенов

func TestGinRefreshToken_Success(t *testing.T) {
	// Инициализация Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	accessSecretKey := "my-access-secret-key"
	refreshSecretKey := "my-refresh-secret-key"

	// Endpoint для обновления токена
	r.POST("/refresh", RefreshTokenHandler(accessSecretKey, refreshSecretKey))

	// Генерация refresh-токена
	refreshToken, err := jwt.GenerateRefreshToken(123, refreshSecretKey, time.Hour*24*7) // 7 дней
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	// Создаем запрос с валидным refresh-токеном
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+refreshToken)
	rec := httptest.NewRecorder()

	// Выполняем запрос
	r.ServeHTTP(rec, req)

	// Проверяем ответ
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "access_token")
}

func TestGinRefreshToken_ExpiredToken(t *testing.T) {
	// Инициализация Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	accessSecretKey := "my-access-secret-key"
	refreshSecretKey := "my-refresh-secret-key"

	// Endpoint для обновления токена
	r.POST("/refresh", RefreshTokenHandler(accessSecretKey, refreshSecretKey))

	// Генерация refresh-токена с истекшим сроком действия
	refreshToken, err := jwt.GenerateRefreshToken(123, refreshSecretKey, -time.Hour)
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	// Создаем запрос с истекшим refresh-токеном
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+refreshToken)
	rec := httptest.NewRecorder()

	// Выполняем запрос
	r.ServeHTTP(rec, req)

	// Проверяем ответ
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"Invalid refresh token"}`, rec.Body.String())
}

func TestGinRefreshToken_InvalidToken(t *testing.T) {
	// Инициализация Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	accessSecretKey := "my-access-secret-key"
	refreshSecretKey := "my-refresh-secret-key"

	// Endpoint для обновления токена
	r.POST("/refresh", RefreshTokenHandler(accessSecretKey, refreshSecretKey))

	// Создаем запрос с невалидным refresh-токеном
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.Header.Set("Authorization", "Bearer invalid.refresh.token.here")
	rec := httptest.NewRecorder()

	// Выполняем запрос
	r.ServeHTTP(rec, req)

	// Проверяем ответ
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"Invalid refresh token"}`, rec.Body.String())
}

func TestGinRefreshToken_NoToken(t *testing.T) {
	// Инициализация Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	accessSecretKey := "my-access-secret-key"
	refreshSecretKey := "my-refresh-secret-key"

	// Endpoint для обновления токена
	r.POST("/refresh", RefreshTokenHandler(accessSecretKey, refreshSecretKey))

	// Создаем запрос без токена
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rec := httptest.NewRecorder()

	// Выполняем запрос
	r.ServeHTTP(rec, req)

	// Проверяем ответ
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.JSONEq(t, `{"error":"Authorization header is required"}`, rec.Body.String())
}
