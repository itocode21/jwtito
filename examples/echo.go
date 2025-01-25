package examples

import (
	"net/http"
	"time"

	"github.com/itocode21/jwtito/jwt"
	"github.com/itocode21/jwtito/middleware"
	"github.com/labstack/echo/v4"
)

func exam() {
	e := echo.New()

	// Секретный ключ для подписи токенов.
	secretKey := "my-secret-key"

	// Роут для генерации токена.
	e.POST("/login", func(c echo.Context) error {
		userID := 123
		token, err := jwt.GenerateToken(userID, secretKey, time.Hour)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
		}
		return c.JSON(http.StatusOK, map[string]string{"token": token})
	})

	// Группа защищённых роутов.
	protectedGroup := e.Group("/protected")
	protectedGroup.Use(middleware.EchoMiddleware(secretKey)) // Применяем middleware ко всей группе.

	// Защищённый роут.
	protectedGroup.GET("", func(c echo.Context) error {
		userID := c.Get("user_id").(int)
		return c.JSON(http.StatusOK, map[string]interface{}{"message": "You are authenticated", "user_id": userID})
	})

	// Запуск сервера.
	e.Start(":8080")
}
