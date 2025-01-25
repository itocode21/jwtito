package examples

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/itocode21/jwtito/jwt"
	"github.com/itocode21/jwtito/middleware"
)

func exam3() {
	r := gin.Default()

	secretKey := "my-secret-key"

	r.POST("/login", func(c *gin.Context) {
		userID := 123
		token, err := jwt.GenerateToken(userID, secretKey, time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	r.GET("/protected", middleware.GinMiddleware(secretKey), func(c *gin.Context) {
		userID := c.MustGet("user_id").(int)
		c.JSON(http.StatusOK, gin.H{"message": "You are authenticated", "user_id": userID})
	})

	r.Run(":8080")
}
