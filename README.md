# JWTito

## Current Version: v0.1.0
[![Release](https://img.shields.io/badge/release-v0.1.0-blue.svg)](https://github.com/itocode21/jwtito/releases/tag/v0.1.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/itocode21/jwtito)](https://goreportcard.com/report/github.com/itocode21/jwtito)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/itocode21/jwtito/blob/main/LICENSE)

JWTito is a simple yet powerful library for working with JWT (JSON Web Tokens) in Go. It provides convenient tools for generating, parsing, and validating tokens, as well as middleware for popular frameworks like Gin and Echo.

## **Features**

- 🛠️ **Token Generation**:
  - Access tokens with customizable expiration.
  - Refresh tokens for renewing access tokens.
  - Support for custom claims (e.g., roles, email, etc.).

- 🔒 **Token Parsing and Validation**:
  - Expiration check for tokens.
  - Error handling (expired tokens, invalid tokens, etc.).

- 🚀 **Middleware for Gin and Echo**:
  - Easy integration with popular frameworks.
  - Support for refresh tokens to renew access tokens.

- ✅ **Comprehensive Test Coverage**:
  - Tests for all major use cases.
  - Tests for error handling.

## **Installation**

To install the library, use the following command:

```bash
go get github.com/itocode21/jwtito
```

# Usage 

## Token Generation
```
package main
import (
	"fmt"
	"time"
	"github.com/itocode21/jwtito/jwt"
)
func main() {
	accessSecretKey := "your-access-secret-key"
	refreshSecretKey := "your-refresh-secret-key"
	// Generate an access token
	accessToken, err := jwt.GenerateToken(123, accessSecretKey, time.Hour, map[string]interface{}{
		"role": "admin",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("Access Token:", accessToken)
	// Generate a refresh token
	refreshToken, err := jwt.GenerateRefreshToken(123, refreshSecretKey, time.Hour*24*7)
	if err != nil {
		panic(err)
	}
	fmt.Println("Refresh Token:", refreshToken)
}
```
## Middleware for Gin
```
package main
import (
	"github.com/gin-gonic/gin"
	"github.com/itocode21/jwtito/middleware/gin"
)
func main() {
	r := gin.Default()
	accessSecretKey := "your-access-secret-key"
	refreshSecretKey := "your-refresh-secret-key"
	// Middleware for access token validation
	r.Use(ginjwt.Middleware(ginjwt.Config{
		SecretKey: accessSecretKey,
		ExpiresIn: time.Hour,
	}))
	// Endpoint to refresh access tokens
	r.POST("/refresh", ginjwt.RefreshTokenHandler(accessSecretKey, refreshSecretKey))
	// Protected endpoint
	r.GET("/protected", func(c *gin.Context) {
		userID := c.MustGet("user_id").(int)
		c.JSON(http.StatusOK, gin.H{
			"message": "You are authenticated!",
			"user_id": userID,
		})
	})
	r.Run(":8080")
}
```

## Middleware for Echo
```
package main
import (
	"github.com/labstack/echo/v4"
	"github.com/itocode21/jwtito/middleware/echo"
)
func main() {
	e := echo.New()
	accessSecretKey := "your-access-secret-key"
	refreshSecretKey := "your-refresh-secret-key"
	// Middleware for access token validation
	e.Use(echojwt.Middleware(echojwt.Config{
		SecretKey: accessSecretKey,
		ExpiresIn: time.Hour,
	}))
	// Endpoint to refresh access tokens
	e.POST("/refresh", echojwt.RefreshTokenHandler(accessSecretKey, refreshSecretKey))
	// Protected endpoint
	e.GET("/protected", func(c echo.Context) error {
		userID := c.Get("user_id").(int)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "You are authenticated!",
			"user_id": userID,
		})
	})
	e.Start(":8080")
}
```
# **Advantages**

* 🚀 Ease of Use: The library provides a simple and intuitive API.
* 🔒 Security: Supports token expiration checks and error handling.
* 🛠️ Flexibility: Allows adding custom claims and configuring token expiration.
* 🧪 Reliability: Comprehensive test coverage for all major scenarios.

# **Future Features**
* Support for Other Signing Algorithms: Adding support for RS256 and other algorithms.
* OAuth2 Support: Integration with OAuth2 providers (Google, GitHub, etc.).

# License
This project is licensed under the MIT License. See the LICENSE file for details.
