package jwt

import (
	"errors"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
	CustomClaims map[string]interface{} `json:"custom_claims,omitempty"`
}

func GenerateToken(userID int, secretKey string, expiresIn time.Duration, customClaims map[string]interface{}) (string, error) {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		CustomClaims: customClaims,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func ParseToken(tokenString, secretKey string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Println("Token has expired:", err)
			return nil, ErrExpiredToken
		}
		log.Println("Invalid token:", err)
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func RefreshToken(tokenString, secretKey string, expiresIn time.Duration) (string, error) {
	claims, err := ParseToken(tokenString, secretKey)
	if err != nil {
		return "", err
	}

	return GenerateToken(claims.UserID, secretKey, expiresIn, claims.CustomClaims)
}
