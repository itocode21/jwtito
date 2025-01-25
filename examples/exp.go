package examples

import (
	"fmt"
	"time"

	"github.com/itocode21/jwtito/jwt"
)

func exam2() {
	secretKey := "my-secret-key"
	userID := 123
	expiresIn := time.Hour

	// Генерация токена
	token, err := jwt.GenerateToken(userID, secretKey, expiresIn)
	if err != nil {
		fmt.Println("Ошибка при генерации токена:", err)
		return
	}
	fmt.Println("Сгенерированный токен:", token)

	// Парсинг токена
	claims, err := jwt.ParseToken(token, secretKey)
	if err != nil {
		fmt.Println("Ошибка при парсинге токена:", err)
		return
	}
	fmt.Printf("Данные из токена: UserID=%v, ExpiresAt=%v\n", claims.UserID, claims.ExpiresAt)
}
