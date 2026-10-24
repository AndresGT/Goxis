package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/AndresGT/Goxis/security/token"
)

func main() {
	secret := "AB61D7F870D7F76292FA547BE0D1E23BD904B5D9376803B0E3351F657A0F11F4"
	if len(secret) < 32 {
		log.Fatal("JWT_SECRET debe tener al menos 32 bytes aleatorios; usa un secreto exclusivo de desarrollo")
	}

	jwtManager, err := token.NewJWTManager(token.JWTConfig{
		SecretKey:            []byte(secret),
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Error al configurar jwtManager: ", err)
	}

	claims := token.Claims{
		UserID: "user-123",
		Email:  "demo@example.com",
		CustomData: map[string]any{
			"displayName": "Usuario de prueba",
			"plan":        "development",
		},
	}

	// El helper crea ambos tokens con el mismo identificador de sesión.
	pair, err := jwtManager.GenerateTokenPair(claims)
	if err != nil {
		log.Fatal("Error al generar los tokens: ", err)
	}

	accessClaims, err := jwtManager.ValidateToken(pair.AccessToken)
	if err != nil {
		log.Fatal("Error al leer el access token: ", err)
	}
	refreshClaims, err := jwtManager.ValidateToken(pair.RefreshToken)
	if err != nil {
		log.Fatal("Error al leer el refresh token: ", err)
	}

	rotated, err := jwtManager.RefreshTokens(pair.RefreshToken)
	if err != nil {
		log.Fatal("Error al rotar el refresh token: ", err)
	}

	fmt.Println("Access token:")
	fmt.Println(pair.AccessToken)
	fmt.Println("\nRefresh token:")
	fmt.Println(pair.RefreshToken)
	printClaims("\nClaims del access token:", accessClaims)
	printClaims("\nClaims del refresh token:", refreshClaims)
	fmt.Printf("\nTipo access: %s | tipo refresh: %s | vence access en: %d segundos\n", accessClaims.TokenType, refreshClaims.TokenType, pair.ExpiresIn)
	fmt.Println("\nAccess token renovado:")
	fmt.Println(rotated.AccessToken)
	fmt.Println("\nRefresh token nuevo (el anterior ya fue consumido):")
	fmt.Println(rotated.RefreshToken)
}

func printClaims(label string, claims token.Claims) {
	encoded, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		log.Fatal("Error al imprimir claims: ", err)
	}
	fmt.Println(label)
	fmt.Println(string(encoded))
}
