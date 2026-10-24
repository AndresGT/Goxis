package main

import (
	"fmt"
	"log"

	goxiscrypto "github.com/AndresGT/Goxis/security/crypto"
)

func main() {
	password := "demo-password-2026"
	algorithms := []struct {
		name string
		hash func(string) (string, error)
	}{
		{"Argon2id (default)", goxiscrypto.HashPassword},
		{"bcrypt", goxiscrypto.HashWithBcrypt},
		{"scrypt", goxiscrypto.HashWithScrypt},
		{"PBKDF2-SHA256", goxiscrypto.HashWithPBKDF2},
	}
	for _, algorithm := range algorithms {
		hash, err := algorithm.hash(password)
		if err != nil {
			log.Fatalf("hash %s: %v", algorithm.name, err)
		}
		valid, err := goxiscrypto.VerifyPassword(password, hash)
		if err != nil {
			log.Fatalf("verificando %s: %v", algorithm.name, err)
		}
		fmt.Printf("%s verificado: %t\n", algorithm.name, valid)
	}

	key, err := goxiscrypto.GenerateEncryptionKey()
	if err != nil {
		log.Fatal("generando clave AES: ", err)
	}
	cipher, err := goxiscrypto.NewAESEncrypter(key)
	if err != nil {
		log.Fatal("creando cifrador: ", err)
	}
	sealed, err := cipher.EncryptString("dato confidencial de demostración")
	if err != nil {
		log.Fatal("cifrando: ", err)
	}
	plain, err := cipher.DecryptString(sealed)
	if err != nil {
		log.Fatal("descifrando: ", err)
	}
	fmt.Println("Texto cifrado:", sealed)
	fmt.Println("Texto recuperado:", plain)

	apiKey, err := goxiscrypto.GenerateAPIKey("demo")
	if err != nil {
		log.Fatal("generando API key: ", err)
	}
	fmt.Println("API key de demostración:", apiKey)
}
