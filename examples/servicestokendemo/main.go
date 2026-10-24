// The example simulates a service that receives an access token and reads a
// specific custom claim after verifying the token.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	"github.com/AndresGT/Goxis/security"
	"github.com/AndresGT/Goxis/security/crypto"
	"github.com/AndresGT/Goxis/security/token"
)

func main() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("generando claves de firma: ", err)
	}
	encryptionKey, err := crypto.GenerateEncryptionKey()
	if err != nil {
		log.Fatal("generando clave de cifrado: ", err)
	}

	// En producción el emisor conserva la clave privada. El servicio validador
	// recibe solo la clave pública y la clave de descifrado autorizada.
	issuer, err := token.New(token.Config{
		Issuer: "goxis-demo", Audience: []string{"orders-service"},
		Level: security.Medium, SigningKeyID: "sign-1", SigningKey: privateKey,
		EncryptionKeyID: "encrypt-1", EncryptionKeys: map[string][]byte{"encrypt-1": encryptionKey},
		Store: token.NewMemoryStore(),
	})
	if err != nil {
		log.Fatal("configurando emisor: ", err)
	}
	validator, err := token.New(token.Config{
		Issuer: "goxis-demo", Audience: []string{"orders-service"}, Level: security.Medium,
		VerificationKeys: map[string]ed25519.PublicKey{"sign-1": publicKey},
		EncryptionKeyID:  "encrypt-1", EncryptionKeys: map[string][]byte{"encrypt-1": encryptionKey},
	})
	if err != nil {
		log.Fatal("configurando validador del servicio: ", err)
	}

	pair, err := issuer.Issue(token.IssueOptions{
		UserID: "user-123", Email: "demo@example.com",
		CustomData: map[string]any{
			"tenant_id": "tenant-42",
			"plan":      "pro",
		},
	})
	if err != nil {
		log.Fatal("emitiendo tokens de demostración: ", err)
	}

	tenantID, err := serviceReadTenantID(validator, pair.AccessToken)
	if err != nil {
		log.Fatal("leyendo tenant_id en el servicio: ", err)
	}
	fmt.Println("tenant_id validado para el servicio:", tenantID)
}

// serviceReadTenantID representa la lógica que puede vivir en un servicio.
// ValidateToken descifra, verifica firma, fechas, emisor y audiencia antes de
// devolver los claims. El servicio debe limitarse a access tokens.
func serviceReadTenantID(validator *token.Manager, rawToken string) (string, error) {
	claims, err := validator.Validate(rawToken, token.AccessToken)
	if err != nil {
		return "", err
	}
	tenantID, ok := claims.CustomData["tenant_id"].(string)
	if !ok || tenantID == "" {
		return "", errors.New("el token no contiene un tenant_id válido")
	}
	return tenantID, nil
}
