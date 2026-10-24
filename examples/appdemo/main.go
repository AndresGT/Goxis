package main

import (
	"fmt"
	"log"
)

func main() {
	app, tokens, err := InitRoutes()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\nTokens de acceso para probar las rutas protegidas:")
	fmt.Printf("Admin:  %s\n", tokens.Admin)
	fmt.Printf("Viewer: %s\n", tokens.Viewer)
	fmt.Println("Prueba: GET /api/public, /api/public/private, /api/public/member y /api/public/admin")

	if err := app.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
