package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	app, tokens, err := InitRoutes()
	if err != nil {
		log.Fatal(err)
	}

	addr := os.Getenv("GOXIS_APPDEMO_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	fmt.Printf("Panel admin local: http://%s/_goxis/admin (usuario: admin, contraseña: admin)\n", addr)
	fmt.Println("\nTokens de acceso para probar las rutas protegidas:")
	fmt.Printf("Admin:  %s\n", tokens.Admin)
	fmt.Printf("Viewer: %s\n", tokens.Viewer)
	fmt.Println("Prueba: GET /api/public, /api/public/private, /api/public/member y /api/public/admin")
	fmt.Println("Verificaciones del piloto: examples/appdemo/smoke-check.ps1 (PowerShell)")

	server, err := app.NewHTTPServer(addr, app)
	if err != nil {
		_ = app.Close()
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		_ = app.Close()
		log.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	log.Printf("Goxis escuchando en %s | rutas registradas: %d", listener.Addr(), app.RouteCount())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	select {
	case sig := <-signals:
		log.Printf("Señal %s recibida; cerrando servidor ordenadamente", sig)
	case err := <-serveErr:
		if err != nil {
			log.Printf("Servidor detenido: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shutdownErr := server.Shutdown(ctx)
	closeErr := app.Close()
	if shutdownErr != nil {
		log.Printf("Error durante el apagado HTTP: %v", shutdownErr)
	}
	if closeErr != nil {
		log.Printf("Error al cerrar Goxis: %v", closeErr)
	}
	if shutdownErr != nil || closeErr != nil {
		log.Fatal("apagado incompleto")
	}
}
