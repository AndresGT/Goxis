package main

import (
	"fmt"
	"os"
	"os/exec"

	log "github.com/AndresGT/Goxis/log"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--special" {
		runSpecial(os.Args[2])
		return
	}

	demoLevels(true)
	demoSpecialLevels(true)
	demoLevels(false)
	demoSpecialLevels(false)
}

func demoLevels(color bool) {
	mode := "sin colores"
	if color {
		mode = "con colores"
	}
	fmt.Printf("\n=== Niveles normales %s ===\n", mode)

	logger := log.New(
		log.WithWriter(os.Stdout),
		log.WithLevel(log.LevelTrace),
		log.WithColor(color),
	)
	logger.Trace("Mensaje de diagnóstico detallado")
	logger.Debug("Mensaje de depuración")
	logger.Info("Mensaje informativo")
	logger.Success("Operación completada")
	logger.Warn("Advertencia de ejemplo")
	logger.Error("Error de ejemplo")
	log.InfoWithFields(
		"prueba",
		map[string]any{
			"hola": "prueba completada",
		},
	)
}

func demoSpecialLevels(color bool) {
	mode := "sin colores"
	if color {
		mode = "con colores"
	}
	fmt.Printf("\n=== Niveles que interrumpen el flujo %s ===\n", mode)
	for _, level := range []string{"fatal", "panic"} {
		cmd := exec.Command(os.Args[0], "--special", level)
		if !color {
			cmd.Env = append(os.Environ(), "GOXIS_LOG_NO_COLOR=1")
		}
		output, err := cmd.CombinedOutput()
		if len(output) > 0 {
			_, _ = os.Stdout.Write(output)
		}
		if err != nil {
			fmt.Printf("(el proceso auxiliar terminó como se esperaba: %v)\n", err)
		}
	}
}

func runSpecial(level string) {
	color := os.Getenv("GOXIS_LOG_NO_COLOR") == ""
	logger := log.New(
		log.WithWriter(os.Stdout),
		log.WithLevel(log.LevelTrace),
		log.WithColor(color),
	)
	switch level {
	case "fatal":
		logger.Fatal("Error fatal de ejemplo")
	case "panic":
		logger.Panic("Panic de ejemplo")
	default:
		os.Exit(2)
	}
}
