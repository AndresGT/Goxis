package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/AndresGT/Goxis/security/audit"
)

func main() {
	auditor, err := audit.NewAuditor(audit.Config{})
	if err != nil {
		log.Fatal("creando auditor: ", err)
	}
	defer auditor.Close()

	if err := auditor.Record(&audit.Event{
		Actor:    audit.ActorInfo{ID: "user-123", Type: "user"},
		Action:   audit.ActionInfo{Type: "LOGIN", Category: "AUTH", Description: "Inicio de sesión"},
		Result:   audit.ResultInfo{Status: "SUCCESS", StatusCode: 200},
		Context:  audit.ContextInfo{IPAddress: "127.0.0.1", RequestID: "request-demo-1"},
		Metadata: map[string]any{"method": "password"},
	}); err != nil {
		log.Fatal("registrando evento: ", err)
	}
	if err := auditor.Record(&audit.Event{
		Actor:   audit.ActorInfo{ID: "user-456", Type: "user"},
		Action:  audit.ActionInfo{Type: "LOGIN", Category: "AUTH"},
		Result:  audit.ResultInfo{Status: "FAILURE", StatusCode: 401},
		Context: audit.ContextInfo{IPAddress: "127.0.0.2"},
	}); err != nil {
		log.Fatal("registrando evento: ", err)
	}

	ctx := context.Background()
	events, err := auditor.Query(ctx, audit.QueryFilter{
		ActorIDs: []string{"user-123"},
		Limit:    10,
	})
	if err != nil {
		log.Fatal("consultando auditoría: ", err)
	}
	fmt.Printf("Eventos para user-123: %d\n", len(events))
	for _, event := range events {
		fmt.Printf("%s %s %s fingerprint=%s\n", event.Timestamp.Format("15:04:05"), event.Action.Type, event.Result.Status, event.DigitalFingerprint)
	}

	var exported bytes.Buffer
	if err := auditor.Export(ctx, audit.QueryFilter{}, audit.ExportFormatJSON, &exported); err != nil {
		log.Fatal("exportando eventos: ", err)
	}
	fmt.Println("Export JSON:")
	fmt.Print(exported.String())
}
