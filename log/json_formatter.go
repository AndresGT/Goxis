package log

import (
	"encoding/json"
	"fmt"
)

func formatJSON(record Record) string {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Sprintf("{\"level\":%q,\"message\":%q}\n", record.Level, record.Message)
	}
	return string(data) + "\n"
}
