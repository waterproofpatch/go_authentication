package go_authentication

import (
	"encoding/json"
	"net/http"
)

type Error struct {
	ErrorMessage string `json:"error_message"`
}

func WriteError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(&Error{ErrorMessage: message})
}
