package rest

import (
	"encoding/json"
	"net/http"

	"aftersec/pkg/server/detonation"
)

var globalDetEngine = detonation.NewEngine()

func (rt *Router) handleDetonate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// For simplicity and efficiency, our agent uploads the raw binary stream directly 
	// in the request body rather than using multipart/form-data.
	defer r.Body.Close()

	result, err := globalDetEngine.Analyze(r.Body)
	if err != nil {
		http.Error(w, "Detonation analysis failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
