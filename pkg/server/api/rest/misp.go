package rest

import (
	"encoding/json"
	"net/http"

	"aftersec/pkg/threatintel"
)

var currentMISPConfig = threatintel.MISPConfig{
	Enabled: false,
}

func (r *Router) handleMISPConfig(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		
		// Mask the auth key in responses
		safeCfg := currentMISPConfig
		if safeCfg.AuthKey != "" {
			safeCfg.AuthKey = "********"
		}
		
		json.NewEncoder(w).Encode(safeCfg)
		return
	}

	if req.Method == http.MethodPost {
		var newCfg threatintel.MISPConfig
		if err := json.NewDecoder(req.Body).Decode(&newCfg); err != nil {
			http.Error(w, "Invalid Config Payload", http.StatusBadRequest)
			return
		}

		if newCfg.AuthKey == "********" {
			newCfg.AuthKey = currentMISPConfig.AuthKey // Preserve old key if masked
		}

		currentMISPConfig = newCfg

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "MISP Server Configuration Updated Successfully",
		})
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func (r *Router) handleMISPSync(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !currentMISPConfig.Enabled || currentMISPConfig.BaseURL == "" {
		http.Error(w, "MISP is not properly configured or enabled on the Server", http.StatusServiceUnavailable)
		return
	}

	mispClient := threatintel.NewMISPClient(&currentMISPConfig)
	
	attrs, err := mispClient.SearchAttributes(req.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "MISP IOC Synchronization Complete",
		"synchronized_indicators": len(attrs),
	})
}
