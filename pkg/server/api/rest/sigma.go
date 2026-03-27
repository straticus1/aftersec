package rest

import (
	"encoding/json"
	"net/http"
)

type SigmaDeployRequest struct {
	RuleYAML string `json:"rule_yaml"`
}

func (r *Router) handleSigmaDeploy(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var deployReq SigmaDeployRequest
	if err := json.NewDecoder(req.Body).Decode(&deployReq); err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	if deployReq.RuleYAML == "" {
		http.Error(w, "rule_yaml is required", http.StatusBadRequest)
		return
	}

	// Deploy rule to active connected fleets via the gRPC struct
	r.enterpriseSrv.SetPendingSigmaRule(deployReq.RuleYAML)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Sigma rule queued for fleet deployment.",
		"deployment_mode": "Next Heartbeat",
	})
}
