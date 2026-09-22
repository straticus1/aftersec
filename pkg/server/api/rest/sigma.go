package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"aftersec/pkg/detection"
)

type SigmaDeployRequest struct {
	Pack detection.SignedPack `json:"pack"`
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

	if err := r.enterpriseSrv.QueueSigmaPack(deployReq.Pack, time.Now()); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, detection.ErrInvalidSignature) || errors.Is(err, detection.ErrRollback) {
			code = http.StatusUnprocessableEntity
		}
		http.Error(w, err.Error(), code)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"message":         "Signed Sigma pack queued for fleet deployment.",
		"deployment_mode": "Next Heartbeat",
		"version":         deployReq.Pack.Pack.Version,
	})
}
