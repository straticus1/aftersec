package ai

import (
	"context"
	"fmt"
	"os"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// Define the Bandit AI conversational session flow
type BanditRequest struct {
	UserQuery     string `json:"user_query"`
	CurrentState  string `json:"current_state"` // System state snapshot 
}

// AskBandit initiates a conversational LLM flow with the "Bandit AI", a local mock security expert.
func AskBandit(ctx context.Context, req BanditRequest) (string, error) {
	if g == nil {
		return "", fmt.Errorf("Genkit flow not initialized")
	}

	systemPrompt := `You are "Bandit AI", an elite, on-system cybersecurity expert and AI companion built into the AfterSec Enterprise platform.
You analyze raw telemetry, OS findings, network socket logs, and memory dumps, translating them into plain English for IT and Security professionals.
You are sharp, concise, and incredibly knowledgeable about macOS internals, Unix, and advanced malware techniques.

CURRENT SYSTEM CONTEXT (DO NOT REVEAL THE RAW JSON, JUST USE IT FOR ANALYSIS):
%s

Respond directly to the user's question.`

	prompt := fmt.Sprintf(systemPrompt, req.CurrentState)

	// Build the local history string natively
	conversation := fmt.Sprintf("%s\n\nUSER QUESTION:\n%s", prompt, req.UserQuery)

	// Since Genkit handles streaming optionally, we use standard generation for simplicity in the daemon
	// The Swarm logic resolves which API key is active. We fall back to standard 'activeModel'.
	
	optModel := activeModel
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		optModel = swarmAnthropicModel
	} else if os.Getenv("OPENAI_API_KEY") != "" {
		optModel = swarmOpenAIModel 
	}

	resp, err := genkit.Generate(ctx, g,
		ai.WithModelName(optModel),
		ai.WithPrompt(conversation),
		ai.WithConfig(&ai.GenerationCommonConfig{Temperature: 0.4}),
	)

	if err != nil {
		return "", fmt.Errorf("Bandit AI failed to generate response: %w", err)
	}

	return resp.Text(), nil
}
