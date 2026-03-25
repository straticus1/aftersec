package ai

import (
	"aftersec/pkg/client"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/anthropic"
	"github.com/firebase/genkit/go/plugins/compat_oai/openai"
	"github.com/firebase/genkit/go/plugins/googlegenai"
)

var g *genkit.Genkit
var activeModel string

// InitGenkit initializes the Genkit framework and registers the AI flows.
func InitGenkit(ctx context.Context, cfg *client.ClientConfig) error {
	var opts []genkit.GenkitOption

	// Load all available provider plugins to enable SWARM multi-agent mode
	if os.Getenv("OPENAI_API_KEY") != "" {
		opts = append(opts, genkit.WithPlugins(&openai.OpenAI{}))
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		opts = append(opts, genkit.WithPlugins(&anthropic.Anthropic{}))
	}
	if os.Getenv("GEMINI_API_KEY") != "" || os.Getenv("GOOGLE_GENAI_API_KEY") != "" {
		opts = append(opts, genkit.WithPlugins(&googlegenai.GoogleAI{}))
	}

	// Map the primary assigned active model
	switch cfg.Daemon.AI.Provider {
	case "openai":
		activeModel = cfg.Daemon.AI.Model
		if activeModel == "" { activeModel = "gpt-4o-mini" }
	case "anthropic", "claude":
		activeModel = cfg.Daemon.AI.Model
		if activeModel == "" { activeModel = "claude-3-5-sonnet-latest" }
	case "gemini", "":
		activeModel = cfg.Daemon.AI.Model
		if activeModel == "" { activeModel = "gemini-2.5-flash" }
	default:
		return fmt.Errorf("unknown AI provider: %s", cfg.Daemon.AI.Provider)
	}

	g = genkit.Init(ctx, opts...)

	genkit.DefineFlow(g, "analyzeThreatFlow", analyzeThreatInternal)

	prov := cfg.Daemon.AI.Provider
	if prov == "" {
		prov = "gemini"
	}
	log.Printf("[Success] Genkit AI Telemetry Analyst initialized (Provider: %s | Model: %s).", prov, activeModel)
	return nil
}

func analyzeThreatInternal(ctx context.Context, threatJSON string) (string, error) {
	prompt := fmt.Sprintf(`You are a macOS security analyst. Analyze the following security telemetry finding and explain the potential threat in one or two concise sentences.
Then, provide the exact macOS terminal command to stop or remove it safely formatted exactly like this:

Remediation:
`+"```bash\n<command>\n```"+`

Telemetry:
%s`, threatJSON)

	response, err := genkit.Generate(ctx, g,
		ai.WithModelName(activeModel),
		ai.WithPrompt(prompt),
	)
	if err != nil {
		return "", err
	}
	return response.Text(), nil
}

// AnalyzeThreat executes the Genkit AI logic to analyze a threat finding.
func AnalyzeThreat(ctx context.Context, threatJSON string) (string, error) {
	if g == nil {
		return "", fmt.Errorf("Genkit flow not initialized")
	}
	return analyzeThreatInternal(ctx, threatJSON)
}

// AnalyzeThreatSwarm queries all available LLM models for independent triages and synthesizes a final Judge verdict.
func AnalyzeThreatSwarm(ctx context.Context, threatJSON string) (string, error) {
	if g == nil { return "", fmt.Errorf("Genkit not initialized") }
	opinions := ""
	
	if os.Getenv("OPENAI_API_KEY") != "" {
		resp, _ := genkit.Generate(ctx, g, ai.WithModelName("gpt-4o-mini"), ai.WithPrompt(fmt.Sprintf("Analyze: %s", threatJSON)))
		if resp != nil { opinions += "ChatGPT Analysis: " + resp.Text() + "\n\n" }
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		resp, _ := genkit.Generate(ctx, g, ai.WithModelName("claude-3-5-sonnet-latest"), ai.WithPrompt(fmt.Sprintf("Analyze: %s", threatJSON)))
		if resp != nil { opinions += "Claude Analysis: " + resp.Text() + "\n\n" }
	}
	if os.Getenv("GEMINI_API_KEY") != "" || os.Getenv("GOOGLE_GENAI_API_KEY") != "" {
		resp, _ := genkit.Generate(ctx, g, ai.WithModelName("gemini-2.5-flash"), ai.WithPrompt(fmt.Sprintf("Analyze: %s", threatJSON)))
		if resp != nil { opinions += "Gemini Analysis: " + resp.Text() + "\n\n" }
	}
	
	judgePrompt := fmt.Sprintf(`You are the Chief Security Officer. Review these independent LLM AI triage reports and synthesize a final, definitive threat judgment. End with a Bash Remediation sequence.
Reports: 
%s`, opinions)
	finalResp, err := genkit.Generate(ctx, g, ai.WithModelName(activeModel), ai.WithPrompt(judgePrompt))
	if err != nil { return "", err }
	return finalResp.Text(), nil
}

// AnalyzeBinarySemantics profiles a binary using NLP string extraction
func AnalyzeBinarySemantics(ctx context.Context, stringsOutput string) (string, error) {
	prompt := fmt.Sprintf(`You are a top-tier malware reverse engineer. Look at these extracted string constants from a macOS executable. State definitively if this looks like malware, a credential stealer, or a legitimate app based on semantic intent and function names.
Strings Dump:
%s`, stringsOutput)
	resp, err := genkit.Generate(ctx, g, ai.WithModelName(activeModel), ai.WithPrompt(prompt))
	if err != nil { return "", err }
	return resp.Text(), nil
}

// GenerateHoneypotContent orchestrates dynamic deception files
func GenerateHoneypotContent(ctx context.Context, decoyType string) (string, error) {
	prompt := fmt.Sprintf(`Generate extremely realistic, fully functioning fake content for a decoy file of type: %s. Do not include markdown formatting or explanations; output ONLY the raw file contents so it can be written perfectly to disk. Make it look irresistible to a hacker.`, decoyType)
	resp, err := genkit.Generate(ctx, g, ai.WithModelName(activeModel), ai.WithPrompt(prompt))
	if err != nil { return "", err }
	return resp.Text(), nil
}
