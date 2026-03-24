package scanners

import (
	"aftersec/pkg/core"
	"os"
	"path/filepath"
	"strings"
)

func ScanSecrets(addFinding func(core.Finding)) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	// 1. AWS Credentials
	awsPath := filepath.Join(home, ".aws", "credentials")
	awsPass := true
	details := "Not found"
	if data, er := os.ReadFile(awsPath); er == nil {
		if strings.Contains(string(data), "aws_access_key_id") {
			awsPass = false
			details = "AWS credentials found locally. Ensure these are short-lived STS tokens and not permanent IAM keys."
		}
	}
	addFinding(core.Finding{
		Category:     "Developer Secrets Hygiene",
		Name:         "AWS Local Credentials",
		Description:  "Check if long-lived AWS credentials are stored in ~/.aws/credentials.",
		Severity:     core.Med,
		CurrentVal:   details,
		ExpectedVal:  "Not found (use STS/SSO)",
		CISBenchmark: "",
		Passed:       awsPass,
	})


	// 2. Kubeconfig check
	kubePath := filepath.Join(home, ".kube", "config")
	kubePass := true
	kDetails := "Not found"
	if data, er := os.ReadFile(kubePath); er == nil {
		if strings.Contains(string(data), "client-key-data") || strings.Contains(string(data), "token:") {
			kubePass = false
			kDetails = "Kubeconfig contains embedded static credentials/tokens."
		} else {
			kDetails = "Kubeconfig exists but uses dynamic exec/sso auth."
		}
	}
	addFinding(core.Finding{
		Category:     "Developer Secrets Hygiene",
		Name:         "Kubeconfig Static Tokens",
		Description:  "Check if Kubernetes configs contain long-lived static tokens.",
		Severity:     core.Med,
		CurrentVal:   kDetails,
		ExpectedVal:  "Not found / Dynamic Auth",
		CISBenchmark: "",
		Passed:       kubePass,
	})



}
