package cmd

import (
	stdcontext "context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"aftersec/pkg/darkscan"
)

var (
	ruleRepoURL    string
	ruleRepoBranch string
)

var darkscanRulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage YARA rule repositories",
	Long: `Manage YARA rule repositories for malware detection.

YARA rules provide pattern-matching capabilities for identifying
malware, suspicious behavior, and known threats. This command allows
you to manage rule repositories from GitHub and other sources.

Popular rule repositories:
  • https://github.com/Yara-Rules/rules (Community rules)
  • https://github.com/reversinglabs/reversinglabs-yara-rules
  • https://github.com/elastic/protections-artifacts

Examples:
  aftersec darkscan rules list
  aftersec darkscan rules update
  aftersec darkscan rules add --url https://github.com/Yara-Rules/rules
  aftersec darkscan rules info`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use 'aftersec darkscan rules --help' to see available commands")
	},
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured YARA rule repositories",
	Long: `List all configured YARA rule repositories.

Displays:
  • Repository URL
  • Branch name
  • Enabled status
  • Last update time
  • Rule count

Examples:
  aftersec darkscan rules list
  aftersec darkscan rules list --json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		listRuleRepositories(scanner)
	},
}

var rulesUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update all YARA rule repositories",
	Long: `Download and update all configured YARA rule repositories.

This command fetches the latest rules from all enabled repositories
and stores them locally for use during malware scanning.

Note: This may take a few minutes depending on the number and size
of configured repositories.

Examples:
  aftersec darkscan rules update
  aftersec darkscan rules update --json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 10*time.Minute)
		defer cancel()

		updateRules(scanner, ctx)
	},
}

var rulesAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new YARA rule repository",
	Long: `Add a new YARA rule repository to the configuration.

Supports:
  • GitHub repositories (e.g., https://github.com/Yara-Rules/rules)
  • Direct rule file URLs
  • Custom rule repositories

The repository will be added to the configuration and immediately
downloaded for use.

Examples:
  aftersec darkscan rules add --url https://github.com/Yara-Rules/rules
  aftersec darkscan rules add --url https://github.com/Yara-Rules/rules --branch master
  aftersec darkscan rules add --url https://example.com/rules/malware.yar`,
	Run: func(cmd *cobra.Command, args []string) {
		if ruleRepoURL == "" {
			fmt.Println("❌ Repository URL required. Use --url flag")
			os.Exit(1)
		}

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 5*time.Minute)
		defer cancel()

		addRuleRepository(scanner, ctx)
	},
}

var rulesRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a YARA rule repository",
	Long: `Remove a YARA rule repository from the configuration.

This will:
  • Remove the repository from configuration
  • Delete locally cached rule files
  • Stop using rules from this repository in scans

Examples:
  aftersec darkscan rules remove --url https://github.com/Yara-Rules/rules`,
	Run: func(cmd *cobra.Command, args []string) {
		if ruleRepoURL == "" {
			fmt.Println("❌ Repository URL required. Use --url flag")
			os.Exit(1)
		}

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		removeRuleRepository(scanner)
	},
}

var rulesInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show YARA rule statistics and information",
	Long: `Display detailed information about installed YARA rules.

Shows:
  • Total number of rules
  • Number of repositories
  • Last update time
  • Rules storage path
  • Auto-update status

Examples:
  aftersec darkscan rules info
  aftersec darkscan rules info --json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		showRuleInfo(scanner)
	},
}

func listRuleRepositories(scanner *darkscan.Client) {
	repos, err := scanner.ListRuleRepositories()
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to list repositories: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to list repositories: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Data:    repos,
		})
		return
	}

	printRuleRepositories(repos)
}

func updateRules(scanner *darkscan.Client, ctx stdcontext.Context) {
	if outputFormat != "json" {
		fmt.Println("🔄 Updating YARA rule repositories...")
		fmt.Println("This may take a few minutes...")
		fmt.Println()
	}

	err := scanner.UpdateRules(ctx)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Update failed: %v", err),
			})
		} else {
			fmt.Printf("❌ Update failed: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Message: "Rule repositories updated successfully",
		})
	} else {
		fmt.Println("✅ Rule repositories updated successfully")
		fmt.Println()

		// Show updated rule info
		showRuleInfo(scanner)
	}
}

func addRuleRepository(scanner *darkscan.Client, ctx stdcontext.Context) {
	branch := ruleRepoBranch
	if branch == "" {
		branch = "main"
	}

	if outputFormat != "json" {
		fmt.Printf("Adding repository: %s (branch: %s)\n", ruleRepoURL, branch)
		fmt.Println("Downloading rules...")
	}

	err := scanner.AddRuleRepository(ctx, ruleRepoURL, branch)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to add repository: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to add repository: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Message: fmt.Sprintf("Repository %s added successfully", ruleRepoURL),
		})
	} else {
		fmt.Printf("✅ Repository added successfully\n")
		fmt.Printf("URL: %s\n", ruleRepoURL)
		fmt.Printf("Branch: %s\n", branch)
	}
}

func removeRuleRepository(scanner *darkscan.Client) {
	if outputFormat != "json" {
		fmt.Printf("Removing repository: %s\n", ruleRepoURL)
	}

	err := scanner.RemoveRuleRepository(ruleRepoURL)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to remove repository: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to remove repository: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Message: fmt.Sprintf("Repository %s removed successfully", ruleRepoURL),
		})
	} else {
		fmt.Printf("✅ Repository removed successfully\n")
		fmt.Println("Local rule files have been deleted")
	}
}

func showRuleInfo(scanner *darkscan.Client) {
	info, err := scanner.GetRuleInfo()
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to get rule info: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to get rule info: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Data:    info,
		})
		return
	}

	printRuleInfo(info)
}

func printRuleRepositories(repos []*darkscan.RuleRepository) {
	if len(repos) == 0 {
		fmt.Println("📚 No YARA rule repositories configured")
		fmt.Println()
		fmt.Println("Add a repository:")
		fmt.Println("  aftersec darkscan rules add --url https://github.com/Yara-Rules/rules")
		return
	}

	fmt.Printf("📚 YARA Rule Repositories (%d configured)\n", len(repos))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	for i, repo := range repos {
		status := "✅ Enabled"
		if !repo.Enabled {
			status = "⏸️  Disabled"
		}

		fmt.Printf("%d. %s\n", i+1, status)
		fmt.Printf("   URL: %s\n", repo.URL)
		fmt.Printf("   Branch: %s\n", repo.Branch)

		if repo.RuleCount > 0 {
			fmt.Printf("   Rules: %d\n", repo.RuleCount)
		}

		if !repo.LastUpdated.IsZero() {
			fmt.Printf("   Last Updated: %s\n", repo.LastUpdated.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("   Last Updated: Never\n")
		}

		fmt.Println()
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func printRuleInfo(info *darkscan.RuleInfo) {
	fmt.Println("📊 YARA Rules Status")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Total Rules:       %d\n", info.TotalRules)
	fmt.Printf("Repositories:      %d\n", len(info.Repositories))

	if !info.LastUpdate.IsZero() {
		fmt.Printf("Last Update:       %s\n", info.LastUpdate.Format("2006-01-02 15:04:05"))
		fmt.Printf("Time Since Update: %s\n", time.Since(info.LastUpdate).Round(time.Minute))
	} else {
		fmt.Printf("Last Update:       Never\n")
	}

	fmt.Printf("Rules Path:        %s\n", info.RulesPath)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if len(info.Repositories) > 0 {
		fmt.Println()
		fmt.Println("Repository Details:")
		for i, repo := range info.Repositories {
			status := "✅"
			if !repo.Enabled {
				status = "⏸️ "
			}

			fmt.Printf("  %d. %s %s\n", i+1, status, repo.URL)

			if repo.RuleCount > 0 {
				fmt.Printf("     Rules: %d\n", repo.RuleCount)
			}
		}
	}

	if info.TotalRules == 0 {
		fmt.Println()
		fmt.Println("⚠️  No rules installed. Run:")
		fmt.Println("   aftersec darkscan rules update")
	}
}

func init() {
	darkscanCmd.AddCommand(darkscanRulesCmd)

	// Subcommands
	darkscanRulesCmd.AddCommand(rulesListCmd)
	darkscanRulesCmd.AddCommand(rulesUpdateCmd)
	darkscanRulesCmd.AddCommand(rulesAddCmd)
	darkscanRulesCmd.AddCommand(rulesRemoveCmd)
	darkscanRulesCmd.AddCommand(rulesInfoCmd)

	// Add flags
	rulesAddCmd.Flags().StringVarP(&ruleRepoURL, "url", "u", "", "Repository URL (required)")
	rulesAddCmd.Flags().StringVarP(&ruleRepoBranch, "branch", "b", "main", "Repository branch")
	rulesAddCmd.MarkFlagRequired("url")

	// Remove flags
	rulesRemoveCmd.Flags().StringVarP(&ruleRepoURL, "url", "u", "", "Repository URL (required)")
	rulesRemoveCmd.MarkFlagRequired("url")
}
