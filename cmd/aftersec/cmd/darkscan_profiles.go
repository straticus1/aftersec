package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"aftersec/pkg/darkscan"
)

var (
	profileName        string
	profileDescription string
	profileEngines     []string
	profileTimeout     int
	profileMaxSize     int64
	profileRecursive   bool
	profileFollowLinks bool
)

var darkscanProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "Manage DarkScan scan profiles",
	Long: `Manage scan profiles for different use cases.

Built-in Profiles:
  - quick      Fast scan with essential engines (30s, 10MB, ClamAV only)
  - standard   Balanced scan (2min, 100MB, ClamAV + YARA)
  - deep       Thorough scan (10min, 500MB, 4 engines)
  - forensic   Comprehensive analysis (30min, 1GB, 6 engines)
  - safe       Production-safe scan (1min, 50MB, ClamAV only)

Examples:
  aftersec darkscan profiles list
  aftersec darkscan profiles show --name forensic
  aftersec darkscan profiles create --name custom-fast --engines clamav,yara
  aftersec darkscan profiles delete --name custom-fast`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use 'aftersec darkscan profiles --help' to see available commands")
	},
}

var profilesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available scan profiles",
	Long: `List all available scan profiles including built-in and custom profiles.

Displays:
  - Profile name
  - Description
  - Enabled engines
  - Timeout and file size limits
  - Recursion settings
  - Whether it's a custom profile

Examples:
  aftersec darkscan profiles list
  aftersec darkscan profiles list --json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		listProfiles(scanner)
	},
}

var profilesShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show details of a specific profile",
	Long: `Display detailed information about a specific scan profile.

Shows all configuration options including:
  - Enabled engines
  - Timeout settings
  - Maximum file size
  - Recursion and symlink following
  - Custom vs built-in status

Examples:
  aftersec darkscan profiles show --name forensic
  aftersec darkscan profiles show --name custom-profile --json`,
	Run: func(cmd *cobra.Command, args []string) {
		if profileName == "" {
			fmt.Println("❌ Profile name required. Use --name flag")
			os.Exit(1)
		}

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		showProfile(scanner, profileName)
	},
}

var profilesCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a custom scan profile",
	Long: `Create a new custom scan profile with specific settings.

Available engines:
  - clamav       ClamAV antivirus scanner
  - yara         YARA pattern matching
  - capa         Capability detection
  - viper        Malware analysis framework
  - document     Document parser
  - heuristics   Behavioral analysis
  - virustotal   VirusTotal API

Examples:
  aftersec darkscan profiles create --name fast-scan \
    --description "Quick custom scan" \
    --engines clamav,yara \
    --timeout 60 \
    --max-size 50 \
    --recursive

  aftersec darkscan profiles create --name paranoid \
    --description "Maximum security" \
    --engines clamav,yara,capa,viper,document,heuristics \
    --timeout 3600 \
    --max-size 2048 \
    --recursive \
    --follow-links`,
	Run: func(cmd *cobra.Command, args []string) {
		if profileName == "" {
			fmt.Println("❌ Profile name required. Use --name flag")
			os.Exit(1)
		}

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		createCustomProfile(scanner)
	},
}

var profilesDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a custom scan profile",
	Long: `Delete a custom scan profile. Built-in profiles cannot be deleted.

Built-in profiles (cannot delete):
  - quick
  - standard
  - deep
  - forensic
  - safe

Examples:
  aftersec darkscan profiles delete --name custom-fast
  aftersec darkscan profiles delete --name my-profile`,
	Run: func(cmd *cobra.Command, args []string) {
		if profileName == "" {
			fmt.Println("❌ Profile name required. Use --name flag")
			os.Exit(1)
		}

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		deleteProfile(scanner, profileName)
	},
}

var profilesApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply a profile as the default",
	Long: `Apply a scan profile as the default profile for all scans.

This updates the configuration to use the specified profile
by default for all future scans.

Examples:
  aftersec darkscan profiles apply --name forensic
  aftersec darkscan profiles apply --name custom-fast`,
	Run: func(cmd *cobra.Command, args []string) {
		if profileName == "" {
			fmt.Println("❌ Profile name required. Use --name flag")
			os.Exit(1)
		}

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		applyProfile(scanner, profileName)
	},
}

func listProfiles(scanner *darkscan.Client) {
	profiles, err := scanner.ListProfiles()
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to list profiles: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to list profiles: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Data:    profiles,
		})
		return
	}

	printProfileList(profiles)
}

func showProfile(scanner *darkscan.Client, name string) {
	profile, err := scanner.GetProfile(name)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Profile not found: %v", err),
			})
		} else {
			fmt.Printf("❌ Profile not found: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Data:    profile,
		})
		return
	}

	printProfileDetails(profile)
}

func createCustomProfile(scanner *darkscan.Client) {
	if len(profileEngines) == 0 {
		fmt.Println("❌ At least one engine required. Use --engines flag")
		fmt.Println("Available: clamav, yara, capa, viper, document, heuristics, virustotal")
		os.Exit(1)
	}

	// Validate engines
	validEngines := map[string]bool{
		"clamav": true, "yara": true, "capa": true, "viper": true,
		"document": true, "heuristics": true, "virustotal": true,
	}

	for _, engine := range profileEngines {
		if !validEngines[strings.ToLower(engine)] {
			fmt.Printf("❌ Invalid engine: %s\n", engine)
			fmt.Println("Valid engines: clamav, yara, capa, viper, document, heuristics, virustotal")
			os.Exit(1)
		}
	}

	// Default values
	if profileTimeout == 0 {
		profileTimeout = 120 // 2 minutes
	}
	if profileMaxSize == 0 {
		profileMaxSize = 100 * 1024 * 1024 // 100MB
	}

	profile := &darkscan.Profile{
		Name:        profileName,
		Description: profileDescription,
		Engines:     profileEngines,
		Timeout:     profileTimeout,
		MaxFileSize: profileMaxSize,
		Recursive:   profileRecursive,
		FollowLinks: profileFollowLinks,
		Custom:      true,
	}

	if outputFormat != "json" {
		fmt.Printf("Creating custom profile '%s'...\n", profileName)
	}

	err := scanner.CreateCustomProfile(profile)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to create profile: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to create profile: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Message: fmt.Sprintf("Profile '%s' created successfully", profileName),
			Data:    profile,
		})
	} else {
		fmt.Printf("✅ Profile '%s' created successfully\n\n", profileName)
		printProfileDetails(profile)
	}
}

func deleteProfile(scanner *darkscan.Client, name string) {
	if outputFormat != "json" {
		fmt.Printf("Deleting profile '%s'...\n", name)
	}

	err := scanner.DeleteCustomProfile(name)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete profile: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to delete profile: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Message: fmt.Sprintf("Profile '%s' deleted successfully", name),
		})
	} else {
		fmt.Printf("✅ Profile '%s' deleted successfully\n", name)
	}
}

func applyProfile(scanner *darkscan.Client, name string) {
	err := scanner.ApplyProfile(name)
	if err != nil {
		if outputFormat == "json" {
			outputJSON(JSONOutput{
				Success: false,
				Error:   fmt.Sprintf("Failed to apply profile: %v", err),
			})
		} else {
			fmt.Printf("❌ Failed to apply profile: %v\n", err)
		}
		os.Exit(1)
	}

	if outputFormat == "json" {
		outputJSON(JSONOutput{
			Success: true,
			Message: fmt.Sprintf("Profile '%s' applied as default", name),
		})
	} else {
		fmt.Printf("✅ Profile '%s' is now the default\n", name)
		fmt.Println("Note: You may need to restart the daemon for changes to take effect")
	}
}

func printProfileList(profiles []*darkscan.Profile) {
	fmt.Println("📋 DarkScan Scan Profiles")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Total: %d profile(s)\n\n", len(profiles))

	// Separate built-in and custom
	var builtIn, custom []*darkscan.Profile
	for _, p := range profiles {
		if p.Custom {
			custom = append(custom, p)
		} else {
			builtIn = append(builtIn, p)
		}
	}

	if len(builtIn) > 0 {
		fmt.Println("Built-in Profiles:")
		for _, profile := range builtIn {
			fmt.Printf("  • %s\n", profile.Name)
			fmt.Printf("    %s\n", profile.Description)
			fmt.Printf("    Engines: %s\n", strings.Join(profile.Engines, ", "))
			fmt.Printf("    Timeout: %ds | Max Size: %s | Recursive: %v\n\n",
				profile.Timeout, formatFileSize(profile.MaxFileSize), profile.Recursive)
		}
	}

	if len(custom) > 0 {
		fmt.Println("Custom Profiles:")
		for _, profile := range custom {
			fmt.Printf("  • %s (custom)\n", profile.Name)
			if profile.Description != "" {
				fmt.Printf("    %s\n", profile.Description)
			}
			fmt.Printf("    Engines: %s\n", strings.Join(profile.Engines, ", "))
			fmt.Printf("    Timeout: %ds | Max Size: %s | Recursive: %v\n\n",
				profile.Timeout, formatFileSize(profile.MaxFileSize), profile.Recursive)
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func printProfileDetails(profile *darkscan.Profile) {
	profileType := "Built-in"
	if profile.Custom {
		profileType = "Custom"
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Profile: %s (%s)\n", profile.Name, profileType)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if profile.Description != "" {
		fmt.Printf("Description:   %s\n", profile.Description)
	}
	fmt.Printf("Engines:       %s\n", strings.Join(profile.Engines, ", "))
	fmt.Printf("Timeout:       %d seconds\n", profile.Timeout)
	fmt.Printf("Max File Size: %s\n", formatFileSize(profile.MaxFileSize))
	fmt.Printf("Recursive:     %v\n", profile.Recursive)
	fmt.Printf("Follow Links:  %v\n", profile.FollowLinks)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func init() {
	darkscanCmd.AddCommand(darkscanProfilesCmd)

	// Subcommands
	darkscanProfilesCmd.AddCommand(profilesListCmd)
	darkscanProfilesCmd.AddCommand(profilesShowCmd)
	darkscanProfilesCmd.AddCommand(profilesCreateCmd)
	darkscanProfilesCmd.AddCommand(profilesDeleteCmd)
	darkscanProfilesCmd.AddCommand(profilesApplyCmd)

	// Show flags
	profilesShowCmd.Flags().StringVarP(&profileName, "name", "n", "", "Profile name")
	profilesShowCmd.MarkFlagRequired("name")

	// Create flags
	profilesCreateCmd.Flags().StringVarP(&profileName, "name", "n", "", "Profile name (required)")
	profilesCreateCmd.Flags().StringVarP(&profileDescription, "description", "d", "", "Profile description")
	profilesCreateCmd.Flags().StringSliceVarP(&profileEngines, "engines", "e", []string{}, "Engines to enable (comma-separated)")
	profilesCreateCmd.Flags().IntVarP(&profileTimeout, "timeout", "t", 120, "Scan timeout in seconds")
	profilesCreateCmd.Flags().Int64Var(&profileMaxSize, "max-size", 100, "Max file size in MB")
	profilesCreateCmd.Flags().BoolVarP(&profileRecursive, "recursive", "r", false, "Enable recursive scanning")
	profilesCreateCmd.Flags().BoolVarP(&profileFollowLinks, "follow-links", "f", false, "Follow symbolic links")
	profilesCreateCmd.MarkFlagRequired("name")
	profilesCreateCmd.MarkFlagRequired("engines")

	// Delete flags
	profilesDeleteCmd.Flags().StringVarP(&profileName, "name", "n", "", "Profile name")
	profilesDeleteCmd.MarkFlagRequired("name")

	// Apply flags
	profilesApplyCmd.Flags().StringVarP(&profileName, "name", "n", "", "Profile name")
	profilesApplyCmd.MarkFlagRequired("name")
}
