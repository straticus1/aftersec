package cmd

import (
	stdcontext "context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"aftersec/pkg/darkscan"
)

var darkscanFiletypeCmd = &cobra.Command{
	Use:   "filetype",
	Short: "File type identification and spoofing detection",
	Long: `Identify actual file types using magic bytes and detect extension spoofing.

Features:
• True file type detection via magic byte analysis
• Extension verification (check if extension matches content)
• Spoofing detection (find files with mismatched extensions)

Supports 50+ file types including:
• Images: PNG, JPEG, GIF, BMP, TIFF, WebP, HEIC, AVIF, SVG, ICO
• Documents: PDF, DOCX, XLSX, PPTX
• Archives: ZIP, GZIP, TAR, RAR, 7Z
• Executables: EXE, ELF, Mach-O`,
}

var darkscanFiletypeIdentifyCmd = &cobra.Command{
	Use:   "identify [file-path]",
	Short: "Identify the actual type of a file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		jsonOutput, _ := cmd.Flags().GetBool("json")

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx := stdcontext.Background()
		result, err := scanner.IdentifyFileType(ctx, filePath)
		if err != nil {
			if jsonOutput {
				filetypeOutputJSON(JSONOutput{
					Success: false,
					Error:   err.Error(),
				})
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if jsonOutput {
			filetypeOutputJSON(JSONOutput{
				Success: true,
				Data:    result,
			})
			return
		}

		printFileTypeResult(result)
	},
}

var darkscanFiletypeVerifyCmd = &cobra.Command{
	Use:   "verify [file-path]",
	Short: "Verify if file extension matches actual content",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		jsonOutput, _ := cmd.Flags().GetBool("json")

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx := stdcontext.Background()
		matches, err := scanner.VerifyExtension(ctx, filePath)
		if err != nil {
			if jsonOutput {
				filetypeOutputJSON(JSONOutput{
					Success: false,
					Error:   err.Error(),
				})
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if jsonOutput {
			filetypeOutputJSON(JSONOutput{
				Success: true,
				Data: map[string]interface{}{
					"file_path": filePath,
					"matches":   matches,
				},
			})
			return
		}

		if matches {
			fmt.Printf("✅ Extension matches content: %s\n", filePath)
			os.Exit(0)
		} else {
			fmt.Printf("⚠️  Extension mismatch detected: %s\n", filePath)
			os.Exit(1)
		}
	},
}

var darkscanFiletypeSpoofingCmd = &cobra.Command{
	Use:   "detect-spoofing [directory]",
	Short: "Scan directory for files with mismatched extensions",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dirPath := args[0]
		jsonOutput, _ := cmd.Flags().GetBool("json")
		recursive, _ := cmd.Flags().GetBool("recursive")

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		if !jsonOutput {
			fmt.Printf("🔍 Scanning for spoofed files in: %s\n", dirPath)
			if recursive {
				fmt.Println("(recursive mode enabled)")
			}
			fmt.Println()
		}

		ctx := stdcontext.Background()
		results, err := scanner.DetectSpoofing(ctx, dirPath, recursive)
		if err != nil {
			if jsonOutput {
				filetypeOutputJSON(JSONOutput{
					Success: false,
					Error:   err.Error(),
				})
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if jsonOutput {
			filetypeOutputJSON(JSONOutput{
				Success: true,
				Data:    results,
			})
			return
		}

		if len(results) == 0 {
			fmt.Println("✅ No spoofed files detected")
			return
		}

		fmt.Printf("⚠️  Found %d spoofed file(s):\n\n", len(results))
		printSpoofingResults(results)
	},
}

func init() {
	darkscanCmd.AddCommand(darkscanFiletypeCmd)
	darkscanFiletypeCmd.AddCommand(darkscanFiletypeIdentifyCmd)
	darkscanFiletypeCmd.AddCommand(darkscanFiletypeVerifyCmd)
	darkscanFiletypeCmd.AddCommand(darkscanFiletypeSpoofingCmd)

	darkscanFiletypeIdentifyCmd.Flags().BoolP("json", "j", false, "Output results as JSON")
	darkscanFiletypeVerifyCmd.Flags().BoolP("json", "j", false, "Output results as JSON")
	darkscanFiletypeSpoofingCmd.Flags().BoolP("json", "j", false, "Output results as JSON")
	darkscanFiletypeSpoofingCmd.Flags().BoolP("recursive", "r", false, "Recursively scan subdirectories")
}

func printFileTypeResult(result *darkscan.FileTypeResult) {
	fmt.Printf("\n📄 File Type Analysis\n")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("File:             %s\n", result.FilePath)
	fmt.Printf("Detected Type:    %s\n", result.DetectedType)
	fmt.Printf("MIME Type:        %s\n", result.DetectedMIME)
	fmt.Printf("File Extension:   %s\n", result.Extension)
	fmt.Printf("Extension Match:  %v\n", result.ExtensionMatches)

	if result.IsSpoofed {
		fmt.Printf("\n⚠️  WARNING: File extension spoofing detected!\n")
		fmt.Printf("The file claims to be %s but is actually %s\n", result.Extension, result.DetectedType)
	} else {
		fmt.Printf("\n✅ Extension matches detected file type\n")
	}

	if result.Details != "" {
		fmt.Printf("\nDetails: %s\n", result.Details)
	}
	fmt.Printf("Confidence: %.0f%%\n\n", result.Confidence*100)
}

func printSpoofingResults(results []*darkscan.FileTypeResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "File\tExtension\tActual Type\tConfidence")
	fmt.Fprintln(w, strings.Repeat("─", 80))

	for _, result := range results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%.0f%%\n",
			truncatePath(result.FilePath, 40),
			result.Extension,
			result.DetectedType,
			result.Confidence*100)
	}

	w.Flush()
	fmt.Println()
}

func filetypeOutputJSON(data interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(data)
}
