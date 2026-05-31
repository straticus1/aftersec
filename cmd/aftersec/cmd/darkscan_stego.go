package cmd

import (
	stdcontext "context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"aftersec/pkg/darkscan"
)

var darkscanStegoCmd = &cobra.Command{
	Use:   "stego",
	Short: "Steganography detection",
	Long: `Detect hidden data in images using multiple analysis techniques:

• LSB Analysis - Least Significant Bit detection
• DCT Analysis - Discrete Cosine Transform analysis (JPEG)
• Statistical Analysis - Entropy and redundancy scoring

Supports: PNG, JPEG, GIF, BMP, TIFF, WebP, and other image formats.`,
}

var darkscanStegoDetectCmd = &cobra.Command{
	Use:   "detect [image-path]",
	Short: "Detect steganography in a single image",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		imagePath := args[0]
		jsonOutput, _ := cmd.Flags().GetBool("json")
		verbose, _ := cmd.Flags().GetBool("verbose")

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		ctx := stdcontext.Background()
		result, err := scanner.DetectSteganography(ctx, imagePath)
		if err != nil {
			if jsonOutput {
				stegoOutputJSON(JSONOutput{
					Success: false,
					Error:   err.Error(),
				})
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if jsonOutput {
			stegoOutputJSON(JSONOutput{
				Success: true,
				Data:    result,
			})
			return
		}

		printStegoResult(result, verbose)
	},
}

var darkscanStegoBatchCmd = &cobra.Command{
	Use:   "batch [image-paths...]",
	Short: "Detect steganography in multiple images",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		verbose, _ := cmd.Flags().GetBool("verbose")
		recursive, _ := cmd.Flags().GetBool("recursive")

		cfg := loadDarkScanConfig()
		scanner := initDarkScanClient(cfg)
		defer scanner.Close()

		var imagePaths []string
		for _, arg := range args {
			info, err := os.Stat(arg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: cannot access %s: %v\n", arg, err)
				continue
			}

			if info.IsDir() {
				if recursive {
					filepath.Walk(arg, func(path string, fi os.FileInfo, err error) error {
						if err != nil {
							return nil
						}
						if !fi.IsDir() && isImageFile(path) {
							imagePaths = append(imagePaths, path)
						}
						return nil
					})
				} else {
					fmt.Fprintf(os.Stderr, "Warning: %s is a directory (use --recursive to scan directories)\n", arg)
				}
			} else if isImageFile(arg) {
				imagePaths = append(imagePaths, arg)
			}
		}

		if len(imagePaths) == 0 {
			fmt.Fprintf(os.Stderr, "Error: no valid image files found\n")
			os.Exit(1)
		}

		ctx := stdcontext.Background()
		results, err := scanner.BatchDetectSteganography(ctx, imagePaths)
		if err != nil {
			if jsonOutput {
				stegoOutputJSON(JSONOutput{
					Success: false,
					Error:   err.Error(),
				})
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if jsonOutput {
			stegoOutputJSON(JSONOutput{
				Success: true,
				Data:    results,
			})
			return
		}

		printBatchStegoResults(results, verbose)
	},
}

func init() {
	darkscanCmd.AddCommand(darkscanStegoCmd)
	darkscanStegoCmd.AddCommand(darkscanStegoDetectCmd)
	darkscanStegoCmd.AddCommand(darkscanStegoBatchCmd)

	darkscanStegoDetectCmd.Flags().BoolP("json", "j", false, "Output results as JSON")
	darkscanStegoDetectCmd.Flags().BoolP("verbose", "v", false, "Show detailed analysis")

	darkscanStegoBatchCmd.Flags().BoolP("json", "j", false, "Output results as JSON")
	darkscanStegoBatchCmd.Flags().BoolP("verbose", "v", false, "Show detailed analysis")
	darkscanStegoBatchCmd.Flags().BoolP("recursive", "r", false, "Recursively scan directories")
}

func printStegoResult(result *darkscan.StegoResult, verbose bool) {
	fmt.Printf("\n📸 Steganography Analysis: %s\n", filepath.Base(result.FilePath))
	fmt.Println(strings.Repeat("─", 60))

	if result.Suspicious {
		fmt.Printf("⚠️  SUSPICIOUS (confidence: %.1f%%)\n", result.Confidence*100)
		if len(result.Techniques) > 0 {
			fmt.Printf("Detected techniques: %v\n", result.Techniques)
		}
	} else {
		fmt.Printf("✅ CLEAN (confidence: %.1f%%)\n", result.Confidence*100)
	}

	if verbose {
		fmt.Println()
		if result.LSBAnalysis != nil {
			fmt.Println("LSB Analysis:")
			fmt.Printf("  Chi² Score:        %.4f\n", result.LSBAnalysis.Chi2Score)
			fmt.Printf("  RS Analysis:       %.4f\n", result.LSBAnalysis.RSAnalysis)
			fmt.Printf("  Anomaly Detected:  %v\n", result.LSBAnalysis.AnomalyDetected)
			if result.LSBAnalysis.EstimatedPayloadSize > 0 {
				fmt.Printf("  Est. Payload:      %d bytes\n", result.LSBAnalysis.EstimatedPayloadSize)
			}
			if len(result.LSBAnalysis.BitPlaneNoise) > 0 {
				fmt.Printf("  Bit Plane Entropy: %v\n", formatFloatSlice(result.LSBAnalysis.BitPlaneNoise))
			}
		}

		if result.DCTAnalysis != nil {
			fmt.Println("\nDCT Analysis:")
			fmt.Printf("  JSteg Detected:     %v\n", result.DCTAnalysis.JStegDetected)
			fmt.Printf("  OutGuess Detected:  %v\n", result.DCTAnalysis.OutGuessDetected)
			fmt.Printf("  Histogram Anomaly:  %v\n", result.DCTAnalysis.HistogramAnomaly)
			fmt.Printf("  Benford Deviation:  %.4f\n", result.DCTAnalysis.BenfordDeviation)
		}

		if result.StatAnalysis != nil {
			fmt.Println("\nStatistical Analysis:")
			fmt.Printf("  Entropy:           %.4f\n", result.StatAnalysis.Entropy)
			fmt.Printf("  Histogram Anomaly: %v\n", result.StatAnalysis.ColorHistogramAnomaly)
			fmt.Printf("  Redundancy:        %.4f\n", result.StatAnalysis.RedundancyScore)
		}
	}

	fmt.Println()
}

func printBatchStegoResults(results []*darkscan.StegoResult, verbose bool) {
	suspicious := 0
	for _, r := range results {
		if r.Suspicious {
			suspicious++
		}
	}

	fmt.Printf("\n📊 Batch Steganography Analysis\n")
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("Total images scanned: %d\n", len(results))
	fmt.Printf("Suspicious images:    %d\n", suspicious)
	fmt.Printf("Clean images:         %d\n", len(results)-suspicious)
	fmt.Println()

	if !verbose {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Image\tStatus\tConfidence\tTechniques")
		fmt.Fprintln(w, strings.Repeat("─", 80))
		for _, result := range results {
			status := "✅ CLEAN"
			if result.Suspicious {
				status = "⚠️  SUSPICIOUS"
			}
			techniques := "-"
			if len(result.Techniques) > 0 {
				techniques = strings.Join(techniqueStrings(result.Techniques), ", ")
			}
			fmt.Fprintf(w, "%s\t%s\t%.1f%%\t%s\n",
				truncatePath(result.FilePath, 40),
				status,
				result.Confidence*100,
				techniques)
		}
		w.Flush()
	} else {
		for _, result := range results {
			printStegoResult(result, true)
		}
	}
}

func isImageFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	imageExts := []string{".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".heic", ".heif", ".avif", ".svg"}
	for _, imgExt := range imageExts {
		if ext == imgExt {
			return true
		}
	}
	return false
}

func formatFloatSlice(vals []float64) string {
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = fmt.Sprintf("%.3f", v)
	}
	return "[" + strings.Join(strs, ", ") + "]"
}

func techniqueStrings(techniques []darkscan.StegoTechnique) []string {
	strs := make([]string, len(techniques))
	for i, t := range techniques {
		strs[i] = t.Name
	}
	return strs
}

func stegoOutputJSON(data interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(data)
}
