package scanners

import (
	"aftersec/pkg/core"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jung-kurt/gofpdf"
)

func ExportJSON(state *core.SecurityState, filepath string) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

// ExportPDF generates an executive summary PDF report.
func ExportPDF(state *core.SecurityState, filepath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// Title
	pdf.SetFont("Arial", "B", 16)
	pdf.CellFormat(190, 10, "AfterSec Enterprise Security Posture Report", "0", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "I", 10)
	pdf.CellFormat(190, 10, fmt.Sprintf("Report Generated: %s", state.Timestamp.Format(time.RFC1123)), "0", 1, "C", false, 0, "")
	pdf.Ln(10)

	// Summary Stats
	passed := 0
	failed := 0
	for _, f := range state.Findings {
		if f.Severity == core.LogOnly {
			continue // Don't count log-only in pass/fail stats
		}
		if f.Passed {
			passed++
		} else {
			failed++
		}
	}
	
	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(190, 10, "Executive Summary", "0", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 11)
	pdf.CellFormat(190, 8, fmt.Sprintf("Passed Checks: %d", passed), "0", 1, "L", false, 0, "")
	pdf.CellFormat(190, 8, fmt.Sprintf("Failed Checks: %d", failed), "0", 1, "L", false, 0, "")
	score := 0.0
	if passed+failed > 0 {
		score = float64(passed) / float64(passed+failed) * 100.0
	}
	pdf.CellFormat(190, 8, fmt.Sprintf("Compliance Score: %.1f%%", score), "0", 1, "L", false, 0, "")
	pdf.Ln(10)

	// Findings specific
	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(190, 10, "Detailed Findings", "0", 1, "L", false, 0, "")
	
	for _, f := range state.Findings {
		if f.Severity == core.LogOnly {
			continue
		}
		
		statusStr := "FAIL"
		if f.Passed {
			statusStr = "PASS"
		}
		
		pdf.SetFont("Arial", "B", 10)
		title := fmt.Sprintf("[%s] %s", statusStr, f.Name)
		pdf.MultiCell(190, 6, title, "0", "L", false)
		
		pdf.SetFont("Arial", "", 9)
		pdf.MultiCell(190, 5, fmt.Sprintf("Category: %s | Severity: %s", f.Category, f.Severity), "0", "L", false)
		if f.CISBenchmark != "" {
			pdf.MultiCell(190, 5, fmt.Sprintf("CIS: %s", f.CISBenchmark), "0", "L", false)
		}
		
		pdf.MultiCell(190, 5, fmt.Sprintf("Description: %s", f.Description), "0", "L", false)
		if !f.Passed {
			pdf.MultiCell(190, 5, fmt.Sprintf("Expected: %s\nCurrent: %s", f.ExpectedVal, f.CurrentVal), "0", "L", false)
		}
		pdf.Ln(4)
	}

	return pdf.OutputFileAndClose(filepath)
}
