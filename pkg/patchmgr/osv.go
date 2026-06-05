package patchmgr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

// EnrichWithCVEs queries OSV.dev for all packages in a single batch request
// and populates CVEs in-place. Packages with no known ecosystem are skipped.
func EnrichWithCVEs(pkgs []OutdatedPackage) {
	enrichWithCVEsURL(pkgs, osvBatchURL)
}

func enrichWithCVEsURL(pkgs []OutdatedPackage, url string) {
	queries := make([]osvQuery, 0, len(pkgs))
	indices := make([]int, 0, len(pkgs))
	for i, p := range pkgs {
		eco := ecosystemFor(p.Source)
		if eco == "" {
			continue
		}
		queries = append(queries, osvQuery{
			Package: osvPkg{Name: p.Name, Ecosystem: eco},
			Version: p.Version,
		})
		indices = append(indices, i)
	}
	if len(queries) == 0 {
		return
	}

	body, err := json.Marshal(osvRequest{Queries: queries})
	if err != nil {
		return
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return
	}

	for ri, result := range osvResp.Results {
		if ri >= len(indices) {
			break
		}
		pkgIdx := indices[ri]
		for _, v := range result.Vulns {
			pkgs[pkgIdx].CVEs = append(pkgs[pkgIdx].CVEs, CVE{
				ID:          cveIDFrom(v),
				Score:       cvssScore(v),
				Description: v.Summary,
			})
		}
	}
}

// ecosystemFor maps a package source to the OSV ecosystem name.
func ecosystemFor(source string) string {
	switch source {
	case "brew":
		return "Homebrew"
	case "apt":
		return "Debian"
	case "dnf":
		return "AlmaLinux"
	case "pacman":
		return "Arch Linux"
	default:
		return ""
	}
}

type osvRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPkg `json:"package"`
	Version string `json:"version,omitempty"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Results []struct {
		Vulns []osvVuln `json:"vulns"`
	} `json:"results"`
}

type osvVuln struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Summary string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// cveIDFrom extracts a CVE ID from an OSV vuln, preferring CVE aliases.
func cveIDFrom(v osvVuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// cvssScore extracts the CVSS v3 base score from the severity field.
func cvssScore(v osvVuln) float64 {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			return parseCVSSVector(s.Score)
		}
	}
	return 0
}

// parseCVSSVector approximates a CVSS v3 base score from the vector string
// by mapping impact metric combinations to standard score ranges.
func parseCVSSVector(vector string) float64 {
	upper := strings.ToUpper(vector)
	network := strings.Contains(upper, "AV:N")

	highCount := 0
	if strings.Contains(upper, "/C:H") { highCount++ }
	if strings.Contains(upper, "/I:H") { highCount++ }
	if strings.Contains(upper, "/A:H") { highCount++ }

	medCount := 0
	if strings.Contains(upper, "/C:L") { medCount++ }
	if strings.Contains(upper, "/I:L") { medCount++ }
	if strings.Contains(upper, "/A:L") { medCount++ }

	switch {
	case highCount >= 3 && network:
		return 9.8
	case highCount >= 2 && network:
		return 8.8
	case highCount >= 1 && network:
		return 7.5
	case highCount >= 1:
		return 7.0
	case medCount >= 2:
		return 5.5
	case medCount >= 1:
		return 4.3
	default:
		return 3.1
	}
}
