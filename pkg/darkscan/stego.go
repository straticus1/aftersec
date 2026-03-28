package darkscan

import (
	"context"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"
	"os"
)

// StegoDetector detects hidden data in images using various techniques
type StegoDetector struct {
	config  *Config
	enabled bool
}

// StegoResult contains steganography detection results
type StegoResult struct {
	FilePath         string
	FileType         string
	Suspicious       bool
	Confidence       float64 // 0.0 - 1.0
	Techniques       []StegoTechnique
	LSBAnalysis      *LSBAnalysis
	DCTAnalysis      *DCTAnalysis
	StatAnalysis     *StatisticalAnalysis
	RecommendedAction string
}

// StegoTechnique represents a detected steganography technique
type StegoTechnique struct {
	Name        string
	Detected    bool
	Confidence  float64
	Description string
	Indicators  []string
}

// LSBAnalysis contains LSB (Least Significant Bit) analysis results
type LSBAnalysis struct {
	Enabled        bool
	Chi2Score      float64  // Chi-square score (higher = more suspicious)
	RSAnalysis     float64  // RS Steganalysis score
	BitPlaneNoise  []float64 // Entropy per bit plane
	AnomalyDetected bool
	EstimatedPayloadSize int64 // Estimated hidden data size in bytes
}

// DCTAnalysis contains DCT coefficient analysis for JPEGs
type DCTAnalysis struct {
	Enabled           bool
	HistogramAnomaly  bool
	BenfordDeviation  float64  // Deviation from Benford's Law
	BlockArtifacts    int
	SuspiciousBlocks  []BlockInfo
	JStegDetected     bool
	OutGuessDetected  bool
}

// BlockInfo contains information about a suspicious DCT block
type BlockInfo struct {
	X              int
	Y              int
	AnomalyScore   float64
	Coefficients   []int
}

// StatisticalAnalysis contains general statistical analysis
type StatisticalAnalysis struct {
	Entropy           float64 // Shannon entropy
	ColorHistogramAnomaly bool
	PixelValueDistribution map[int]int
	UnexpectedPatterns []string
	RedundancyScore   float64
}

// NewStegoDetector creates a new steganography detector
func NewStegoDetector(cfg *Config) (*StegoDetector, error) {
	// For now, always enabled if called
	return &StegoDetector{
		config:  cfg,
		enabled: true,
	}, nil
}

// DetectSteganography performs comprehensive steganography detection on an image
func (s *StegoDetector) DetectSteganography(ctx context.Context, filePath string) (*StegoResult, error) {
	if !s.enabled {
		return nil, fmt.Errorf("steganography detection not enabled")
	}

	// Open and decode image
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read header to determine file type
	header := make([]byte, 512)
	n, _ := file.Read(header)
	header = header[:n]
	fileType, _, _ := detectFileType(header)

	// Reset file pointer
	file.Seek(0, 0)

	result := &StegoResult{
		FilePath:   filePath,
		FileType:   fileType,
		Techniques: []StegoTechnique{},
	}

	// Decode image
	img, format, err := image.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	// Perform analysis based on image format
	switch format {
	case "png", "bmp", "gif":
		result.LSBAnalysis = s.analyzeLSB(img)
		result.StatAnalysis = s.analyzeStatistics(img)
	case "jpeg":
		// For JPEG, we need raw file data for DCT analysis
		file.Seek(0, 0)
		data, _ := io.ReadAll(file)
		result.DCTAnalysis = s.analyzeDCT(data)
		result.StatAnalysis = s.analyzeStatistics(img)
	default:
		result.StatAnalysis = s.analyzeStatistics(img)
	}

	// Aggregate results and calculate confidence
	result.Suspicious, result.Confidence = s.calculateSuspicionScore(result)
	result.RecommendedAction = s.recommendAction(result)
	result.Techniques = s.identifyTechniques(result)

	return result, nil
}

// analyzeLSB performs LSB analysis on images
func (s *StegoDetector) analyzeLSB(img image.Image) *LSBAnalysis {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	if width == 0 || height == 0 {
		return &LSBAnalysis{Enabled: false}
	}

	// Extract LSB planes
	lsbPlanes := make([][]byte, 8) // 8 bit planes
	for i := range lsbPlanes {
		lsbPlanes[i] = make([]byte, 0, width*height)
	}

	// Extract bits from each pixel
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r, _, _, _ := img.At(x, y).RGBA()

			// Convert to 8-bit values
			r8 := uint8(r >> 8)

			// Extract each bit plane for red channel (could do G, B too)
			for bit := 0; bit < 8; bit++ {
				lsbPlanes[bit] = append(lsbPlanes[bit], (r8>>bit)&1)
			}
		}
	}

	// Calculate entropy for each bit plane
	bitPlaneNoise := make([]float64, 8)
	for i, plane := range lsbPlanes {
		bitPlaneNoise[i] = calculateEntropy(plane)
	}

	// Chi-square test on LSB plane
	chi2Score := chiSquareTest(lsbPlanes[0])

	// RS Steganalysis
	rsScore := rsSteganalysis(img)

	// Detect anomaly: LSB plane should have high entropy if data is hidden
	anomalyDetected := false
	estimatedSize := int64(0)

	// If LSB has very high entropy (close to 1.0) and higher than other planes, it's suspicious
	if bitPlaneNoise[0] > 0.95 && bitPlaneNoise[0] > bitPlaneNoise[7] {
		anomalyDetected = true
		// Rough estimate: if LSB is filled, payload is ~12.5% of image size
		estimatedSize = int64(width * height * 3 / 8) // 3 channels, 1 bit each
	}

	return &LSBAnalysis{
		Enabled:              true,
		Chi2Score:            chi2Score,
		RSAnalysis:           rsScore,
		BitPlaneNoise:        bitPlaneNoise,
		AnomalyDetected:      anomalyDetected,
		EstimatedPayloadSize: estimatedSize,
	}
}

// analyzeDCT performs DCT coefficient analysis for JPEGs
func (s *StegoDetector) analyzeDCT(data []byte) *DCTAnalysis {
	analysis := &DCTAnalysis{
		Enabled:          true,
		SuspiciousBlocks: []BlockInfo{},
	}

	// Simplified JPEG DCT analysis
	// In production, you'd use a full JPEG parser to extract DCT coefficients
	// For now, we do basic pattern detection

	// Check for JSteg signature (modifies LSB of DCT coefficients)
	// JSteg typically creates specific patterns in coefficient histograms
	analysis.JStegDetected = detectJStegPattern(data)

	// Check for OutGuess signature (embeds data while preserving statistics)
	analysis.OutGuessDetected = detectOutGuessPattern(data)

	// Benford's Law test on DCT coefficients
	// Natural images follow Benford's Law, steganography violates it
	analysis.BenfordDeviation = benfordTest(data)

	// Histogram anomaly detection
	analysis.HistogramAnomaly = analysis.BenfordDeviation > 0.15

	return analysis
}

// analyzeStatistics performs general statistical analysis
func (s *StegoDetector) analyzeStatistics(img image.Image) *StatisticalAnalysis {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	analysis := &StatisticalAnalysis{
		PixelValueDistribution: make(map[int]int),
		UnexpectedPatterns:     []string{},
	}

	// Calculate entropy and color distribution
	var pixels []byte
	colorCounts := make(map[uint32]int)

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			r8, g8, b8 := uint8(r>>8), uint8(g>>8), uint8(b>>8)

			pixels = append(pixels, r8, g8, b8)

			// Track color frequency
			colorKey := uint32(r8)<<16 | uint32(g8)<<8 | uint32(b8)
			colorCounts[colorKey]++

			// Pixel value distribution
			analysis.PixelValueDistribution[int(r8)]++
			analysis.PixelValueDistribution[int(g8)]++
			analysis.PixelValueDistribution[int(b8)]++

			_ = a // unused but extracted for completeness
		}
	}

	// Calculate Shannon entropy
	analysis.Entropy = calculateEntropy(pixels)

	// Check for color histogram anomalies
	// Natural images have varied colors, stego images may have unusual distributions
	if len(colorCounts) < (width*height)/10 {
		analysis.ColorHistogramAnomaly = true
		analysis.UnexpectedPatterns = append(analysis.UnexpectedPatterns, "Limited color palette")
	}

	// Calculate redundancy score (how repetitive the data is)
	analysis.RedundancyScore = calculateRedundancy(pixels)

	return analysis
}

// calculateSuspicionScore aggregates all analysis results into a final score
func (s *StegoDetector) calculateSuspicionScore(result *StegoResult) (bool, float64) {
	var score float64
	var factors int

	// LSB analysis contribution
	if result.LSBAnalysis != nil && result.LSBAnalysis.Enabled {
		factors++
		if result.LSBAnalysis.AnomalyDetected {
			score += 0.4
		}
		if result.LSBAnalysis.Chi2Score > 50 { // High chi-square indicates non-random data
			score += 0.3
		}
		if result.LSBAnalysis.RSAnalysis > 0.1 {
			score += 0.3
		}
	}

	// DCT analysis contribution
	if result.DCTAnalysis != nil && result.DCTAnalysis.Enabled {
		factors++
		if result.DCTAnalysis.JStegDetected {
			score += 0.5
		}
		if result.DCTAnalysis.OutGuessDetected {
			score += 0.5
		}
		if result.DCTAnalysis.HistogramAnomaly {
			score += 0.3
		}
	}

	// Statistical analysis contribution
	if result.StatAnalysis != nil {
		factors++
		// High entropy can indicate encrypted/hidden data
		if result.StatAnalysis.Entropy > 7.5 { // Out of 8.0 max
			score += 0.2
		}
		if result.StatAnalysis.ColorHistogramAnomaly {
			score += 0.2
		}
		if result.StatAnalysis.RedundancyScore < 0.1 {
			score += 0.2
		}
	}

	// Normalize score
	if factors > 0 {
		score = score / float64(factors)
	}

	// Clamp to [0, 1]
	if score > 1.0 {
		score = 1.0
	}

	suspicious := score > 0.5

	return suspicious, score
}

// identifyTechniques identifies specific steganography techniques detected
func (s *StegoDetector) identifyTechniques(result *StegoResult) []StegoTechnique {
	techniques := []StegoTechnique{}

	// LSB embedding
	if result.LSBAnalysis != nil && result.LSBAnalysis.AnomalyDetected {
		techniques = append(techniques, StegoTechnique{
			Name:        "LSB Embedding",
			Detected:    true,
			Confidence:  0.7,
			Description: "Least Significant Bit embedding detected in image",
			Indicators:  []string{"High LSB entropy", "Chi-square anomaly"},
		})
	}

	// JSteg
	if result.DCTAnalysis != nil && result.DCTAnalysis.JStegDetected {
		techniques = append(techniques, StegoTechnique{
			Name:        "JSteg",
			Detected:    true,
			Confidence:  0.8,
			Description: "JSteg JPEG steganography detected",
			Indicators:  []string{"DCT coefficient patterns"},
		})
	}

	// OutGuess
	if result.DCTAnalysis != nil && result.DCTAnalysis.OutGuessDetected {
		techniques = append(techniques, StegoTechnique{
			Name:        "OutGuess",
			Detected:    true,
			Confidence:  0.75,
			Description: "OutGuess statistical steganography detected",
			Indicators:  []string{"Coefficient distribution anomalies"},
		})
	}

	return techniques
}

// recommendAction provides guidance based on detection results
func (s *StegoDetector) recommendAction(result *StegoResult) string {
	if result.Confidence > 0.8 {
		return "High probability of steganography. Quarantine and analyze with specialized tools."
	} else if result.Confidence > 0.5 {
		return "Moderate suspicion. Manual review recommended."
	} else {
		return "Low suspicion. Image appears clean."
	}
}

//
// Helper Functions
//

// calculateEntropy calculates Shannon entropy of byte data
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	length := float64(len(data))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// chiSquareTest performs chi-square test on data
func chiSquareTest(data []byte) float64 {
	if len(data) < 2 {
		return 0
	}

	// Count pairs of bits
	observed := make(map[string]int)
	for i := 0; i < len(data)-1; i++ {
		pair := fmt.Sprintf("%d%d", data[i], data[i+1])
		observed[pair]++
	}

	// Expected frequency for random data
	expected := float64(len(data)-1) / 4.0

	// Calculate chi-square
	chi2 := 0.0
	for _, obs := range observed {
		diff := float64(obs) - expected
		chi2 += (diff * diff) / expected
	}

	return chi2
}

// rsSteganalysis performs RS steganalysis
// Simplified version - checks for regularity/singularity patterns
func rsSteganalysis(img image.Image) float64 {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	if width < 10 || height < 10 {
		return 0
	}

	// Sample random regions and check for smoothness vs noise
	regularCount := 0
	singularCount := 0
	samples := 100

	for i := 0; i < samples; i++ {
		x := i % (width - 2)
		y := i / (width - 2)
		if y >= height-2 {
			break
		}

		// Get 2x2 block
		r1, _, _, _ := img.At(x, y).RGBA()
		r2, _, _, _ := img.At(x+1, y).RGBA()
		r3, _, _, _ := img.At(x, y+1).RGBA()
		r4, _, _, _ := img.At(x+1, y+1).RGBA()

		// Calculate variance
		vals := []int{int(r1 >> 8), int(r2 >> 8), int(r3 >> 8), int(r4 >> 8)}
		mean := (vals[0] + vals[1] + vals[2] + vals[3]) / 4
		variance := 0
		for _, v := range vals {
			diff := v - mean
			variance += diff * diff
		}

		if variance < 10 {
			regularCount++ // Smooth region
		} else if variance > 100 {
			singularCount++ // Noisy region
		}
	}

	// RS ratio - natural images have balanced R and S groups
	// Stego images disturb this balance
	if regularCount+singularCount == 0 {
		return 0
	}

	ratio := math.Abs(float64(regularCount-singularCount)) / float64(regularCount+singularCount)
	return ratio
}

// detectJStegPattern detects JSteg steganography patterns in JPEG data
func detectJStegPattern(data []byte) bool {
	// JSteg embeds in LSB of non-zero, non-one DCT coefficients
	// Look for specific byte patterns that indicate JSteg

	// Simplified: check for repeated patterns that suggest LSB modification
	if len(data) < 1000 {
		return false
	}

	// Count specific byte value frequencies
	zeroCount := 0
	oneCount := 0

	for i := 100; i < len(data) && i < 1000; i++ {
		if data[i] == 0 {
			zeroCount++
		} else if data[i] == 1 {
			oneCount++
		}
	}

	// JSteg avoids 0 and 1 values
	ratio := float64(zeroCount+oneCount) / 900.0
	return ratio < 0.1 // Less than 10% zero/one values suggests JSteg
}

// detectOutGuessPattern detects OutGuess steganography
func detectOutGuessPattern(data []byte) bool {
	// OutGuess preserves statistical properties
	// Check for artificially balanced coefficient distributions

	if len(data) < 1000 {
		return false
	}

	// Sample DCT coefficients and check distribution
	hist := make(map[byte]int)
	for i := 100; i < len(data) && i < 1000; i++ {
		hist[data[i]]++
	}

	// Calculate distribution uniformity
	// OutGuess creates unnaturally uniform distributions
	variance := 0.0
	mean := 900.0 / float64(len(hist))
	for _, count := range hist {
		diff := float64(count) - mean
		variance += diff * diff
	}
	variance /= float64(len(hist))

	// Low variance suggests artificial distribution balancing
	return variance < 10.0
}

// benfordTest applies Benford's Law to detect anomalies
func benfordTest(data []byte) float64 {
	if len(data) < 100 {
		return 0
	}

	// Count first digit occurrences (non-zero)
	firstDigits := make([]int, 10)
	for _, b := range data {
		if b > 0 {
			// Get first digit
			val := int(b)
			for val >= 10 {
				val /= 10
			}
			firstDigits[val]++
		}
	}

	// Benford's Law expected frequencies
	benford := []float64{0, 0.301, 0.176, 0.125, 0.097, 0.079, 0.067, 0.058, 0.051, 0.046}

	// Calculate deviation
	total := 0
	for _, count := range firstDigits {
		total += count
	}

	if total == 0 {
		return 0
	}

	deviation := 0.0
	for i := 1; i < 10; i++ {
		observed := float64(firstDigits[i]) / float64(total)
		expected := benford[i]
		deviation += math.Abs(observed - expected)
	}

	return deviation / 9.0 // Average deviation
}

// calculateRedundancy measures data redundancy
func calculateRedundancy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count unique bytes
	unique := make(map[byte]bool)
	for _, b := range data {
		unique[b] = true
	}

	// Redundancy: fewer unique values = higher redundancy
	return 1.0 - (float64(len(unique)) / 256.0)
}

// BatchDetectSteganography scans multiple images for steganography
func (s *StegoDetector) BatchDetectSteganography(ctx context.Context, paths []string) ([]*StegoResult, error) {
	results := make([]*StegoResult, 0, len(paths))

	for _, path := range paths {
		result, err := s.DetectSteganography(ctx, path)
		if err != nil {
			// Log error but continue with other files
			result = &StegoResult{
				FilePath:   path,
				Suspicious: false,
				Confidence: 0,
			}
		}
		results = append(results, result)
	}

	return results, nil
}
