package forensics

type PkgAnalysisResult struct {
	PreinstallScript    string
	PostinstallScript   string
	RawScriptsExtracted int
	Error               error
}
