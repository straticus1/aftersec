package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// Threats: the reporter sends one bounded posture document over TLS 1.3 to the
// management origin and verifies the management CA. It refuses http, redirects,
// and a report it cannot name. The enrollment code is an argument and is not
// written to disk. This does not create a hardware quote or an agent credential.

const factsScript = `$v = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop; $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop; $boot = $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); $version = (($v.ProductName + ' ' + $v.DisplayVersion + ' ' + $v.CurrentBuild).Trim()); if (-not $version) { throw 'missing os version' }; [pscustomobject]@{os_version=$version; last_boot=$boot} | ConvertTo-Json -Compress`

type factDocument struct {
	OSVersion string `json:"os_version"`
	LastBoot  string `json:"last_boot"`
}

type windowsReport struct {
	OrganizationID string  `json:"organization_id"`
	Code           string  `json:"code"`
	Hostname       string  `json:"hostname"`
	OSVersion      string  `json:"os_version"`
	LastBoot       string  `json:"last_boot"`
	Checks         []check `json:"checks"`
}

func buildReport(hostname, organization, code string, factRaw []byte, checks []check, now time.Time) ([]byte, error) {
	if hostname == "" || strings.ContainsAny(hostname, "\r\n\t /\\") || len(hostname) > 255 {
		return nil, errors.New("hostname is invalid")
	}
	if organization == "" || code == "" || strings.ContainsAny(code, "\r\n\t") {
		return nil, errors.New("inventory report is invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(factRaw))
	dec.DisallowUnknownFields()
	var facts factDocument
	if err := dec.Decode(&facts); err != nil || dec.More() {
		return nil, errors.New("os facts are invalid")
	}
	facts.OSVersion = strings.TrimSpace(facts.OSVersion)
	if facts.OSVersion == "" || len(facts.OSVersion) > 128 || strings.ContainsAny(facts.OSVersion, "\r\n\t/\\") {
		return nil, errors.New("os version is invalid")
	}
	boot, err := time.Parse(time.RFC3339, facts.LastBoot)
	if err != nil || boot.After(now.Add(2*time.Minute)) {
		return nil, errors.New("last boot is invalid")
	}
	if len(checks) != 2 {
		return nil, errors.New("posture checks are incomplete")
	}
	body, err := json.Marshal(windowsReport{
		OrganizationID: organization,
		Code:           code,
		Hostname:       hostname,
		OSVersion:      facts.OSVersion,
		LastBoot:       boot.UTC().Format(time.RFC3339),
		Checks:         checks,
	})
	if err != nil {
		return nil, errors.New("inventory report is invalid")
	}
	return body, nil
}

func postInventory(ctx context.Context, server string, caPEM, payload []byte) error {
	origin, err := url.Parse(server)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return errors.New("inventory server must be an https origin")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("management CA is invalid")
	}
	origin.Path = "/api/v1/inventory/windows"
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect refused")
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    pool,
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.String(), bytes.NewReader(payload))
	if err != nil {
		return errors.New("inventory report was rejected")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("inventory report was rejected")
	}
	defer resp.Body.Close()
	if _, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); err != nil {
		return errors.New("inventory report was rejected")
	}
	if resp.StatusCode != http.StatusCreated {
		return errors.New("inventory report was rejected")
	}
	return nil
}

func runReport(args []string) {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	server := flags.String("server", "", "")
	tenant := flags.String("tenant", "", "")
	caPath := flags.String("ca", "", "")
	code := flags.String("code", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Usage: aftersec-windows report --server https://host:8080 --tenant UUID --ca ca.pem --code CODE")
		os.Exit(2)
	}
	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "This scanner requires Windows.")
		os.Exit(2)
	}
	info, err := os.Lstat(*caPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > 1<<20 {
		fmt.Fprintln(os.Stderr, "management CA is invalid")
		os.Exit(2)
	}
	caPEM, err := os.ReadFile(*caPath)
	if err != nil || len(caPEM) == 0 || len(caPEM) > 1<<20 {
		fmt.Fprintln(os.Stderr, "management CA is invalid")
		os.Exit(2)
	}
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostname is invalid")
		os.Exit(1)
	}
	ctx := context.Background()
	factRaw, err := runPowerShell(ctx, powershellPreamble+factsScript)
	if err != nil {
		fmt.Fprintln(os.Stderr, "os facts are unavailable")
		os.Exit(1)
	}
	checks := scan(ctx, runPowerShell)
	body, err := buildReport(hostname, *tenant, *code, factRaw, checks, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	if err := postInventory(ctx, *server, caPEM, body); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
