// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

// Package crashreport provides opt-in anonymous crash reporting for the Erst CLI.
//
// When enabled (ERST_CRASH_REPORTING=true or crash_reporting=true in config),
// fatal panics and unhandled errors are serialised and sent to the configured
// endpoint before the process exits. No personal data or transaction content is
// collected: only the error message, stack trace, OS/arch, and Erst version.
//
// The feature is disabled by default. Users must explicitly opt in via the
// environment variable or config file.
package crashreport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"time"
)

const (
	// DefaultEndpoint is the default anonymous crash collection endpoint.
	DefaultEndpoint = "https://crash.erst.dev/v1/report"

	// defaultTimeout is the maximum time allowed for the HTTP request.
	defaultTimeout = 5 * time.Second

	// envOptIn is the environment variable users set to enable crash reporting.
	envOptIn = "ERST_CRASH_REPORTING"

	// envEndpoint overrides the reporting endpoint.
	envEndpoint = "ERST_CRASH_ENDPOINT"
)

// Report is the payload sent to the crash collection endpoint.
// Fields are deliberately minimal to preserve user privacy.
type Report struct {
	// Version of the Erst binary that crashed.
	Version string `json:"version"`
	// CommitSHA is the VCS revision embedded at build time.
	CommitSHA string `json:"commit_sha,omitempty"`
	// GOOS and GOARCH from the build environment.
	OS   string `json:"os"`
	Arch string `json:"arch"`
	// GoVersion is the Go toolchain used to compile the binary.
	GoVersion string `json:"go_version"`
	// CrashTime is the RFC 3339 timestamp of the crash.
	CrashTime string `json:"crash_time"`
	// ErrorMessage is the top-level error string (no user data).
	ErrorMessage string `json:"error_message"`
	// StackTrace is the goroutine dump captured at panic time.
	StackTrace string `json:"stack_trace,omitempty"`
	// Command is the cobra command path that was executing (e.g. "erst debug").
	Command string `json:"command,omitempty"`
}

// Config controls crash reporter behaviour.
type Config struct {
	// Enabled must be true for any report to be sent.
	Enabled bool
	// Endpoint is the URL that accepts POST application/json crash reports.
	// Defaults to DefaultEndpoint when empty.
	Endpoint string
	// Version, CommitSHA are injected from the build.
	Version   string
	CommitSHA string
}

// Reporter sends crash reports to the configured endpoint.
type Reporter struct {
	cfg    Config
	client *http.Client
}

// New creates a Reporter from cfg.
// If cfg.Endpoint is empty, DefaultEndpoint is used.
func New(cfg Config) *Reporter {
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultEndpoint
	}
	// Allow the endpoint to be overridden at runtime without recompilation.
	if env := os.Getenv(envEndpoint); env != "" {
		cfg.Endpoint = env
	}
	return &Reporter{
		cfg: cfg,
		client: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// IsEnabled returns true when crash reporting is active.
// The environment variable takes precedence over the struct field so users can
// opt out without editing their config file.
func (r *Reporter) IsEnabled() bool {
	switch os.Getenv(envOptIn) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	}
	return r.cfg.Enabled
}

// Send constructs a Report from err and stack, then POSTs it to the endpoint.
// It returns without error if reporting is disabled.
// Errors from the HTTP call are returned but should not be treated as fatal by
// the caller — the binary is already in a crash path.
func (r *Reporter) Send(ctx context.Context, err error, stack []byte, command string) error {
	if !r.IsEnabled() {
		return nil
	}

	report := r.buildReport(err, stack, command)

	payload, jsonErr := json.Marshal(report)
	if jsonErr != nil {
		return fmt.Errorf("crashreport: failed to marshal report: %w", jsonErr)
	}

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Endpoint, bytes.NewReader(payload))
	if reqErr != nil {
		return fmt.Errorf("crashreport: failed to build request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "erst/"+r.cfg.Version)

	resp, httpErr := r.client.Do(req)
	if httpErr != nil {
		return fmt.Errorf("crashreport: HTTP request failed: %w", httpErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("crashreport: server returned %d", resp.StatusCode)
	}

	return nil
}

// buildReport constructs the Report value from the current process metadata.
func (r *Reporter) buildReport(err error, stack []byte, command string) Report {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	goVersion := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		goVersion = bi.GoVersion
	}

	return Report{
		Version:      r.cfg.Version,
		CommitSHA:    r.cfg.CommitSHA,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		GoVersion:    goVersion,
		CrashTime:    time.Now().UTC().Format(time.RFC3339),
		ErrorMessage: errMsg,
		StackTrace:   string(stack),
		Command:      command,
	}
}

// HandlePanic is intended to be deferred at the top of main or Execute.
// If a panic is in flight it captures the stack, sends a report (best-effort),
// then re-panics so the runtime still terminates with a non-zero exit code.
func (r *Reporter) HandlePanic(ctx context.Context, command string) {
	v := recover()
	if v == nil {
		return
	}

	stack := debug.Stack()

	var err error
	switch e := v.(type) {
	case error:
		err = e
	default:
		err = fmt.Errorf("%v", e)
	}

	// Best-effort: ignore send errors — we are already in a fatal path.
	_ = r.Send(ctx, err, stack, command)

	// Re-panic so Go's runtime prints the stack and exits non-zero.
	panic(v)
}
