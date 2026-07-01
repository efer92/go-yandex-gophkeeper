// Package version exposes build-time version information injected via ldflags.
package version

// Version is set at build time via -ldflags "-X .../version.Version=v1.0.0".
var Version = "dev"

// BuildDate is set at build time via -ldflags "-X .../version.BuildDate=...".
var BuildDate = "unknown"
