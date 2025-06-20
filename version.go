package main

// Version information
const (
	Version = "v1.0.0-dev"
	AppName = "WrapGuard"
)

// GetVersion returns the version string
func GetVersion() string {
	return Version
}

// GetFullVersion returns the full version string with app name
func GetFullVersion() string {
	return AppName + " " + Version
}
