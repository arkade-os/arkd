package config

import "fmt"

type VersionGuardLevel string

const (
	VersionGuardMajor VersionGuardLevel = "major"
	VersionGuardMinor VersionGuardLevel = "minor"
	VersionGuardPatch VersionGuardLevel = "patch"
)

func parseVersionGuardLevel(s string) (VersionGuardLevel, error) {
	switch s {
	case string(VersionGuardMajor):
		return VersionGuardMajor, nil
	case string(VersionGuardMinor):
		return VersionGuardMinor, nil
	case string(VersionGuardPatch):
		return VersionGuardPatch, nil
	default:
		return "", fmt.Errorf(
			"build version guard level not supported, please select one of: major, minor, patch",
		)
	}
}
