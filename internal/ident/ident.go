package ident

import (
	"fmt"
	"regexp"
	"strings"
)

var commandIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func IsCommandID(value string) bool {
	return commandIDPattern.MatchString(strings.TrimSpace(value))
}

func ValidateCommandID(value string) error {
	id := strings.TrimSpace(value)
	if !commandIDPattern.MatchString(id) {
		return fmt.Errorf("invalid command_id: %s", value)
	}
	return nil
}

func NormalizeCommandID(value string) (string, error) {
	id := strings.TrimSpace(value)
	if !commandIDPattern.MatchString(id) {
		return "", fmt.Errorf("invalid command_id: %s", value)
	}
	return id, nil
}
