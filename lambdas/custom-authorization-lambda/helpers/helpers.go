package helpers

import (
	"errors"
	"strings"
)

// GetToken extracts the token from the "Bearer ..." string
func GetToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is empty")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("authorization header format must be Bearer {token}")
	}

	return parts[1], nil
}
