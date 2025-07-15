package jwt

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// VerificationResult holds details after verification
type VerificationResult struct {
	IsValid  bool
	ClientID string
	Scope    string
}

// VerifyJWT validates JWT signature and claims
func VerifyJWT(tokenString string) (VerificationResult, error) {
	// Replace this with your actual public key or KMS-based verification if needed
	secret := []byte("your-256-bit-secret")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing algorithm
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return VerificationResult{IsValid: false}, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		clientID, _ := claims["client_id"].(string)
		scope, _ := claims["scope"].(string)

		return VerificationResult{
			IsValid:  true,
			ClientID: clientID,
			Scope:    scope,
		}, nil
	}

	return VerificationResult{IsValid: false}, errors.New("invalid token claims")
}
