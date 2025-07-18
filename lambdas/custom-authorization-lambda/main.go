package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/golang-jwt/jwt/v5"
)

var publicKey *rsa.PublicKey

func init() {

	/**
		This needs to be changed!
		Either move this Public Key to a SSM Parameter Store
		Or use a Secrets Manager to store the Public Key
		Research the costs of both and speed to see which is better...
	**/
	publicKeyData, err := os.ReadFile("Public_Key.pem")
	if err != nil {
		log.Fatalf("Failed to read public key: %v", err)
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}
}

func handler(ctx context.Context, request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {

	tokenString := extractBearerToken(request.AuthorizationToken)
	if tokenString == "" {
		log.Println("No token provided")
		return generatePolicy("", "Deny", request.MethodArn), nil
	}

	// log.Printf("Received token: %s\n", tokenString)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil || !token.Valid {
		log.Printf("Token validation failed: %v\n", err)
		return generatePolicy("", "Deny", request.MethodArn), nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("Unable to parse JWT claims")
		return generatePolicy("", "Deny", request.MethodArn), nil
	}

	principalID, ok := claims["client_id"].(string)
	if !ok || principalID == "" {
		log.Println("client_id not found in token claims")
		return generatePolicy("", "Deny", request.MethodArn), nil
	}

	return generatePolicy(principalID, "Allow", request.MethodArn), nil
}

func extractBearerToken(authHeader string) string {
	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

func generatePolicy(principalID, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	return events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: principalID,
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		},
	}
}

func main() {
	lambda.Start(handler)
}
