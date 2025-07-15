package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/SmartSuite-Core/oauth-api-gw/lambdas/custom-authorization-lambda/helpers"
	"github.com/SmartSuite-Core/oauth-api-gw/lambdas/custom-authorization-lambda/jwt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

type CustomAuthorizerEvent struct {
	Type               string `json:"type"`
	AuthorizationToken string `json:"authorizationToken"`
	MethodArn          string `json:"methodArn"`
}

func handler(ctx context.Context, event CustomAuthorizerEvent) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Printf("Event received: %+v\n", event)

	token, err := helpers.GetToken(event.AuthorizationToken)
	if err != nil {
		log.Printf("Error extracting token: %v\n", err)
		return events.APIGatewayCustomAuthorizerResponse{}, fmt.Errorf("Unauthorized")
	}

	verified, err := jwt.VerifyJWT(token)
	if err != nil {
		log.Printf("JWT verification failed: %v\n", err)
		return events.APIGatewayCustomAuthorizerResponse{}, fmt.Errorf("Unauthorized")
	}

	log.Printf("Verified: %+v\n", verified)

	if verified.IsValid {
		policy := helpers.GeneratePolicy(verified.ClientID, "Allow", event.MethodArn, []string{verified.Scope})
		policyJSON, _ := json.Marshal(policy)
		log.Printf("Allow policy: %s\n", string(policyJSON))
		return policy, nil
	}

	denyPolicy := helpers.GeneratePolicy(verified.ClientID, "Deny", event.MethodArn, nil)
	log.Printf("Deny policy generated\n")
	return denyPolicy, nil
}

func main() {
	lambda.Start(handler)
}
