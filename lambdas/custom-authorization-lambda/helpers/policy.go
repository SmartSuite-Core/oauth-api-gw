package helpers

import (
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// GeneratePolicy creates a policy document to allow or deny access, and attaches context (e.g., scopes)
func GeneratePolicy(principalID, effect, resource string, scopes []string) events.APIGatewayCustomAuthorizerResponse {
	policy := events.APIGatewayCustomAuthorizerResponse{
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

	if len(scopes) > 0 {
		policy.Context = map[string]interface{}{
			"permissions": strings.Join(scopes, " "),
		}
	}

	return policy
}
