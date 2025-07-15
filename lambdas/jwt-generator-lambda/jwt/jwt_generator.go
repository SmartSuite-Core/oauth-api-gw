package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/SmartSuite-Core/oauth-api-gw/lambdas/jwt-generator-lambda/helpers"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var KMS_KEY_ID string = os.Getenv("KMS_KEY_ID")
var API_GW_URL string = os.Getenv("API_GW_URL")

func GenerateJWT(ctx context.Context, clientId string, scope []string) (string, error) {
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"iss":       API_GW_URL,
		"client_id": clientId,
		"scope":     scope,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	jwtHeader := helpers.Base64URL(headerBytes)
	jwtPayload := helpers.Base64URL(payloadBytes)

	message := fmt.Sprintf("%s.%s", jwtHeader, jwtPayload)

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", err
	}

	kmsClient := kms.NewFromConfig(cfg)

	signInput := &kms.SignInput{
		KeyId:            aws.String(KMS_KEY_ID), // KMS KEY ID
		Message:          []byte(message),
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	}

	signOutput, err := kmsClient.Sign(ctx, signInput)
	if err != nil {
		return "", err
	}

	signature := helpers.Base64URL(signOutput.Signature)

	jwt := fmt.Sprintf("%s.%s.%s", jwtHeader, jwtPayload, signature)

	return jwt, nil
}
