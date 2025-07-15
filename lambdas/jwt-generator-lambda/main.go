/*
GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -o bootstrap lambda/main.go
zip myFunction.zip bootstrap
*/
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/SmartSuite-Core/oauth-api-gw/lambdas/jwt-generator-lambda/jwt"
	"github.com/SmartSuite-Core/oauth-api-gw/lambdas/jwt-generator-lambda/postgresql"

	"github.com/aws/aws-lambda-go/lambda"
)

var db *sql.DB

var POSTGRESQL_URI string = os.Getenv("POSTGRESQL_URI")

// var KMS_KEY_ID string = os.Getenv("KMS_KEY_ID")
// var API_GW_URL string = os.Getenv("API_GW_URL")

type Request struct {
	ClientID      string   `json:"ClientID"`
	ClientSecret  string   `json:"ClientSecret"`
	AllowedScopes []string `json:"AllowedScopes"`
}

type Response struct {
	StatusCode int    `json:"statusCode"`
	Body       string `json:"body"`
}

func handler(ctx context.Context, req Request) (Response, error) {
	var err error

	// Establish connection with PostgreSQL
	db, err = sql.Open("postgres", POSTGRESQL_URI)
	if err != nil {
		return Response{StatusCode: 500, Body: "Internal Server Error - Can not connect to PostgreSQL"}, err
	}
	defer db.Close()

	// Verify DB connection
	if err = db.Ping(); err != nil {
		return Response{StatusCode: 500, Body: "Internal Server Error - Can not ping PostgreSQL"}, err
	}

	// to cleanup
	log.Println("Successfully Connected to DB")

	isValid, err := postgresql.ValidateClient(db, req.ClientID, req.ClientSecret, req.AllowedScopes)
	if err != nil || !isValid {
		return Response{StatusCode: 401, Body: "Unauthorized - Invalid client credentials"}, fmt.Errorf("authentication failed: %v", err)
	}

	// to cleanup
	log.Println("Successfully Validated Client")

	jwt, err := jwt.GenerateJWT(ctx, req.ClientID, req.AllowedScopes)
	if err != nil {
		return Response{StatusCode: 500, Body: "Internal Server Error - Can not generate JWT"}, err
	}

	// to cleanup
	log.Println("Successfully Generated JWT")

	body := map[string]interface{}{
		"access_token": jwt,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	jsonBodyData, err := json.Marshal(body)
	if err != nil {
		log.Fatal("Error marshaling map to JSON:", err)
		return Response{StatusCode: 500, Body: "Internal Server Error - Can not generate response body"}, err
	}

	return Response{StatusCode: 200, Body: string(jsonBodyData)}, nil
}

func main() {
	lambda.Start(handler)
}
