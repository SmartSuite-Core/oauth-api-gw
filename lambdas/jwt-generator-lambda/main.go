package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/SmartSuite-Core/oauth-api-gw/lambdas/jwt-generator-lambda/jwt"
	"github.com/SmartSuite-Core/oauth-api-gw/lambdas/jwt-generator-lambda/postgresql"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	_ "github.com/lib/pq"
)

/*
	Things to consider:
	see init():
		TODO: move env variables to SSM Parameter Store or Secrets Manager.
		TODO: find optimal values for concurrent DB connections and idle connections for prod env.
	see VerifyJWT():
		TODO: move public_key.pem to SSM Parameter Store or Secrets Manager.
*/

var db *sql.DB

type Request struct {
	GrantType     string
	ClientID      string
	ClientSecret  string
	AllowedScopes []string
}

func init() {
	var err error

	// TODO: move these values to SSM Param store or to Secrets
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=require",
		host, port, user, password, dbname,
	)

	// Establish connection with PostgreSQL
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Unable to connect to DB: %v", err)
	}

	// TODO: find optimal values for prod
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(1 * time.Minute)
}

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// log.Printf("Received request body: %+v\n", request.Body)

	formValues, err := url.ParseQuery(request.Body)
	if err != nil {
		log.Printf("Error parsing form body: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusBadRequest,
			Body:       "Invalid form data",
		}, nil
	}

	req := Request{
		ClientID:     formValues.Get("client_id"),
		ClientSecret: formValues.Get("client_secret"),
	}

	// Parse scopes: e.g., "read, write" → ["read", "write"]
	scopeStr := formValues.Get("scope")
	if scopeStr != "" {
		// Remove spaces after commas
		scopeStr = strings.ReplaceAll(scopeStr, " ", "")
		req.AllowedScopes = strings.Split(scopeStr, ",")
	}

	// log.Printf("Parsed Request - GrantType: %s, ClientID: %s, Scopes: %+v\n", req.GrantType, req.ClientID, req.AllowedScopes)

	// Verify DB connection
	if err = db.Ping(); err != nil {
		log.Printf("Failed to ping database: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       "Internal Server Error - Database Connection Issue",
		}, nil
	}

	isValid, err := postgresql.ValidateClient(db, req.ClientID, req.ClientSecret, req.AllowedScopes)
	if err != nil || !isValid {
		log.Printf("Invalid client credentials: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusUnauthorized,
			Body:       "Unauthorized - Invalid Client's Credentials",
		}, nil
	}

	jwt, err := jwt.GenerateJWT(ctx, req.ClientID, req.AllowedScopes)
	if err != nil {
		log.Printf("Can not generate JWT: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       "Internal Server Error - Can not generate JWT",
		}, nil
	}

	responseBody := map[string]interface{}{
		"access_token": jwt,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	jsonBody, _ := json.Marshal(responseBody)

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(jsonBody),
	}, nil
}

func main() {
	lambda.Start(handler)
}
