package postgresql

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

/*
validateClient function accepts 3 params:
- clientID of type string
- clientSecret of type string
- scopes of type []string
- returns bool and error

Function performs the following actions:
- validates the clientID, clientSecret and scopes against the database
- returns true if the client is valid and has permissions; otherwise, false
- returns an error if the validation fails
*/
func ValidateClient(db *sql.DB, clientID string, clientSecret string, scopes []string) (bool, error) {
	tableName := os.Getenv("TABLE_NAME")
	var storedHashedSecret string
	var storedScopes string

	query := `SELECT client_secret, scope FROM ` + tableName + ` WHERE client_id = $1`

	err := db.QueryRow(query, clientID).Scan(&storedHashedSecret, &storedScopes)
	if err != nil {
		return false, err
	}

	if storedHashedSecret == "" {
		return false, fmt.Errorf("Invalid Client Id")
	}

	// Validate client_secret
	if bcrypt.CompareHashAndPassword([]byte(storedHashedSecret), []byte(clientSecret)) != nil {
		return false, fmt.Errorf("Invalid Client Secret")
	}

	// Validate scopes
	var dbScopes []string
	if err := json.Unmarshal([]byte(storedScopes), &dbScopes); err != nil {
		return false, err
	}

	scopeMap := make(map[string]bool)
	for _, scope := range dbScopes {
		scopeMap[scope] = true
	}

	for _, requestedScope := range scopes {
		if !scopeMap[requestedScope] {
			log.Println("Invalid Scopes")
			return false, fmt.Errorf("invalid scope: %s", requestedScope)
		}
	}

	return true, nil
}
