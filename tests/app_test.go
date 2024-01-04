// fastjwt_test.go
package fastjwt

import (
	"testing"

	"github.com/codegshinde/fastjwt"
)

func TestGenerateAndVerifyJwt(t *testing.T) {
	// Initialize the JWT secret
	secretKey := "test-secret-key"
	fastjwt.InitializeSecret(secretKey)

	// Example: Generate JWT
	userID := "user123"
	token, err := fastjwt.GenerateJwt(userID)
	if err != nil {
		t.Fatalf("Error generating JWT: %v", err)
	}

	// Assert that the generated token is not empty
	if len(token) == 0 {
		t.Fatal("Generated token is empty")
	}

	t.Logf("Generated JWT: %s", token)

	// Example: Verify JWT
	claims, err := fastjwt.VerifyJwt(token)
	if err != nil {
		t.Fatalf("Error verifying JWT: %v", err)
	}

	// Assert that the claims match the expected values
	if claims.AdminId != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.AdminId)
	}

	// Additional assertions based on specific claims if needed
}

func TestGenerateAndVerifyExpiredJwt(t *testing.T) {
	// Initialize the JWT secret
	secretKey := "test-secret-key"
	fastjwt.InitializeSecret(secretKey)

	// Example: Generate expired JWT
	userID := "user123"
	token, err := fastjwt.GenerateJwtWithShortExpiration(userID)
	if err != nil {
		t.Fatalf("Error generating expired JWT: %v", err)
	}

	// Example: Verify expired JWT
	_, err = fastjwt.VerifyJwt(token)
	if err == nil {
		t.Fatal("Expected an error verifying expired JWT, but got none")
	}

}
