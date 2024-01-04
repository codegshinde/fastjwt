package fastjwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey []byte

// Claims represents the claims in a JWT token.
type Claims struct {
	AdminId string `json:"adminId"`
	jwt.RegisteredClaims
}

// InitializeSecret initializes the JWT secret at the root level.
func InitializeSecret(key string) {
	secretKey = []byte(key)
}

// GenerateJwt generates a signed JWT token.
func GenerateJwt(id string) (string, error) {
	claims := &Claims{
		AdminId: id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Audience:  []string{"microservices"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// VerifyJwt verifies a JWT token.
func VerifyJwt(tokenString string) (*Claims, error) {
	// Parse the JWT token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	// Access user information from the token claims
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}

// GenerateJwtWithShortExpiration generates a signed JWT token with a short expiration time.
func GenerateJwtWithShortExpiration(id string) (string, error) {
	claims := &Claims{
		AdminId: id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(100 * time.Microsecond)), // Set a short expiration time (1 second)
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Audience:  []string{"microservices"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
