package main

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("supersecretkey")
var refreshSecret = []byte("refreshsecretkey")

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateAccessToken creates a new JWT access token for the given username.
// The token has an expiration time of 15 minutes from the current time.
// It returns the signed token string or an error if signing fails.
func GenerateAccessToken(username string) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// GenerateRefreshToken creates a new JWT refresh token for the given username.
// The token has an expiration time of 7 days from the current time.
// It returns the signed token string or an error if signing fails.
func GenerateRefreshToken(username string) (string, error) {
	expirationTime := time.Now().Add(7 * 24 * time.Hour)
	claims := &RefreshClaims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(refreshSecret)
}

// ValidateAccessToken checks if the given token is a valid access token.
// It returns the underlying Claims object and an error.
func ValidateAccessToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid access token")
	}
	return claims, nil
}

// ValidateRefreshToken checks if the given token is a valid refresh token.
// It returns the underlying Claims object and an error.
func ValidateRefreshToken(tokenStr string) (*RefreshClaims, error) {
	claims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return refreshSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid refresh token")
	}
	return claims, nil
}
