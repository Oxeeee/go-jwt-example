package main

import (
	"encoding/json"
	"log"
	"net/http"
)

var userDB = map[string]string{
	"user1": "password123",
	"user2": "securepassword",
}

// LoginHandler handles user login requests. It expects a POST request with a JSON body
// containing "username" and "password" fields. If the credentials are valid, it generates
// and sets both access and refresh tokens as HTTP-only cookies. If the credentials are
// invalid, it returns an HTTP 401 status. It also returns appropriate HTTP error statuses
// for invalid request methods and malformed request bodies.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Login attempt: Username: %s, Password: %s", creds.Username, creds.Password)

	if userDB[creds.Username] != creds.Password {
		log.Printf("Invalid credentials for username: %s", creds.Username)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	accessToken, err := GenerateAccessToken(creds.Username)
	if err != nil {
		log.Printf("Error generating access token: %v", err)
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := GenerateRefreshToken(creds.Username)
	if err != nil {
		log.Printf("Error generating refresh token: %v", err)
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	log.Printf("Access and refresh tokens generated for user: %s", creds.Username)

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		HttpOnly: true,
		Path:     "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Path:     "/",
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful"))
}

// RefreshTokenHandler refreshes an access token from a valid refresh token.
// It expects a refresh token as an HTTP-only cookie, and returns an HTTP 401
// status if the token is invalid or missing. If the token is valid, it returns
// an HTTP 200 status with a new access token as an HTTP-only cookie.
func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "Refresh token not found", http.StatusUnauthorized)
		return
	}

	claims, err := ValidateRefreshToken(refreshCookie.Value)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	accessToken, err := GenerateAccessToken(claims.Username)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		HttpOnly: true,
		Path:     "/",
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Access token refreshed"))
}

// ProtectedHandler is a handler that returns a personalized message to a user.
// The handler expects a username to be present in the request context, and
// returns a 500 error if it is not.
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Context: %v", r.Context())
	username, ok := r.Context().Value(usernameKey).(string)
	if !ok {
		log.Printf("Error: 'username' not found in context or is not a string")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	log.Printf("User authenticated: %s", username)
	w.Write([]byte("Hello, " + username + "! This is a protected route."))
}
