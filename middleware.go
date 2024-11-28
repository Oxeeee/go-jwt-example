package main

import (
	"context"
	"log"
	"net/http"
)

type contextKey string

const usernameKey = "username"

// AuthMiddleware is an HTTP middleware that requires an access token cookie
// to be present in the request.  If the cookie is not present or is invalid,
// it returns an HTTP 401 Unauthorized response.  If the access token is valid,
// it extracts the username from the token and adds it to the request context
// as the "username" value.
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("access_token")
		if err != nil {
			log.Printf("Error: %v - Token not found in cookies", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		log.Printf("Access token found: %s", cookie.Value)

		claims, err := ValidateAccessToken(cookie.Value)
		if err != nil {
			log.Printf("Error validating access token: %v", err)
			http.Redirect(w, r, "/refresh", http.StatusTemporaryRedirect)
			return
		}

		log.Printf("Access token validated successfully for user: %s", claims.Username)

		ctx := context.WithValue(r.Context(), usernameKey, claims.Username)
		log.Printf("Adding username '%s' to context", claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
