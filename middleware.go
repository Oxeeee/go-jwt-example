package main

import (
	"context"
	"net/http"
)

type contextKey string

const usernameKey contextKey = "username"

// AuthMiddleware is an HTTP middleware that requires an access token cookie
// to be present in the request.  If the cookie is not present or is invalid,
// it returns an HTTP 401 Unauthorized response.  If the access token is valid,
// it extracts the username from the token and adds it to the request context
// as the "username" value.
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("access_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := ValidateAccessToken(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/refresh", http.StatusTemporaryRedirect)
			return
		}

		ctx := context.WithValue(r.Context(), usernameKey, claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
