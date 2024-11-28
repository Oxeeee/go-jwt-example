package main

import (
	"log"
	"net/http"
)

// main starts a server on port 8080, with endpoints for login and protected pages.
// The login endpoint accepts POST requests with JSON bodies containing a username
// and password.  The protected endpoint requires a valid JWT token in the `token`
// cookie.
func main() {
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/protected", AuthMiddleware(ProtectedHandler))
	http.HandleFunc("/refresh", RefreshTokenHandler)

	log.Println("Server running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
