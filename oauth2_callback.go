package nvr

import (
	"context"
	"fmt"
	"net/http"
	"nvr/pkg/storage"
	"nvr/pkg/web/auth"

	"golang.org/x/oauth2"
)

// OAuth2Authenticator is a generic interface for OAuth2 authenticators.
type OAuth2Authenticator interface {
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	FetchUserInfo(token *oauth2.Token) (map[string]interface{}, error)
}

// registerOAuth2Callback registers the OAuth2 callback route
func registerOAuth2Callback(router *http.ServeMux, a auth.Authenticator, env *storage.ConfigEnv) {
	router.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Authorization code not found", http.StatusBadRequest)
			return
		}

		// Type assert to access OAuth2 specific methods
		oauth2Auth, ok := a.(OAuth2Authenticator)
		if !ok {
			http.Error(w, "Invalid authenticator type", http.StatusInternalServerError)
			return
		}

		token, err := oauth2Auth.Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
			return
		}

		userInfo, err := oauth2Auth.FetchUserInfo(token)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to fetch user info: %v", err), http.StatusInternalServerError)
			return
		}

		sessionToken := createSessionForUser(userInfo)
		http.SetCookie(w, &http.Cookie{
			Name:  "session_token",
			Value: sessionToken,
			Path:  "/",
		})

		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func createSessionForUser(userInfo map[string]interface{}) string {
	// Implement your session creation logic here.
	// This is a placeholder implementation.
	email, ok := userInfo["email"].(string)
	if !ok {
		email = "unknown"
	}
	return fmt.Sprintf("session_for_%s", email)
}