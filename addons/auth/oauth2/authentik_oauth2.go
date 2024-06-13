/*
//env.yaml
addons:
  - nvr/addons/auth/authentik

goBin: /usr/bin/go
homeDir: /path/to/home/dir

authMethod: oauth2
clientID: your-client-id
clientSecret: your-client-secret
authURL: https://authentik.example.com/application/o/authorize/
tokenURL: https://authentik.example.com/application/o/token/
redirectURL: https://yourapp.example.com/oauth2/callback
userInfoURL: https://authentik.example.com/api/v3/outpost/me/
*/

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"nvr/pkg/log"
	"nvr/pkg/storage"
	"nvr/pkg/web/auth"
	"strings"
	"sync"

	"golang.org/x/oauth2"
)

type AuthentikOAuth2Authenticator struct {
	oauth2Config *oauth2.Config
	userInfoURL  string
	tokenStore   map[string]*oauth2.Token
	authCache    map[string]auth.ValidateResponse
	logger       *log.Logger
	mu           sync.Mutex
}

func NewAuthentikOAuth2Authenticator(env storage.ConfigEnv, logger *log.Logger) (*AuthentikOAuth2Authenticator, error) {
	if env.ClientID == "" {
		return nil, fmt.Errorf("clientID is not configured")
	}

	if env.ClientSecret == "" {
		return nil, fmt.Errorf("clientSecret is not configured")
	}

	if env.AuthURL == "" {
		return nil, fmt.Errorf("authURL is not configured")
	}

	if env.TokenURL == "" {
		return nil, fmt.Errorf("tokenURL is not configured")
	}

	if env.RedirectURL == "" {
		return nil, fmt.Errorf("redirectURL is not configured")
	}

	if env.UserInfoURL == "" {
		return nil, fmt.Errorf("userInfoURL is not configured")
	}

	config := &oauth2.Config{
		ClientID:     env.ClientID,
		ClientSecret: env.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  env.AuthURL,
			TokenURL: env.TokenURL,
		},
		RedirectURL: env.RedirectURL,
		Scopes:      []string{"openid", "profile", "email"},
	}

	return &AuthentikOAuth2Authenticator{
		oauth2Config: config,
		userInfoURL:  env.UserInfoURL,
		tokenStore:   make(map[string]*oauth2.Token),
		authCache:    make(map[string]auth.ValidateResponse),
		logger:       logger,
	}, nil
}

func (a *AuthentikOAuth2Authenticator) ValidateRequest(r *http.Request) auth.ValidateResponse {
	a.mu.Lock()
	defer a.mu.Unlock()

	reqToken := r.Header.Get("Authorization")
	if res, exists := a.authCache[reqToken]; exists {
		return res
	}

	token, err := a.extractToken(r)
	if err != nil {
		return auth.ValidateResponse{}
	}

	userInfo, err := a.fetchUserInfo(token)
	if err != nil {
		return auth.ValidateResponse{}
	}

	account := auth.Account{
		ID:       userInfo.Sub,
		Username: userInfo.Email,
		IsAdmin:  false, // Determine based on your application's user roles
		Token:    token.AccessToken,
	}

	res := auth.ValidateResponse{
		IsValid: true,
		User:    account,
	}
	a.authCache[reqToken] = res
	return res
}

func (a *AuthentikOAuth2Authenticator) AuthDisabled() bool {
	return false
}

func (a *AuthentikOAuth2Authenticator) UsersList() map[string]auth.AccountObfuscated {
	a.mu.Lock()
	defer a.mu.Unlock()

	list := make(map[string]auth.AccountObfuscated)
	for _, res := range a.authCache {
		user := res.User
		list[user.ID] = auth.AccountObfuscated{
			ID:       user.ID,
			Username: user.Username,
			IsAdmin:  user.IsAdmin,
		}
	}
	return list
}

func (a *AuthentikOAuth2Authenticator) UserSet(req auth.SetUserRequest) error {
	return fmt.Errorf("user set operation is not supported in OAuth2")
}

func (a *AuthentikOAuth2Authenticator) UserDelete(id string) error {
	return fmt.Errorf("user delete operation is not supported in OAuth2")
}

func (a *AuthentikOAuth2Authenticator) User(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := a.ValidateRequest(r)
		if !res.IsValid {
			w.Header().Set("WWW-Authenticate", `Bearer realm=""`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *AuthentikOAuth2Authenticator) Admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := a.ValidateRequest(r)
		if !res.IsValid || !res.User.IsAdmin {
			w.Header().Set("WWW-Authenticate", `Bearer realm="NVR"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *AuthentikOAuth2Authenticator) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := a.ValidateRequest(r)
		token := r.Header.Get("X-CSRF-TOKEN")

		if token != res.User.Token {
			http.Error(w, "Invalid CSRF-token.", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *AuthentikOAuth2Authenticator) MyToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := a.ValidateRequest(r)
		if !res.IsValid {
			http.Error(w, "Invalid token.", http.StatusUnauthorized)
			return
		}
		token := res.User.Token
		if _, err := w.Write([]byte(token)); err != nil {
			http.Error(w, "could not write token", http.StatusInternalServerError)
			return
		}
	})
}

func (a *AuthentikOAuth2Authenticator) Logout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Implement logout by revoking the token if supported by the provider
		w.Header().Set("WWW-Authenticate", `Bearer realm=""`)
		http.Error(w, "Logged out.", http.StatusUnauthorized)
	})
}

func (a *AuthentikOAuth2Authenticator) extractToken(r *http.Request) (*oauth2.Token, error) {
	reqToken := r.Header.Get("Authorization")
	if !strings.HasPrefix(reqToken, "Bearer ") {
		return nil, fmt.Errorf("invalid token prefix")
	}
	tokenString := strings.TrimPrefix(reqToken, "Bearer ")

	token := &oauth2.Token{
		AccessToken: tokenString,
	}

	return token, nil
}

func (a *AuthentikOAuth2Authenticator) fetchUserInfo(token *oauth2.Token) (*UserInfo, error) {
	client := a.oauth2Config.Client(context.Background(), token)
	resp, err := client.Get(a.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}
	return &userInfo, nil
}

func (a *AuthentikOAuth2Authenticator) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return a.oauth2Config.Exchange(ctx, code)
}

func (a *AuthentikOAuth2Authenticator) FetchUserInfo(token *oauth2.Token) (map[string]interface{}, error) {
	client := a.oauth2Config.Client(context.Background(), token)
	resp, err := client.Get(a.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}
	return userInfo, nil
}

// UserInfo represents the user info response from Authentik.
type UserInfo struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}
