// Package eveauth provides a client for authorizing desktop applications
// using the EVE Online Single Sign-On (SSO) service.
package eveauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/toqueteos/webbrowser"
)

type contextKey int

const (
	keyCodeVerifier contextKey = iota
	keyState
)

const (
	authorizeURLDefault = "https://login.eveonline.com/v2/oauth/authorize"
	callbackPathDefault = "callback"
	pingTimeout         = 5 * time.Second
	protocol            = "http://"
	resourceHost        = "login.eveonline.com"
	tokenURLDefault     = "https://login.eveonline.com/v2/oauth/token"
	completedPath       = "/authorized"
)

//go:embed tmpl/*
var templFS embed.FS

var (
	ErrAborted        = errors.New("process aborted prematurely")
	ErrAlreadyRunning = errors.New("another instance is already running")
	ErrInvalid        = errors.New("invalid operation")
	ErrNotInitialized = errors.New("not initialized")
	ErrTokenError     = errors.New("token error")
)

// Token represents an OAuth2 token for a character in Eve Online.
type Token struct {
	AccessToken   string    `json:"access_token"`
	CharacterID   int32     `json:"character_id"`
	CharacterName string    `json:"character_name"`
	ExpiresAt     time.Time `json:"expires_at"`
	RefreshToken  string    `json:"refresh_token"`
	Scopes        []string  `json:"scopes"`
	TokenType     string    `json:"token_type"`
}

// newToken creates e new Token from a tokenPayload and returns it.
func newToken(rawToken *tokenPayload, characterID int, characterName string, scopes []string) *Token {
	t := &Token{
		AccessToken:   rawToken.AccessToken,
		CharacterID:   int32(characterID),
		CharacterName: characterName,
		ExpiresAt:     rawToken.expiresAt(),
		RefreshToken:  rawToken.RefreshToken,
		TokenType:     rawToken.TokenType,
		Scopes:        scopes,
	}
	return t
}

// Config represents the configuration for a client.
type Config struct {
	// The SSO client ID of the Eve Online app. This field is required.
	ClientID string

	// The port for the local webserver to run. This field is required.
	Port int

	// The local path for the OAuth2 callback.
	// The default is "callback".
	CallbackPath string

	// The HTTP client to use for all requests. Uses http.DefaultClient by default.
	HTTPClient *http.Client

	// Customer logger instance. Uses slog by default.
	Logger LeveledLogger

	// A function to open an URL in the system's browser.
	// The default will open an URL in the default browser of the current system.
	OpenURL func(string) error

	// When enabled will keep the SSO server running and not start the authorization flow.
	// This feature is for testing purposes only.
	IsDemoMode bool

	// OAuth2 authorization endpoint
	AuthorizeURL string

	// OAuth2 token endpoint
	TokenURL string
}

// Client is a client for authorizing desktop applications with the EVE Online SSO service.
// It implements OAuth 2.0 with the PKCE protocol.
// A Client instance is re-usable.
type Client struct {
	authorizeURL  string
	callbackPath  string
	clientID      string
	httpClient    *http.Client
	isAuthorizing atomic.Bool
	isDemoMode    bool
	logger        LeveledLogger
	openURL       func(string) error
	port          int
	tokenURL      string
}

// NewClient returns a valid client from a configuration.
// It will return an error if the provided configuration is invalid.
//
// The callback URL is constructed from the configuration and might look like this:
// http://localhost:8000/callback
func NewClient(config Config) (*Client, error) {
	if config.ClientID == "" {
		return nil, fmt.Errorf("must specify client ID: %w", ErrInvalid)
	}
	if config.Port == 0 {
		return nil, fmt.Errorf("must specify port: %w", ErrInvalid)
	}
	s := &Client{
		authorizeURL: authorizeURLDefault,
		callbackPath: callbackPathDefault,
		clientID:     config.ClientID,
		httpClient:   http.DefaultClient,
		logger:       slog.Default(),
		openURL:      webbrowser.Open,
		port:         config.Port,
		tokenURL:     tokenURLDefault,
	}
	if config.AuthorizeURL != "" {
		s.authorizeURL = config.AuthorizeURL
	}
	if config.CallbackPath != "" {
		cb, _ := strings.CutPrefix(config.CallbackPath, "/")
		s.callbackPath = cb
	}
	if config.HTTPClient != nil {
		s.httpClient = config.HTTPClient
	}
	if config.IsDemoMode {
		s.isDemoMode = config.IsDemoMode
	}
	if config.TokenURL != "" {
		s.tokenURL = config.TokenURL
	}
	if config.Logger != nil {
		s.logger = config.Logger
	}
	if config.OpenURL != nil {
		s.openURL = config.OpenURL
	}
	return s, nil
}

// Authorize starts the authorization flow and returns a new token when successful.
//
// At the beginning the SSO login page will be opened in the browser.
// On completion of the flow a landing page will be shown in the browser.
//
// This function blocks and can be canceled through the context and will then return [ErrAborted].
//
// Only one instance of this function may run at the same time.
// Trying to run another instance will return [ErrAlreadyRunning].
func (s *Client) Authorize(ctx context.Context, scopes []string) (*Token, error) {
	if s.clientID == "" || s.port == 0 {
		return nil, ErrNotInitialized
	}
	if !s.isAuthorizing.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("authorize: %w", ErrAlreadyRunning)
	}
	defer func() {
		s.isAuthorizing.Store(false)
	}()
	codeVerifier, err := generateRandomStringBase64(32)
	if err != nil {
		return nil, fmt.Errorf("authorize: %w", err)
	}
	serverCtx := context.WithValue(ctx, keyCodeVerifier, codeVerifier)
	state, err := generateRandomStringBase64(16)
	if err != nil {
		return nil, fmt.Errorf("authorize: %w", err)
	}
	serverCtx = context.WithValue(serverCtx, keyState, state)
	serverCtx, cancel := context.WithCancel(serverCtx)
	defer cancel()

	// result variables. These are returned to caller.
	var (
		errValue atomic.Value
		token    atomic.Pointer[Token]
	)

	processError := func(w http.ResponseWriter, status int, err error) {
		s.logger.Warn("SSO authorization failed", "error", err)
		http.Error(w, fmt.Sprintf("SSO authorization failed: %s", err), status)
		errValue.Store(fmt.Errorf("authorize: %w", err))
		cancel() // shutdown http server
	}

	router := http.NewServeMux()
	// Route for responding to ping requests
	router.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong\n")
	})
	// Route for stopping the server
	router.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		cancel()
	})
	// Route for responding to SSO callback from CCP server
	router.HandleFunc("/"+s.callbackPath, func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query()
		stateGot := v.Get("state")
		stateWant := serverCtx.Value(keyState).(string)
		if stateGot != stateWant {
			processError(w, http.StatusUnauthorized, fmt.Errorf("invalid state. Want: %s - Got: %s", stateWant, stateGot))
			return
		}
		code := v.Get("code")
		codeVerifier := serverCtx.Value(keyCodeVerifier).(string)
		rawToken, err := s.fetchNewToken(code, codeVerifier)
		if err != nil {
			processError(w, http.StatusUnauthorized, fmt.Errorf("fetch new token: %w", err))
			return
		}
		jwtToken, err := validateJWT(ctx, s.httpClient, rawToken.AccessToken)
		if err != nil {
			processError(w, http.StatusUnauthorized, fmt.Errorf("token validation: %w", err))
			return
		}
		characterID, err := extractCharacterID(jwtToken)
		if err != nil {
			processError(w, http.StatusInternalServerError, fmt.Errorf("extract character ID: %w", err))
			return
		}
		characterName := extractCharacterName(jwtToken)
		scopes, err := extractScopes(jwtToken)
		if err != nil {
			processError(w, http.StatusInternalServerError, err)
			return
		}
		tok := newToken(rawToken, characterID, characterName, scopes)
		token.Store(tok)
		s.logger.Info("SSO authorization successful", "characterID", tok.CharacterID, "characterName", tok.CharacterName)
		http.Redirect(w, r, completedPath, http.StatusSeeOther)
	})
	router.HandleFunc(completedPath, func(w http.ResponseWriter, r *http.Request) {
		var name, id string
		tok := token.Load()
		if tok != nil {
			name = tok.CharacterName
			id = strconv.Itoa(int(tok.CharacterID))
		} else {
			name = "?"
			id = "1"
		}
		t, err := template.ParseFS(templFS, "tmpl/authorized.html")
		if err != nil {
			processError(w, http.StatusInternalServerError, err)
			return
		}
		err = t.Execute(w, map[string]string{"Name": name, "ID": id})
		if err != nil {
			processError(w, http.StatusInternalServerError, err)
			return
		}
		if s.isDemoMode {
			return
		}
		cancel() // shutdown http server
	})
	// Route for returning 404 on all other paths
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	// we want to be sure the server is running before starting the browser
	// and we want to be able to exit early in case the port is blocked
	server := &http.Server{
		Addr:    s.address(),
		Handler: newRequestLogger(router, s.logger),
	}
	l, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return nil, fmt.Errorf("authorize: listen on address: %w", err)
	}
	defer func() {
		if err := server.Close(); err != nil {
			s.logger.Error("authorize: server closed", "error", err)
		}
	}()

	s.logger.Info("authorize: server started", "address", protocol+server.Addr)

	go func() {
		if err := server.Serve(l); err != http.ErrServerClosed {
			s.logger.Error("authorize: server terminated prematurely", "error", err)
		}
		cancel()
		s.logger.Info("authorize: server stopped")
	}()

	ctxPing, cncl := context.WithTimeout(ctx, pingTimeout)
	defer cncl()

	u, err := url.JoinPath(protocol+server.Addr, "ping")
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid path: %w", err)
	}
	req, err := http.NewRequestWithContext(ctxPing, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("authorize: prepare ping: %w", err)
	}
	_, err = s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authorize: ping: %w", err)
	}

	if !s.isDemoMode {
		if err := s.startAuthorization(state, codeVerifier, scopes); err != nil {
			return nil, fmt.Errorf("authorize: start: %w", err)
		}
	}
	<-serverCtx.Done()

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownRelease()

	if err := server.Shutdown(shutdownCtx); err != nil {
		s.logger.Warn("authorize: server shutdown", "error", err)
	}

	if x := errValue.Load(); x != nil {
		return nil, x.(error) // we expect this to always be an error
	}

	t := token.Load()
	if t == nil {
		return nil, fmt.Errorf("authorize: start SSO: %w", ErrAborted)
	}
	return t, nil
}

// generateRandomStringBase64 returns a random string of given length with base64 encoding.
func generateRandomStringBase64(length int) (string, error) {
	data := make([]byte, length)
	_, err := rand.Read(data)
	if err != nil {
		return "", err
	}
	s := base64.URLEncoding.EncodeToString(data)
	return s, nil
}

func (s *Client) address() string {
	return fmt.Sprintf("localhost:%d", s.port)
}

// startAuthorization opens the browser and shows the character selection page for SSO.
func (s *Client) startAuthorization(state string, codeVerifier string, scopes []string) error {
	challenge, err := calcCodeChallenge(codeVerifier)
	if err != nil {
		return err
	}
	u, err := s.makeStartURL(challenge, state, scopes)
	if err != nil {
		return err
	}
	return s.openURL(u)
}

func calcCodeChallenge(codeVerifier string) (string, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(codeVerifier)); err != nil {
		return "", err
	}
	challenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return challenge, nil
}

func (s *Client) makeStartURL(challenge, state string, scopes []string) (string, error) {
	uri, err := url.JoinPath(protocol+s.address(), s.callbackPath)
	if err != nil {
		return "", err
	}
	v := url.Values{}
	v.Set("client_id", s.clientID)
	v.Set("code_challenge_method", "S256")
	v.Set("code_challenge", challenge)
	v.Set("redirect_uri", uri)
	v.Set("response_type", "code")
	v.Set("scope", strings.Join(scopes, " "))
	v.Set("state", state)
	return s.authorizeURL + "/?" + v.Encode(), nil
}

// token payload as returned from SSO API
type tokenPayload struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// expiresAt returns the time when this token will expire.
func (t *tokenPayload) expiresAt() time.Time {
	x := time.Now().Add(time.Second * time.Duration(t.ExpiresIn))
	return x
}

// fetchNewToken returns a new token from SSO API.
func (s *Client) fetchNewToken(code, codeVerifier string) (*tokenPayload, error) {
	form := url.Values{
		"client_id":     {s.clientID},
		"code_verifier": {codeVerifier},
		"code":          {code},
		"grant_type":    {"authorization_code"},
	}
	req, err := http.NewRequest("POST", s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Host", resourceHost)

	s.logger.Info("Sending auth request to SSO API")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	token := tokenPayload{}
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}
	if token.Error != "" {
		err := fmt.Errorf(
			"SSO new token: token payload has error: %s, %s: %w",
			token.Error, token.ErrorDescription,
			ErrTokenError,
		)
		return nil, err
	}
	return &token, nil
}

// RefreshToken refreshes token when successful
// or returns an error when the refresh has failed.
func (s *Client) RefreshToken(ctx context.Context, token *Token) error {
	if s.clientID == "" || s.port == 0 {
		return ErrNotInitialized
	}
	if token == nil || token.RefreshToken == "" {
		return fmt.Errorf("refresh: missing refresh token: %w", ErrTokenError)
	}
	rawToken, err := s.fetchRefreshedToken(token.RefreshToken)
	if err != nil {
		return fmt.Errorf("refresh: %w", err)
	}
	_, err = validateJWT(ctx, s.httpClient, rawToken.AccessToken)
	if err != nil {
		return fmt.Errorf("refresh: %w", err)
	}
	token.AccessToken = rawToken.AccessToken
	token.RefreshToken = rawToken.RefreshToken
	token.ExpiresAt = rawToken.expiresAt()
	return nil
}

func (s *Client) fetchRefreshedToken(refreshToken string) (*tokenPayload, error) {
	form := url.Values{
		"client_id":     {s.clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req, err := http.NewRequest("POST", s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Host", resourceHost)
	s.logger.Debug("Requesting token from SSO API", "grant_type", form.Get("grant_type"), "url", s.tokenURL)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	token := tokenPayload{}
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}
	if token.Error != "" {
		err := fmt.Errorf(
			"SSO refresh token: token payload has error: %s, %s: %w",
			token.Error,
			token.ErrorDescription,
			ErrTokenError,
		)
		return nil, err
	}
	return &token, nil
}
