package ginOidc

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type InitParams struct {
	Router        *gin.Engine     // gin router (used to set handler for OIDC)
	ClientId      string          // id from the authorization service (OIDC provider)
	ClientSecret  string          // secret from the authorization service (OIDC provider)
	Issuer        url.URL         // the URL identifier for the authorization service. for example: "https://accounts.google.com" - try adding "/.well-known/openid-configuration" to the path to make sure it's correct
	ClientUrl     url.URL         // your website's/service's URL for example: "http://localhost:8081/" or "https://mydomain.com/
	Scopes        []string        // OAuth scopes. If you're unsure go with: []string{oidc.ScopeOpenID, "profile", "email"}
	ErrorHandler  gin.HandlerFunc // errors handler. for example: func(c *gin.Context) {c.String(http.StatusBadRequest, "ERROR...")}
	PostLogoutUrl url.URL         // user will be redirected to this URL after he logs out (i.e. accesses the '/logout' endpoint added in 'Init()')
}

func Init(i InitParams) gin.HandlerFunc {
	verifier, config := initVerifierAndConfig(i)
	i.Router.GET("/logout.html", logoutHandler(i))
	i.Router.Any("/oidc-callback", callbackHandler(i, verifier, config))
	return protectMiddleware(config)
}

func GetValue(c *gin.Context, key string) (value string) {
	srvSession := sessions.Default(c)
	sessionClaimRaw := srvSession.Get("oidcClaims")
	if sessionClaimRaw != nil {
		sessionClaim := sessionClaimRaw.(string)
		var claims map[string]interface{}
		err := json.Unmarshal([]byte(sessionClaim), &claims)
		if err != nil {
			log.Error(err)
		}
		v := claims[key]
		return v.(string)
	}
	return
}

func GetIdentity(c *gin.Context) (identity Identity, err error) {
	srvSession := sessions.Default(c)
	sessionClaimRaw := srvSession.Get("oidcClaims")
	if sessionClaimRaw != nil {
		sessionClaim := sessionClaimRaw.(string)
		err = json.Unmarshal([]byte(sessionClaim), &identity)
		if err != nil {
			return
		}
	}
	return
}

func initVerifierAndConfig(i InitParams) (verifier *oidc.IDTokenVerifier, config *oauth2.Config) {
	providerCtx := context.Background()
	provider, err := oidc.NewProvider(providerCtx, i.Issuer.String())
	if err != nil {
		log.Fatalf("Failed to init OIDC provider. Error: %v \n", err.Error())
	} else {
		oidcConfig := &oidc.Config{
			ClientID: i.ClientId,
		}
		verifier := provider.Verifier(oidcConfig)
		endpoint := provider.Endpoint()
		i.ClientUrl.Path = "oidc-callback"
		config := &oauth2.Config{
			ClientID:     i.ClientId,
			ClientSecret: i.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  i.ClientUrl.String(),
			Scopes:       i.Scopes,
		}
		return verifier, config
	}
	return
}

func logoutHandler(i InitParams) func(c *gin.Context) {
	return func(c *gin.Context) {
		serverSession := sessions.Default(c)
		serverSession.Set("oidcAuthorized", false)
		serverSession.Set("oidcClaims", nil)
		serverSession.Set("oidcState", nil)
		serverSession.Set("oidcOriginalRequestUrl", nil)
		err := serverSession.Save()
		if err != nil {
			log.Error(err)
		}
		logoutUrl := i.Issuer
		logoutUrl.RawQuery = (url.Values{"redirect_uri": []string{i.PostLogoutUrl.String()}}).Encode()
		logoutUrl.Path = "auth/realms/solutions/protocol/openid-connect/logout"
		c.Redirect(http.StatusFound, logoutUrl.String())
	}
}

func callbackHandler(i InitParams, verifier *oidc.IDTokenVerifier, config *oauth2.Config) func(c *gin.Context) {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		serverSession := sessions.Default(c)

		state, ok := (serverSession.Get("oidcState")).(string)
		if handleOk(c, i, ok, "failed to parse state") {
			return
		}

		if handleOk(c, i, c.Query("state") == state, "get 'state' param didn't match local 'state' value") {
			return
		}

		oauth2Token, err := config.Exchange(ctx, c.Query("code"))
		if handleError(c, i, err, "failed to exchange token") {
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if handleOk(c, i, ok, "no id_token field in oauth2 token") {
			return
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if handleError(c, i, err, "failed to verify id token") {
			return
		}

		var claims map[string]interface{}
		err = idToken.Claims(&claims)
		if handleError(c, i, err, "failed to parse id token") {
			return
		}

		claimsJson, err := json.Marshal(claims)
		if handleError(c, i, err, "failed to marshal id token: ") {
			return
		}

		originalRequestUrl, ok := (serverSession.Get("oidcOriginalRequestUrl")).(string)
		if handleOk(c, i, ok, "failed to parse originalRequestUrl") {
			return
		}

		serverSession.Set("oidcAuthorized", true)
		serverSession.Set("oidcState", nil)
		serverSession.Set("oidcOriginalRequestUrl", nil)
		serverSession.Set("oidcClaims", string(claimsJson))
		serverSession.Set("refreshToken", oauth2Token.RefreshToken)

		err = serverSession.Save()
		if handleError(c, i, err, "failed save sessions.") {
			return
		}

		c.Redirect(http.StatusFound, originalRequestUrl)
	}
}

func protectMiddleware(config *oauth2.Config) func(c *gin.Context) {
	return func(c *gin.Context) {
		serverSession := sessions.Default(c)
		authorized := serverSession.Get("oidcAuthorized")
		refreshToken := serverSession.Get("refreshToken")
		var tok *oauth2.Token
		if refreshToken != nil {
			ts := config.TokenSource(c, &oauth2.Token{RefreshToken: refreshToken.(string)})
			var err error
			tok, err = ts.Token()
			if err != nil {
				log.Infof("error when check token validity : %s", err)
			}
		}

		if (authorized != nil && authorized.(bool)) && tok.Valid() ||
			c.Request.URL.Path == "oidc-callback" {
			c.Next()
			return
		}
		log.Info("unauthorized")
		state := RandomString(16)
		serverSession.Set("oidcAuthorized", false)
		serverSession.Set("oidcState", state)
		serverSession.Set("oidcOriginalRequestUrl", c.Request.URL.String())
		err := serverSession.Save()
		if err != nil {
			log.Error("failed save sessions. error: " + err.Error()) // todo handle more gracefully
		}
		c.Redirect(http.StatusTemporaryRedirect, config.AuthCodeURL(state)) // redirect to authorization server
	}

}

func handleError(c *gin.Context, i InitParams, err error, message string) bool {
	if err == nil {
		return false
	}
	_ = c.Error(errors.New(message))
	i.ErrorHandler(c)
	c.Abort()
	return true
}

func handleOk(c *gin.Context, i InitParams, ok bool, message string) bool {
	if ok {
		return false
	}
	return handleError(c, i, errors.New("not ok"), message)
}

// random string
var src = rand.NewSource(time.Now().UnixNano())

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func RandomString(n int) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
