package main

import (
	"github.com/SYSU-ECNC/oidc-adapter/internal/pkg/gothlark"
	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	hydra "github.com/ory/hydra-client-go"
	"net/http"
	"net/url"
	"os"
)

var (
	hydraClient = NewHydraClient()
)

func NewHydraClient() *hydra.APIClient {
	conf := hydra.NewConfiguration()
	conf.Servers = hydra.ServerConfigurations{
		{
			URL: os.Getenv("HYDRA_ADMIN_URL"),
		},
	}
	return hydra.NewAPIClient(conf)
}

func acceptLoginChallenge(c *gin.Context, challenge, subject string) {
	acceptBody, _, err := hydraClient.AdminApi.AcceptLoginRequest(c).
		LoginChallenge(challenge).
		AcceptLoginRequest(*hydra.NewAcceptLoginRequest(subject)).
		Execute()

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, acceptBody.RedirectTo)
}

// Workaround for goth to obtain providerName from gin's Params
func obtainProvider(c *gin.Context) {
	query := c.Request.URL.Query()
	query.Add("provider", c.Param("provider"))
	c.Request.URL.RawQuery = query.Encode()
}

func main() {
	goth.UseProviders(
		gothlark.New(
			os.Getenv("LARK_APP_ID"),
			os.Getenv("LARK_APP_SECRET"),
			os.Getenv("LARK_OAUTH_CALLBACK_URL"),
		),
	)

	r := gin.Default()

	r.GET("/oidc-adapter/login", func(c *gin.Context) {
		challenge := c.Query("login_challenge")

		body, _, err := hydraClient.AdminApi.GetLoginRequest(c).LoginChallenge(challenge).Execute()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		// If hydra was already able to authenticate the user, skip will be true and we don't need to re-authenticate
		// the user.
		if body.Skip {
			// Now it's time to grant the login request. You could also deny the request if something went terribly wrong
			// (for example your arch-enemy logging in!)
			acceptLoginChallenge(c, challenge, body.Subject)
			return
		}

		query := url.Values{}
		query.Add("state", challenge)
		redirectTo := url.URL{
			Scheme:   c.Request.URL.Scheme,
			Host:     c.Request.URL.Host,
			Path:     "/oidc-adapter/auth/lark",
			RawQuery: query.Encode(),
		}
		c.Redirect(http.StatusTemporaryRedirect, redirectTo.String())
	})

	r.GET("/oidc-adapter/consent", func(c *gin.Context) {
		challenge := c.Query("consent_challenge")

		reqBody, _, err := hydraClient.AdminApi.GetConsentRequest(c).ConsentChallenge(challenge).Execute()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		remember := true
		rememberFor := int64(600)
		acceptReq := hydra.AcceptConsentRequest{
			GrantAccessTokenAudience: reqBody.RequestedAccessTokenAudience,
			GrantScope:               reqBody.RequestedScope,
			Remember:                 &remember,
			RememberFor:              &rememberFor,
			Session:                  nil,
		}
		acceptBody, _, err := hydraClient.AdminApi.AcceptConsentRequest(c).
			ConsentChallenge(challenge).
			AcceptConsentRequest(acceptReq).
			Execute()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
		}
		c.Redirect(http.StatusTemporaryRedirect, acceptBody.RedirectTo)
	})

	r.GET("/oidc-adapter/auth/:provider/callback", obtainProvider, func(c *gin.Context) {
		user, err := gothic.CompleteUserAuth(c.Writer, c.Request)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		acceptLoginChallenge(c, c.Query("state"), user.UserID)
	})

	r.GET("/oidc-adapter/auth/:provider", obtainProvider, func(c *gin.Context) {
		gothic.BeginAuthHandler(c.Writer, c.Request)
	})

	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
