package main

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/mitchellh/mapstructure"
	hydra "github.com/ory/hydra-client-go"
	kratos "github.com/ory/kratos-client-go"
	"net/http"
	"net/url"
	"os"
)

var (
	hydraClient  = NewHydraClient()
	kratosClient = NewKratosClient()
)

type Traits struct {
	NetID string `mapstructure:"netid"`
	Name  string `mapstructure:"name"`
	Email string `mapstructure:"email"`
}

func NewHydraClient() *hydra.APIClient {
	conf := hydra.NewConfiguration()
	conf.Servers = hydra.ServerConfigurations{
		{
			URL: os.Getenv("HYDRA_ADMIN_URL"),
		},
	}
	return hydra.NewAPIClient(conf)
}

func NewKratosClient() *kratos.APIClient {
	conf := kratos.NewConfiguration()
	conf.Servers = kratos.ServerConfigurations{
		{
			URL: os.Getenv("KRATOS_ADMIN_URL"),
		},
	}
	return kratos.NewAPIClient(conf)
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

func main() {
	r := gin.Default()

	r.GET("/kratos-hydra/login", func(c *gin.Context) {
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

		// Now we're going to kratos login screen
		callbackQuery := url.Values{}
		callbackQuery.Add("login_challenge", challenge)
		callbackURL := url.URL{
			Scheme:   c.Request.URL.Scheme,
			Host:     c.Request.URL.Host,
			Path:     "/kratos-hydra/callback",
			RawQuery: callbackQuery.Encode(),
		}

		redirectQuery := url.Values{}
		redirectQuery.Add("return_to", callbackURL.String())
		redirectTo := url.URL{
			Scheme:   c.Request.URL.Scheme,
			Host:     c.Request.URL.Host,
			Path:     "/kratos/self-service/login/browser",
			RawQuery: redirectQuery.Encode(),
		}

		c.Redirect(http.StatusTemporaryRedirect, redirectTo.String())
	})

	r.GET("/kratos-hydra/callback", func(c *gin.Context) {
		sess, _, err := kratosClient.V0alpha2Api.ToSession(c).Cookie(c.GetHeader("cookie")).Execute()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		traits, ok := sess.Identity.Traits.(map[string]interface{})
		if !ok {
			c.AbortWithError(http.StatusInternalServerError, errors.New("traits not deserializable"))
			return
		}
		netID, ok := traits["netid"].(string)
		if !ok {
			c.AbortWithError(http.StatusInternalServerError, errors.New("traits field not deserializable"))
			return
		}

		acceptLoginChallenge(c, c.Query("login_challenge"), netID)
	})

	r.GET("/kratos-hydra/consent", func(c *gin.Context) {
		challenge := c.Query("consent_challenge")

		reqBody, _, err := hydraClient.AdminApi.GetConsentRequest(c).ConsentChallenge(challenge).Execute()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		sess, _, err := kratosClient.V0alpha2Api.ToSession(c).Cookie(c.GetHeader("cookie")).Execute()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		var traits Traits
		err = mapstructure.Decode(sess.Identity.Traits, &traits)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, errors.New("traits not deserializable"))
			return
		}

		idTokenData := make(map[string]interface{}, 0)
		idTokenData["netid"] = traits.NetID
		idTokenData["name"] = traits.Name
		idTokenData["given_name"] = traits.Name
		idTokenData["email"] = traits.Email

		remember := false
		acceptReq := hydra.AcceptConsentRequest{
			GrantAccessTokenAudience: reqBody.RequestedAccessTokenAudience,
			GrantScope:               reqBody.RequestedScope,
			Remember:                 &remember,
			RememberFor:              nil,
			Session: &hydra.ConsentRequestSession{
				IdToken: idTokenData,
			},
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

	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
