package gothlark

import (
	"errors"
	"fmt"
	"github.com/chyroc/lark"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"net/http"
)

// New creates a new Lark provider, and sets up important connection details.
func New(appID, appSecret, callbackURL string) *Provider {
	httpClient := goth.HTTPClientWithFallBack(nil)

	return &Provider{
		providerName: "lark",
		CallbackURL:  callbackURL,
		httpClient:   httpClient,
		larkClient: lark.New(
			lark.WithHttpClient(wrapHttpClient(httpClient)),
			lark.WithAppCredential(appID, appSecret),
		),
	}
}

// Provider is the implementation of `goth.Provider` for accessing WeCom.
type Provider struct {
	providerName string
	CallbackURL  string
	httpClient   *http.Client
	larkClient   *lark.Lark
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Debug is a no-op for the Lark package.
func (p *Provider) Debug(_ bool) {}

// BeginAuth asks Lark for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	req := lark.GenOAuthURLReq{
		RedirectURI: p.CallbackURL,
		State:       state,
	}
	authURL := p.larkClient.Auth.GenOAuthURL(goth.ContextForClient(p.httpClient), &req)

	session := &Session{
		AuthURL: authURL,
	}
	return session, nil
}

// FetchUser will go to Lark and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		RawData: map[string]interface{}{
			"open_id":  sess.OpenID,
			"union_id": sess.UnionID,
		},
		Provider: p.Name(),
	}

	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	ctx := goth.ContextForClient(p.httpClient)
	req := lark.GetUserReq{
		UserIDType: lark.IDTypePtr(lark.IDTypeUnionID),
		UserID:     sess.UnionID,
	}
	data, _, err := p.larkClient.Contact.GetUser(ctx, &req)
	if err != nil {
		return user, err
	}

	if data.User.EmployeeNo == "" {
		return user, errors.New("user's NetID (employee_no) is not configured in Lark")
	}

	user.UserID = data.User.EmployeeNo
	user.Name = data.User.Name
	user.AvatarURL = data.User.Avatar.AvatarOrigin

	return user, nil
}

// RefreshToken refresh token is not provided by Lark
func (p *Provider) RefreshToken(_ string) (*oauth2.Token, error) {
	return nil, errors.New("refresh token is not provided by lark")
}

// RefreshTokenAvailable refresh token is not provided by Lark
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
