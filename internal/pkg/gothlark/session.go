package gothlark

import (
	"encoding/json"
	"errors"
	"github.com/chyroc/lark"
	"strings"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with Lark.
type Session struct {
	AuthURL     string
	AccessToken string
	OpenID      string
	UnionID     string
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Lark provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Lark and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)

	ctx := goth.ContextForClient(p.httpClient)
	req := lark.GetAccessTokenReq{
		GrantType: "authorization_code",
		Code:      params.Get("code"),
	}
	body, _, err := p.larkClient.Auth.GetAccessToken(ctx, &req)
	if err != nil {
		return "", err
	}

	s.AccessToken = body.AccessToken
	s.OpenID = body.OpenID
	s.UnionID = body.UnionID
	return s.AccessToken, nil
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}
