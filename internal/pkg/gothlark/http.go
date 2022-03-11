package gothlark

import (
	"context"
	"net/http"
)

type HttpClient struct {
	wrapped *http.Client
}

func wrapHttpClient(client *http.Client) *HttpClient {
	return &HttpClient{
		wrapped: client,
	}
}

func (c *HttpClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	reqWithCtx := req.WithContext(ctx)
	return c.wrapped.Do(reqWithCtx)
}
