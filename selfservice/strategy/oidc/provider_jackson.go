// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/ory/x/urlx"
)

type ProviderJackson struct {
	*ProviderGenericOIDC
}

func NewProviderJackson(
	config *Configuration,
	reg Dependencies,
) Provider {
	return &ProviderJackson{
		ProviderGenericOIDC: &ProviderGenericOIDC{
			config: config,
			reg:    reg,
		},
	}
}

func (j *ProviderJackson) setProvider(ctx context.Context) {
	fmt.Println("jackson: setProvider:")

	if j.ProviderGenericOIDC.p == nil {
		internalHost := strings.TrimSuffix(j.config.TokenURL, "/api/oauth/token")
		config := oidc.ProviderConfig{
			IssuerURL:     j.config.IssuerURL,
			AuthURL:       j.config.AuthURL,
			TokenURL:      j.config.TokenURL,
			DeviceAuthURL: "",
			UserInfoURL:   internalHost + "/api/oauth/userinfo",
			JWKSURL:       internalHost + "/oauth/jwks",
			Algorithms:    []string{"RS256"},
		}
		j.ProviderGenericOIDC.p = config.NewProvider(j.withHTTPClientContext(ctx))
	}
}

func (j *ProviderJackson) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	fmt.Println("jackson: OAuth2:")
	j.setProvider(ctx)
	endpoint := j.ProviderGenericOIDC.p.Endpoint()
	config := j.oauth2ConfigFromEndpoint(ctx, endpoint)
	config.RedirectURL = urlx.AppendPaths(
		j.reg.Config().SAMLRedirectURIBase(ctx),
		"/self-service/methods/saml/callback/"+j.config.ID).String()

	return config, nil
}
