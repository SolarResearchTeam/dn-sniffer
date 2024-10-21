package oidc

import (
	"context"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"sync"
	"errors"
	"net/http"
	"crypto/tls"

	config "github.com/SolarResearchTeam/dn-sniffer/config"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
)

type OIDCConfig struct {
	Provider     *oidc.Provider
	OAuth2Config *oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	LoginURL     func(state string) string
}

var oidcConfigInstance *OIDCConfig

func InitOIDCConfig() error {
	if !config.Conf.OIDC.Enabled {
		return errors.New("OIDC disabled")
	}

	transport := http.Transport{}
	transport.TLSClientConfig = &tls.Config{
	    InsecureSkipVerify:true,
	}
	myClient := &http.Client{Transport: &transport}
	ctx := oidc.ClientContext(context.Background(), myClient)
	provider, err := oidc.NewProvider(ctx, config.Conf.OIDC.OIDC_url)
	if err != nil {
		log.Error("OIDC(InitOIDCConfig)", err.Error())
		return err
	}

	proto := ""
	if config.Conf.WebServerConf.UseTLS {
		proto = "s"
	}
	callback := "http" + proto + "://" + config.Conf.WebServerConf.Hostname + "/oauth/callback"

	oauth2Config := &oauth2.Config{
		ClientID:     config.Conf.OIDC.ClientId,
		ClientSecret: config.Conf.OIDC.ClientSecret, 
		RedirectURL:  callback,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "dnsniffer"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

	oidcConfigInstance = &OIDCConfig{
		Provider:     provider,
		OAuth2Config: oauth2Config,
		Verifier:     verifier,
		LoginURL: func(state string) string {
			return oauth2Config.AuthCodeURL(state)
		},
	}

	return nil
}

var mu sync.Mutex

func GetOIDCConfigInstance() (*OIDCConfig, error) {
	mu.Lock()
	defer mu.Unlock()
	if oidcConfigInstance == nil {
		err := InitOIDCConfig()
		if err != nil {
			return nil, err
		}
	}
	return oidcConfigInstance, nil
}