package ssl

import (
	"strings"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
	conf "github.com/SolarResearchTeam/dn-sniffer/config"
	
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}


type DNSProvider struct {
	TLD string
	RecId string
}

func NewDNSProvider() (*DNSProvider, error) {
	return &DNSProvider{}, nil
}

func (d *DNSProvider) Present(domain, token, keyAuth string) error {
    info := dns01.GetChallengeInfo(domain, keyAuth)

    record := ds.Record{}
    record.Type = "TXT"
    d.TLD = strings.TrimRight(info.FQDN,".")
    record.TLD = strings.TrimRight(info.FQDN,".")
    record.Value = info.Value

    id, err := models.Database.RecordAdd(&record)
    if err != nil {
    	return err
    }
    d.RecId = id
    return nil
}

func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
    _, err := models.Database.RecordDelete(d.RecId)
    return err
}



func Gencert(domain string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	myUser := MyUser{
		Email: "",
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	DNS, err := NewDNSProvider()
	if err != nil {
	    return err
	}
	client.Challenge.SetDNS01Provider(DNS,dns01.CondOption(true,dns01.DisableCompletePropagationRequirement()))

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	path := conf.Conf.SSL.Path
	err = os.MkdirAll(path+"/"+domain, os.ModePerm)
	if err != nil {
		return err
	}

	os.Remove(path+"/"+domain+"/cert.pem")
	certOut, err := os.Create(path+"/"+domain+"/cert.pem")
	if err != nil {
		return err
	}
	certOut.Write(certificates.Certificate)
	certOut.Close()

	os.Remove(path+"/"+domain+"/key.pem")
	keyOut, err := os.OpenFile(path+"/"+domain+"/key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	keyOut.Write(certificates.PrivateKey)
	keyOut.Close()

	err = ReloadCerts()
	return err
}