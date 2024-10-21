package ssl

import (
	"crypto/tls"
	"net/http"
	"net"
)

//Gloabl config for all. Since everybody uses it, we can onflight edit it in one place
var GlobalTLSConfig tls.Config


func NewTlsConfig() error {
	GlobalTLSConfig = tls.Config{
		NextProtos:   []string{"h2", "http/1.1"},
		InsecureSkipVerify:       true,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Kept for backwards compatibility with some clients
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}


	err := ReloadCerts()
	return err
}


func ListenAndServeTLS(srv *http.Server) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	defer ln.Close()

	tlsListener := tls.NewListener(ln, &GlobalTLSConfig)
	servErr := srv.Serve(tlsListener)
	return servErr
}