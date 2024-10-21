package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/utils"
)

var AllowedNetworks []net.IPNet

// Middlewares applier
func Use(handler http.HandlerFunc, middleware ...func(http.Handler) http.HandlerFunc) http.HandlerFunc {
	for _, mid := range middleware {
		handler = mid(handler)
	}
	return handler
}

// Load user to request context
func GetContext(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := Storage.Get(r)
		if user, ok := session.Values["user"]; ok {
			u := user.(*ds.Users)
			r = set(r, "user", u)
		} else {
			r = set(r, "user", nil)
		}
		handler.ServeHTTP(w, r)
	}
}

// Override request max size (in golang 10MB is default)
func SetMaxSize(handler http.Handler, size int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, size*1024*1024)
		handler.ServeHTTP(w, r)
	}
}

// Security headers
func ApplySecHeaders(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csp := "frame-ancestors 'none';"
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	}
}

func CheckIP(handler http.Handler) http.HandlerFunc {
	if AllowedNetworks == nil {
		loadWhiteList()
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if len(AllowedNetworks) > 0 {
			if checkAddr(strings.Split(r.RemoteAddr, ":")[0]) {
				handler.ServeHTTP(w, r)
			} else {
				utils.GetTemplate(w, r, "403").ExecuteTemplate(w, "base", nil)
			}
		} else {
			handler.ServeHTTP(w, r)
		}
	}
}

// Set value to request context
func set(r *http.Request, key, value interface{}) *http.Request {
	if value == nil {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), key, value))
}

func loadWhiteList() {
	AllowedNetworks = []net.IPNet{}
	for _, network := range config.Conf.WebServerConf.Whitelist {
		if network == "*" {
			AllowedNetworks = []net.IPNet{}
			return
		}
		_, ipnetA, _ := net.ParseCIDR(network)
		if ipnetA != nil {
			AllowedNetworks = append(AllowedNetworks, *ipnetA)
		}
	}
}

func checkAddr(addr string) bool {
	ip := net.ParseIP(addr)
	if ip != nil {
		for _, network := range AllowedNetworks {
			if network.Contains(ip) {
				return true
			}
		}
	}
	return false
}
