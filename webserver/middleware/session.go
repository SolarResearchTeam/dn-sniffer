package middleware

import (
	"time"
	"net/http"

	conf "github.com/SolarResearchTeam/dn-sniffer/config"

	"github.com/google/uuid"
)
var Storage = Session_storage{}

func init() {
	Storage.Sessions = make(map[string]*Session)
}

func SessionStoreInit() {
	if conf.Conf.WebServerConf.UseTLS {
		Storage.Settings.Secure = true
	}


	if conf.Conf.Cookie.Domain  != "" {
		Storage.Settings.Domain = conf.Conf.Cookie.Domain
	}
	Storage.Settings.Name = conf.Conf.Cookie.Name
	Storage.Settings.Path = conf.Conf.Cookie.Path
	Storage.MaxAge = int64(conf.Conf.Cookie.MaxAge)

	Storage.Settings.HttpOnly = true
	//Storage.Settings.SameSite = 3
}

type Cookie_options struct {
	Name 		string
	Path 		string
	Domain  	string	
	Secure 		bool
	SameSite    int
	HttpOnly	bool
}

type Session_storage struct {
	Settings Cookie_options
	MaxAge int64
	Sessions map[string]*Session
}

func (s *Session_storage) Get(r *http.Request) *Session {
	if c, errCookie := r.Cookie(s.Settings.Name); errCookie == nil {
		if session, ok := s.Sessions[c.Value]; ok {
			if session != nil {
				if (time.Now().Unix() - session.Created) < s.MaxAge {
					return session
				}
				session.Wipe()
			}
		}
	}
	return NewSession()
}

type Session struct {
	Id string
	Values map[interface{}]interface{}
	Created int64
}

func NewSession() *Session {
	session :=  &Session{
		Id: uuid.New().String(),
		Values: make(map[interface{}]interface{}),
		Created: time.Now().Unix(),
	}
	return session
}

func (s *Session) Save(w http.ResponseWriter) {
	Storage.Sessions[s.Id] = s
	http.SetCookie(w, newcookie(s.Id))
}

func (s *Session) Delete(w http.ResponseWriter) {
	s.Wipe()
	http.SetCookie(w, &http.Cookie{Name:Storage.Settings.Name,MaxAge:-1})
}

func (s *Session) Wipe() {
	delete(Storage.Sessions, s.Id)
}

func newcookie(id string) *http.Cookie {
	return &http.Cookie{
		Name:        Storage.Settings.Name,
		Value:       id,
		Path:        Storage.Settings.Path,
		Domain:      Storage.Settings.Domain,
		MaxAge:      int(Storage.MaxAge),
		Secure:      Storage.Settings.Secure,
		HttpOnly:    Storage.Settings.HttpOnly,
	}
}
