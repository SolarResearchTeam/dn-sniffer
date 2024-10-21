package config

import (
	"encoding/json"
	"io/ioutil"
)

// WebServer configuration details
type WebServer struct {
	WebServerURL string `json:"webserver_url"`
	Hostname     string `json:"hostname"`
	UseTLS       bool   `json:"use_tls"`
	Whitelist 	[]string `json:"whitelist"`
}
type MongoDB struct {
	MongoMainDBName      string `json:"main_db_name"`

	MongoDNSDBName 		 string `json:"dns_db_name"`
	MongoHitsDBName      string `json:"dns_hits_db_name"`
	MongoInteractDBName  string `json:"interact_db_name"`
	MongoXSSHunterDBName string `json:"xsshunter_db_name"`

	MongoDBPath          string `json:"db_path"`
	MongoDBUser          string `json:"db_user"`
	MongoDBPassword      string `json:"db_password"`
}

type Cookie struct {
	Name 		string	`json:"name"`
	Path 		string	`json:"path"`
	Domain 		string	`json:"domain"`
	MaxAge 		int 	`json:"maxage"`
}

type DNS struct {
	PrimaryZone []string `json:"primary_zone"`
	UseTCP      bool   `json:"use_tcp"`
	UseUDP      bool   `json:"use_udp"`
	TCPPort     string `json:"tcpport"`
	UDPPort     string `json:"udpport"`
	ListenIP    string `json:"listenip"`
	AnswerIP    string `json:"answerip"`
	TTL         int    `json:"ttl"`
}

type XSSHunter struct {
	XSSHunterURL  string `json:"xsshunter_url"`
	UseTLS        bool   `json:"use_tls"`
}

type SMTP struct {
	From          string `json:"from"`
	ServerAddress string `json:"smtp_server_address"`
	ServerPort    int    `json:"smtp_server_port"`
	User          string `json:"smtp_server_username" default:""`
	Password      string `json:"smtp_server_password" default:""`
	TLS           bool   `json:"use_tls"`
	VerifyTLS     bool   `json:"verify_tls"`
}

type Interact struct {
	ListenIP         string `json:"listen_ip"`
	TmpDir           string `json:"share_dir"`
}

type SSL struct {
	Path           string `json:"path"`
}

type OIDC struct {
	Enabled 		bool 	`json:"enabled"`
	Provider_Name 	string 	`json:"provider_name"`
	OIDC_url 		string 	`json:"oidc_url"`
	ClientId 		string 	`json:"client_id"`
	ClientSecret	string 	`json:"cleint_secret"`
	CreateUsers 	bool 	`json:"create_users"`
}

// Config represents the configuration information.
type Config struct {
	WebServerConf WebServer `json:"web_server"`
	MongoConf     MongoDB   `json:"mongo_db"`
	DNS           DNS       `json:"dns"`
	Interact      Interact  `json:"interact"`
	SMTP          SMTP      `json:"smtp"`
	XSSHunter     XSSHunter `json:"xsshunter"`
	SSL 		  SSL  		`json:"ssl"`
	Cookie 		  Cookie 	`json:"cookie"`
	OIDC 		  OIDC 		`json:"oidc"`
}

var Conf Config

// LoadConfig loads the configuration from the specified filepath
func LoadConfig(filepath string) (*Config, error) {
	// Get the config file
	configFile, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(configFile, &Conf)
	if err != nil {
		return nil, err
	}
	return &Conf, nil
}
