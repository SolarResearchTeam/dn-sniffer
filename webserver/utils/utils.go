package utils

import (
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"encoding/base64"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var RegexPatterns = map[string]*regexp.Regexp{
	"domain":     regexp.MustCompile(`^([a-z0-9A-Z]+(-[a-z0-9A-Z]+)*\.)+[a-zA-Z]{2,}$`),
	"username":   regexp.MustCompile(`^[a-zA-Z0-9\.\_]{2,}$`),
	"first_name": regexp.MustCompile(`^[a-zA-Z0-9]{2,}$`),
	"last_name":  regexp.MustCompile(`^[a-zA-Z0-9]{2,}$`),
	"phone":      regexp.MustCompile(`^[0-9 \(\)\-]{2,}$`),
	"email":      regexp.MustCompile(`^[A-Z0-9\.\_\%\+\-a-z]+\@[A-Z0-9\.\-a-z]+\.[A-Za-z]{2,}$`),
	"company":    regexp.MustCompile(`^[A-Za-z0-9]{2,}$`),
}

type FileSystem struct {
	fs http.FileSystem
}

func (ufs FileSystem) Open(name string) (http.File, error) {
	f, err := ufs.fs.Open(name)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if s.IsDir() {
		index := strings.TrimSuffix(name, "/") + "/index.html"
		_, err := ufs.fs.Open(index)
		if err != nil {
			return nil, os.ErrPermission
		}
	}
	return f, nil
}

func IsPortAvailable(port string) bool {
	address := net.JoinHostPort("127.0.0.1", port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err == nil {
		return false
	}
	if conn != nil {
		return false
	}

	return true
}

func GeneratePasswordHash(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func Dir(filepath string) http.FileSystem {
	return FileSystem{
		fs: http.Dir(filepath),
	}
}

func RegExChecker(input string, whattocheck string) bool {
	if pattern, ok := RegexPatterns[whattocheck]; ok {
		return pattern.MatchString(input)
	}
	return false
}

func FileExist(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}

func DefaultPayload(token, url, uuid string) string {
	b, _ := ioutil.ReadFile("templates/xsshunter.js")
	payload := strings.Replace(string(b), "{{.MotherShipToken}}", token, 1)
	payload = strings.Replace(payload, "{{.MotherShipUrl}}", url, 2)
	payload = strings.Replace(payload, "{{.UUID}}", uuid, 2)
	return payload
}

func GenerateSamples(msurl, name, hname string) string {
	var temp string
	b, _ := ioutil.ReadFile("templates/payloads.txt")
	uri := msurl
	temp = strings.Replace(string(b), "{{PayloadURL}}", uri, 3)
	temp = strings.Replace(temp, "{{BASE64PayloadURL}}", url.PathEscape(base64.StdEncoding.EncodeToString([]byte(uri))), 3)
	return temp
}

func GetTemplate(w http.ResponseWriter, r *http.Request, tmpl string) *template.Template {
	var err error
	templates := template.New("template")
	_, err = templates.ParseFiles("templates/base.html", "templates/nav.html", "templates/header.html", "templates/"+tmpl+".html")
	return template.Must(templates, err)
}