package ssl

import (
	"os"
	"crypto/x509"
	"encoding/pem"
	"time"
	"fmt"

	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	config "github.com/SolarResearchTeam/dn-sniffer/config"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
)


func Renewer() {
	path := config.Conf.SSL.Path
	for {
		renewrs, err := models.Database.GetAllRenewers()
		if err != nil {
			log.Error("SSL(Renewer_GetAllRenewers)", err.Error())
			continue
		}
		for _,renewer := range *renewrs {
    		cert_bytes,err := os.ReadFile(path + "/" + renewer.Domain +"/cert.pem")
			if err == nil {
				 block, rest := pem.Decode(cert_bytes)
				 if block == nil || len(rest) > 0 {
				 	log.Error("SSL(Renewer_Decode)", "Failed to decode. Cert not in PEM format?")
					continue
				 } else {
					cert,err := x509.ParseCertificate(block.Bytes)
					if err == nil {
						now := time.Now()
						diff := now.Sub(cert.NotAfter)
						if diff.Hours() < 72 {
							log.Info("SSL(Renewer_Gencert)", fmt.Sprintf("Trying to renew %s cert",renewer.Domain))
							err = Gencert(renewer.Domain)
							if err != nil {
								log.Error("SSL(Renewer_Gencert)", err.Error())
								continue
							}
							log.Info("SSL(Renewer_Gencert)", fmt.Sprintf("Success renew %s cert",renewer.Domain))
						}

					} else {
						log.Error("SSL(Renewer_ParseCertificate)", err.Error())
						continue
					}
				}
			} else {
				log.Error("SSL(Renewer_ParseCertificate)", err.Error())
				continue
			}
		}
		time.Sleep(time.Second * 60 * 60 * 24)
	}
}