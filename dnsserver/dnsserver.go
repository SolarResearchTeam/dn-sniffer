package dnsserver

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
	"fmt"

	"github.com/miekg/dns"

	"github.com/SolarResearchTeam/dn-sniffer/config"
	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	log "github.com/SolarResearchTeam/dn-sniffer/logger"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
)

type DNSServer struct {
	tcpserver *dns.Server
	udpserver *dns.Server
}

type DNSTypes map[uint16]string

var DNSType = DNSTypes{
	1:  "A",
	2:  "NS",
	5:  "CNAME",
	6:  "SOA",
	12: "PTR",
	28: "AAAA",
	16: "TXT",
	15: "MX",
}

func NewDnsServer() *DNSServer {
	dns.HandleFunc(".", DNSRequestHandler)
	var tcpDNSServer *dns.Server = nil
	var udpDNSServer *dns.Server = nil
	if config.Conf.DNS.UseTCP {
		tcpDNSServer = &dns.Server{
			Addr: config.Conf.DNS.ListenIP + ":" + config.Conf.DNS.TCPPort,
			Net:  "tcp",
		}
	}
	if config.Conf.DNS.UseUDP {
		udpDNSServer = &dns.Server{
			Addr: config.Conf.DNS.ListenIP + ":" + config.Conf.DNS.UDPPort,
			Net:  "udp",
		}
	}
	dnsserver := &DNSServer{
		tcpserver: tcpDNSServer,
		udpserver: udpDNSServer,
	}
	return dnsserver
}

func (ds *DNSServer) Start() {
	if ds.tcpserver != nil {
		go func() {
			err := ds.tcpserver.ListenAndServe()
			if err != nil {
				log.Fatal("DNSServer_TCP(Start)", err.Error())
			}
			log.Console_Info("DNSServer_TCP(Graceful stop)")
		}()

	}
	if ds.udpserver != nil {
		go func() {
			err := ds.udpserver.ListenAndServe()
			if err != nil {
				log.Fatal("DNSServer_UDP(Start)", err.Error())
			}
			log.Console_Info("DNSServer_UDP(Graceful stop)")
		}()
	}
}


func (ds *DNSServer) Stop() {
	_, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	if ds.tcpserver != nil {
		ds.tcpserver.Shutdown()
	}
	if ds.udpserver != nil {
		ds.udpserver.Shutdown()
	}
}

func FindZone(tld string) string {
	for strings.Contains(tld, ".") {
		exist, err := models.Database.TLDExist(tld)
		if err != nil {
			return ""
		}
		if exist {
			return tld
		}
		tld = strings.SplitN(tld, ".", 2)[1]
	}
	return ""
}

func DNSRequestHandler(w dns.ResponseWriter, r *dns.Msg) {
	domain := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, "."))

	inzones := false
	for _, zone := range config.Conf.DNS.PrimaryZone {
		if strings.HasSuffix(domain, zone) {
			inzones = true 
			break
		}
	}

	if !inzones {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{}
		w.WriteMsg(m)
		return
	} 

	tp := DNSType[r.Question[0].Qtype]
	zonename := FindZone(domain)
	inblackhole, err := models.Database.InBlackHole(domain, strings.Split(w.RemoteAddr().String(), ":")[0])
	if err != nil {
		log.Error("DNSServer(RequestHandler)", fmt.Sprintf("Type: %s, Domain: %s, Err: %s",tp,domain,err.Error()))
	}
	if !(inblackhole) {
		hit := ds.Hit{
			Time:       time.Now().Format("2006.01.02 15:04:06"),
			DomainName: domain,
			IP:         w.RemoteAddr().String(),
		}

		if zonename != "" {
			_, err := models.Database.WriteHit(zonename, &hit)
			if err != nil {
				log.Error("DNSServer(RequestHandler)", fmt.Sprintf("Type: %s, Domain: %s, Err: %s",tp,domain,err.Error()))
			}
		} else {
			_, err := models.Database.WriteHit("other", &hit)
			if err != nil {
				log.Error("DNSServer(RequestHandler)", fmt.Sprintf("Type: %s, Domain: %s, Err: %s",tp,domain,err.Error()))
			}
		}
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	var rr []dns.RR

	switch tp {
	case "TXT":
		rr = prepTXT(domain)
	case "A":
		rr = prepA(domain)
	case "AAAA":
		rr = prepAAAA(domain)
	case "MX":
		rr = prepMX(domain)
	case "NS":
		rr = prepNS(domain)
	case "SOA":
		rr = prepSOA(domain)
	case "PTR":
		rr = prepPTR(domain)
	case "CNAME":
		rr = prepCNAME(domain)
	default:
		rr = prepAll(domain)
	}

	m.Answer = rr
	err = w.WriteMsg(m)
	if err != nil {
		log.Error("DNSServer(RequestHandler)", fmt.Sprintf("Type: %s, Domain: %s, Err: %s",tp,domain,err.Error()))
	}
}

func prepTXT(domain string) []dns.RR {
	var answer = []dns.RR{}
	records, err := models.Database.RecordByTypeAndName(domain, "TXT")
	if err != nil {
		log.Error("DNSServer(prepTXT)", err.Error())
		return answer
	}
	for _, record := range *records {
		rr1 := new(dns.TXT)
		rr1.Hdr = dns.RR_Header{
			Name:   domain + ".",
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    uint32(config.Conf.DNS.TTL),
		}
		rr1.Txt = []string{record.Value}
		answer = append(answer, rr1)
	}

	return answer
}

func prepPTR(domain string) []dns.RR {
	var answer = []dns.RR{}
	records, err := models.Database.RecordByTypeAndName(domain, "PTR")
	if err != nil {
		log.Error("DNSServer(prepPTR)", err.Error())
		return answer
	}
	for _, record := range *records {
		rr1 := new(dns.PTR)
		rr1.Hdr = dns.RR_Header{
			Name:   domain + ".",
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    uint32(config.Conf.DNS.TTL),
		}
		rr1.Ptr = strings.TrimRight(record.Value, ".") + "."
		answer = append(answer, rr1)
	}

	return answer
}

func prepCNAME(domain string) []dns.RR {
	var answer = []dns.RR{}
	records, err := models.Database.RecordByTypeAndName(domain, "CNAME")
	if err != nil {
		log.Error("DNSServer(prepCNAME)", err.Error())
		return answer
	}
	for _, record := range *records {
		rr1 := new(dns.CNAME)
		rr1.Hdr = dns.RR_Header{
			Name:   domain + ".",
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    uint32(config.Conf.DNS.TTL),
		}
		rr1.Target = strings.TrimRight(record.Value, ".") + "."
		answer = append(answer, rr1)
	}

	return answer
}

func prepA(domain string) []dns.RR {
	var answer = []dns.RR{}

	//Rebind part
	rebindexist, err := models.Database.RebindExist(domain)
	if err != nil {
		//log.Error("DNSServer(prepA)", err.Error())
	}
	if rebindexist {
		rebind, err := models.Database.GetRebind(domain)
		if err != nil {
			//log.Error("DNSServer(prepA)", err.Error())
		}
		tm, _ := strconv.Atoi(rebind.Time)
		if (rebind.LastRequest == 0) || ((time.Now().Unix() - rebind.LastRequest) > int64(tm)) {
			rr1 := new(dns.A)
			rr1.Hdr = dns.RR_Header{
				Name:   domain + ".",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(tm),
			}
			rebind.LastRequest = time.Now().Unix()
			rr1.A = net.ParseIP(rebind.FromIP)
			_, err := models.Database.RebindUpdate(rebind)
			if err != nil {
				log.Error("DNSServer(prepA_Rebind1)", err.Error())
			}
			answer = append(answer, rr1)
		} else {
			rr1 := new(dns.A)
			rr1.Hdr = dns.RR_Header{
				Name:   domain + ".",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(config.Conf.DNS.TTL),
			}
			rr1.A = net.ParseIP(rebind.ToIP)
			rebind.LastRequest = 0
			rr1.Hdr.Ttl = uint32(config.Conf.DNS.TTL)
			_, err := models.Database.RebindUpdate(rebind)
			if err != nil {
				log.Error("DNSServer(prepA_Rebind2)", err.Error())
			}
			answer = append(answer, rr1)
		}
		//Regular part
	} else {
		records, err := models.Database.RecordByTypeAndName(domain, "A")
		if err != nil {
			log.Error("DNSServer(prepA)", err.Error())
			rr1 := new(dns.A)
			rr1.Hdr = dns.RR_Header{
				Name:   domain + ".",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(config.Conf.DNS.TTL),
			}
			rr1.A = net.ParseIP(config.Conf.DNS.AnswerIP)
			answer = append(answer, rr1)
			return answer
		}
		if len(*records) == 0 {
			rr1 := new(dns.A)
			rr1.Hdr = dns.RR_Header{
				Name:   domain + ".",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(config.Conf.DNS.TTL),
			}
			rr1.A = net.ParseIP(config.Conf.DNS.AnswerIP)
			answer = append(answer, rr1)
		}
		for _, record := range *records {
			rr1 := new(dns.A)
			rr1.Hdr = dns.RR_Header{
				Name:   domain + ".",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(config.Conf.DNS.TTL),
			}
			rr1.A = net.ParseIP(record.Value)
			answer = append(answer, rr1)

		}
	}
	return answer
}

func prepAAAA(domain string) []dns.RR {
	var answer = []dns.RR{}
	records, err := models.Database.RecordByTypeAndName(domain, "AAAA")
	if err != nil {
		log.Error("DNSServer(prepAAAA)", err.Error())
		rr1 := new(dns.AAAA)
		rr1.Hdr = dns.RR_Header{
			Name:   domain + ".",
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    uint32(config.Conf.DNS.TTL),
		}
		rr1.AAAA = net.ParseIP(config.Conf.DNS.AnswerIP)
		answer = append(answer, rr1)
		return answer
	}
	if len(*records) == 0 {
		rr1 := new(dns.AAAA)
		rr1.Hdr = dns.RR_Header{
			Name:   domain + ".",
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    uint32(config.Conf.DNS.TTL),
		}
		rr1.AAAA = net.ParseIP(config.Conf.DNS.AnswerIP)
		answer = append(answer, rr1)
	}
	for _, record := range *records {
		rr1 := new(dns.AAAA)
		rr1.Hdr = dns.RR_Header{
			Name:   domain + ".",
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    uint32(config.Conf.DNS.TTL),
		}
		rr1.AAAA = net.ParseIP(record.Value)
		answer = append(answer, rr1)
	}
	return answer
}

func prepMX(domain string) []dns.RR {
	var answer = []dns.RR{}
	records, err := models.Database.RecordByTypeAndName(domain, "MX")
	if err != nil {
		log.Error("DNSServer(prepMX)", err.Error())
		return answer
	}
	for _, record := range *records {
		rr1 := new(dns.MX)
		rr1.Hdr = dns.RR_Header{
			Name:   domain + ".",
			Rrtype: dns.TypeMX,
			Class:  dns.ClassINET,
			Ttl:    uint32(config.Conf.DNS.TTL),
		}
		rr1.Mx = record.Value
		answer = append(answer, rr1)
	}
	return answer
}

func prepNS(domain string) []dns.RR {
	var answer = []dns.RR{}
	records, err := models.Database.RecordByTypeAndName(domain, "NS")
	if err != nil {
		log.Error("DNSServer(prepNS)", err.Error())
		return answer
	}
	for _, record := range *records {
		rr1 := new(dns.NS)
		rr1.Hdr = dns.RR_Header{
			Name:   domain + ".",
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    uint32(config.Conf.DNS.TTL),
		}
		rr1.Ns = record.Value
		answer = append(answer, rr1)
	}
	return answer
}

func prepSOA(domain string) []dns.RR {
	var answer = []dns.RR{}
	records, err := models.Database.RecordByTypeAndName(domain, "SOA")
	if err != nil {
		log.Error("DNSServer(prepSOA)", err.Error())
		return answer
	}
	if len(*records) == 0 {
		rr1 := new(dns.SOA)
		rr1.Hdr = dns.RR_Header{
			Name:   domain + ".",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    uint32(config.Conf.DNS.TTL),
		}
		rr1.Mbox = domain + "."
		time_uint, _ := strconv.ParseUint(time.Now().Format("2006020123"), 10, 32)
		rr1.Serial = uint32(time_uint)
		rr1.Refresh = uint32(config.Conf.DNS.TTL)
		rr1.Retry = uint32(config.Conf.DNS.TTL - 1)
		rr1.Expire = 120
		rr1.Minttl = uint32(config.Conf.DNS.TTL)
		rr1.Ns = domain + "."
		answer = append(answer, rr1)
	}
	for _, record := range *records {
		rr1 := new(dns.SOA)
		rr1.Hdr = dns.RR_Header{
			Name:   domain + ".",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    uint32(config.Conf.DNS.TTL),
		}
		rr1.Mbox = domain + "."
		time_uint, _ := strconv.ParseUint(time.Now().Format("2006020123"), 10, 32)
		rr1.Serial = uint32(time_uint)
		rr1.Refresh = uint32(config.Conf.DNS.TTL)
		rr1.Retry = uint32(config.Conf.DNS.TTL - 1)
		rr1.Expire = 120
		rr1.Minttl = uint32(config.Conf.DNS.TTL)
		rr1.Ns = record.Value
		answer = append(answer, rr1)
	}
	return answer
}

func prepAll(domain string) []dns.RR {
	var answer = []dns.RR{}
	txt := prepTXT(domain)
	a := prepA(domain)
	aaaa := prepAAAA(domain)
	mx := prepMX(domain)
	ns := prepNS(domain)
	soa := prepSOA(domain)
	ptr := prepPTR(domain)
	cname := prepCNAME(domain)

	answer = append(answer, soa...)
	answer = append(answer, a...)
	answer = append(answer, aaaa...)
	answer = append(answer, txt...)
	answer = append(answer, mx...)
	answer = append(answer, ns...)
	answer = append(answer, ptr...)
	answer = append(answer, cname...)
	return answer
}
