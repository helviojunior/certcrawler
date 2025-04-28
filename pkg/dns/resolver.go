package dns

import (
    "net/url"
    "errors"
    "strings"
    "fmt"

    "github.com/helviojunior/certcrawler/pkg/log"
    "github.com/miekg/dns"
)

type DNSResolver struct {
    DnsServer string
    DnsPort int
    DnsProtocol string

    Proxy *url.URL
}

var resolver = &DNSResolver{
    DnsServer    : "8.8.8.8",
    DnsPort      : 53,
    DnsProtocol  : "UDP",
}

func InitResolver(dnsServer string, proxy string) error {
    if dnsServer == "" {
        resolver.DnsServer = GetDefaultDnsServer("")
    }

    if proxy != "" {
        u, err := url.Parse(proxy)
        if err != nil {
            return errors.New("Error parsing URL: " + err.Error())
        }

        _, err = FromURL(u, nil)
        if err != nil {
            return errors.New("Error parsing URL: " + err.Error())
        }
        resolver.Proxy = u

        port := u.Port()
        if port == "" {
            port = "1080"
        }
        log.Warn("Setting proxy to " + u.Scheme + "://" + u.Hostname() + ":" + port)
    }else{
        resolver.Proxy = nil
    }
    
    resolver.DnsServer = fmt.Sprintf("%s:%d", resolver.DnsServer, resolver.DnsPort)
    _, err := GetValidDnsSuffix(resolver.DnsServer, "google.com.", resolver.Proxy)
    if err != nil {
        log.Error("Error checking DNS connectivity", "err", err)
        return err
    }

    return nil
}

func GetCloudProduct(ip string) (string, string, error) {
    if arpa, err := dns.ReverseAddr(ip); err == nil {

        m := new(dns.Msg)
        m.Id = dns.Id()
        m.RecursionDesired = true

        m.SetQuestion(arpa, dns.TypePTR)

        //r, err := dns.Exchange(m, run.dnsServer); 
        c := new(SocksClient)
        if r, err := c.Exchange(m, resolver.Proxy, resolver.DnsServer); err == nil {
            for _, ans := range r.Answer {
                ptr, ok := ans.(*dns.PTR)
                if ok {
                    log.Debug("DNS", "IP", ip, "PTR", ptr.Ptr)
                    cc, prodName, _ := _containsCloudProduct(ptr.Ptr)
                    if cc {
                        log.Debug("DNS", "IP", ip, "PTR", ptr.Ptr, "product", prodName)
                        return strings.Trim(strings.ToLower(ptr.Ptr), ". "), prodName, nil
                    }

                    log.Debug("DNS", "IP", ip, "PTR", ptr.Ptr)
                    return strings.Trim(strings.ToLower(ptr.Ptr), ". "), "", nil
                }
            }
        }else{
            return "", "", err
        }
    }else{
        return "", "", err
    }

    return "", "", nil
}

func _containsCloudProduct(s string) (bool, string, string) {
    s = strings.Trim(strings.ToLower(s), ". ")
    for prodName, identifiers := range products {
        for _, id := range identifiers {
            if strings.Contains(s, strings.ToLower(id)) {
                return true, prodName, id
            }
        }
    }
    return false, "", ""
}

func GetDefaultDnsServer(fallback string) string {
    if fallback == "" {
        fallback = "8.8.8.8"
    }

    srv := GetDNSServers()
    if len(srv) == 0 {
        return fallback
    }

    return srv[0].Addr().String()
}

func GetValidDnsSuffix(dnsServer string, suffix string, proxyUri *url.URL) (string, error) {
    suffix = strings.Trim(suffix, ". ")
    if suffix == "" {
        return "", errors.New("empty suffix string")
    }

    suffix = strings.ToLower(suffix) + "."
    i := false

    m := new(dns.Msg)
    m.Id = dns.Id()
    m.RecursionDesired = true

    m.Question = make([]dns.Question, 1)
    m.Question[0] = dns.Question{suffix, dns.TypeSOA, dns.ClassINET}

    c := new(SocksClient)
    in, err := c.Exchange(m, proxyUri, dnsServer); 
    if err != nil {
        return "", err
    }else{
        
        for _, ans1 := range in.Answer {
            if _, ok := ans1.(*dns.SOA); ok {
                i = true
            }
        }
        
    }

    if i == false {
        return "", errors.New("SOA not found for domain '"+ suffix + "'")
    }

    return suffix, nil

}