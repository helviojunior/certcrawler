package readers

import (
	//"fmt"
	"os"

	"net/netip"
	"strings"

	"github.com/helviojunior/certcrawler/internal/tools"
	"github.com/lair-framework/go-nmap"

	"github.com/helviojunior/certcrawler/pkg/log"
)

// NmapReader is an Nmap results reader
type NmapReader struct {
	Options *NmapReaderOptions
}

// NmapReaderOptions are options for the nmap reader
type NmapReaderOptions struct {
	// Path to an Nmap XML file
	Source string

	// Ports to limit scans to
	Ports []int

	// Protocols maps "ip:port" to the detected application protocol
	// ("http" or "https") based on the Nmap service information. Only
	// HTTP/HTTPS services are recorded here.
	Protocols map[string]string
}

// NewNmapReader prepares a new Nmap reader
func NewNmapReader(opts *NmapReaderOptions) *NmapReader {
	return &NmapReader{
		Options: opts,
	}
}

// Read an nmap file
func (nr *NmapReader) Read(outList *[]netip.AddrPort) error {
	xml, err := os.ReadFile(nr.Options.Source)
	if err != nil {
		return err
	}

	nmapXML, err := nmap.Parse(xml)
	if err != nil {
		if len(xml) < 1024 {
			return err
		}

		log.Warn("XML data is broken, trying to solve that...", "err", err)

		// Check if we can solve the most common issue
		var err2 error
		newText := string(xml[len(xml)-1024:])
		if strings.Contains(newText, "<runstats") && !strings.Contains(newText, "</runstats>") {
			xml = append(xml, []byte("</runstats>")...)
		}
		if !strings.Contains(newText, "</nmaprun>") {
			xml = append(xml, []byte("</nmaprun>")...)
		}
		nmapXML, err2 = nmap.Parse(xml)
		if err2 != nil {
			return err //Return original error
		}
		log.Warn("Issue resolved: XML data has been successfully repaired and loaded.")
	}

	for _, host := range nmapXML.Hosts {
		for _, address := range host.Addresses {
			if !tools.SliceHasStr([]string{"ipv4", "ipv6"}, address.AddrType) {
				continue
			}

			for _, port := range host.Ports {
				// filter only open ports
				if port.State.State != "open" {
					continue
				}

				// apply the port filter if it exists
				if len(nr.Options.Ports) > 0 && !tools.SliceHasInt(nr.Options.Ports, port.PortId) {
					continue
				}

				ip, err := netip.ParseAddr(address.Addr)
				if err != nil {
					log.Debugf("Invalid IP (%s): %s", address.Addr, err.Error())
					continue
				}

				// ip:port candidates
				endpoint := netip.AddrPortFrom(ip, uint16(port.PortId))
				*outList = append(*outList, endpoint)

				// Record the HTTP/HTTPS application protocol (if any) so the
				// runner can grab the HTTP banner and page title.
				if proto := httpProtocol(&port); proto != "" {
					if nr.Options.Protocols == nil {
						nr.Options.Protocols = map[string]string{}
					}
					nr.Options.Protocols[endpoint.String()] = proto
				}
			}
		}
	}

	return nil
}

// httpProtocol inspects an Nmap port's service information and returns "https"
// for TLS-wrapped HTTP services, "http" for plain HTTP services, or an empty
// string when the service is not HTTP-based.
func httpProtocol(port *nmap.Port) string {
	name := strings.ToLower(port.Service.Name)
	tunnel := strings.ToLower(port.Service.Tunnel)

	if !strings.Contains(name, "http") {
		return ""
	}

	if tunnel == "ssl" || tunnel == "tls" || strings.Contains(name, "https") || strings.HasPrefix(name, "ssl/") {
		return "https"
	}

	return "http"
}
