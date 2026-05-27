package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/helviojunior/certcrawler/internal/ascii"
	"github.com/helviojunior/certcrawler/internal/tools"
	"github.com/helviojunior/certcrawler/pkg/log"
	"github.com/helviojunior/certcrawler/pkg/models"
	"github.com/helviojunior/certcrawler/pkg/writers"
	resolver "github.com/helviojunior/gopathresolver"
	"github.com/spf13/cobra"
)

var dnsCmdFlags = struct {
	fromFile string
	toFile   string

	fromExt string
}{}

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Export every valid FQDN found inside the certificates (excluding SNIs)",
	Long: ascii.LogoHelp(ascii.Markdown(`
# report dns

Export every DNS name found inside the collected certificates that is **not**
already known as an SNI (server name) used during the scan.

Names are harvested from the certificate Subject (CN), Subject Alternative
Names (SAN), Issuer (CN) and the CRL/OCSP/issuer distribution URLs. Only
entries that are a valid FQDN are kept. Wildcard prefixes (` + "`*.`" + `) are
stripped and the resulting list is unique and sorted.

A --from-file (SQLite or JSON Lines) must be specified. When --to-file is set
the list is written there (one FQDN per line), otherwise it is printed to the
standard output.`)),
	Example: `
   - certcrawler report dns --from-file ~/.certcrawler.sqlite3
   - certcrawler report dns --from-file ~/.certcrawler.sqlite3 --to-file dns.txt
   - certcrawler report dns --from-file certcrawler.jsonl --to-file dns.txt`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		var err error

		if dnsCmdFlags.fromFile == "" {
			return errors.New("from file not set")
		}

		dnsCmdFlags.fromFile, err = resolver.ResolveFullPath(dnsCmdFlags.fromFile)
		if err != nil {
			return err
		}

		if dnsCmdFlags.toFile != "" {
			dnsCmdFlags.toFile, err = resolver.ResolveFullPath(dnsCmdFlags.toFile)
			if err != nil {
				return err
			}
		}

		dnsCmdFlags.fromExt = strings.ToLower(filepath.Ext(dnsCmdFlags.fromFile))
		if !tools.SliceHasStr(conversionCmdExtensions, dnsCmdFlags.fromExt) {
			return errors.New("unsupported from file type")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		collector := newFqdnCollector()

		switch dnsCmdFlags.fromExt {
		case ".sqlite3", ".db":
			if err := convertFromDbTo(dnsCmdFlags.fromFile, []writers.Writer{collector}); err != nil {
				log.Error("failed to read from SQLite", "err", err)
				return
			}
		case ".jsonl":
			if err := convertFromJsonlTo(dnsCmdFlags.fromFile, []writers.Writer{collector}); err != nil {
				log.Error("failed to read from JSON Lines", "err", err)
				return
			}
		}

		names := collector.results()
		log.Info("collected DNS names", "count", len(names))

		if dnsCmdFlags.toFile != "" {
			if err := writeLines(dnsCmdFlags.toFile, names); err != nil {
				log.Error("could not write target file", "err", err)
				return
			}
			log.Info("wrote DNS names to file", "file", dnsCmdFlags.toFile)
			return
		}

		for _, n := range names {
			fmt.Println(n)
		}
	},
}

func init() {
	reportCmd.AddCommand(dnsCmd)

	dnsCmd.Flags().StringVar(&dnsCmdFlags.fromFile, "from-file", "~/.certcrawler.db", "The file to read the results from")
	dnsCmd.Flags().StringVar(&dnsCmdFlags.toFile, "to-file", "", "The file to write the FQDN list to (one per line). When empty, prints to stdout")
}

// fqdnRegex validates a (non-wildcard) FQDN: one or more dot-separated labels
// followed by an alphabetic TLD of at least two characters.
var fqdnRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

// cnRegex extracts the CN value from an RFC2253/RFC4514 distinguished name
// string such as "CN=example.com,O=Foo,C=US".
var cnRegex = regexp.MustCompile(`(?i)CN=([^,/+]+)`)

// fqdnCollector implements the writers.Writer interface so it can be fed by the
// existing convertFrom* loaders. It gathers candidate DNS names from each
// certificate and the SNIs used while scanning, so SNIs can be excluded later.
type fqdnCollector struct {
	candidates map[string]struct{}
	snis       map[string]struct{}
}

func newFqdnCollector() *fqdnCollector {
	return &fqdnCollector{
		candidates: map[string]struct{}{},
		snis:       map[string]struct{}{},
	}
}

func (c *fqdnCollector) Write(host *models.Host) error {
	if n := normalizeFQDN(host.SNI); n != "" {
		c.snis[n] = struct{}{}
	}

	for _, cert := range host.Certificates {
		// CN from Subject and Issuer distinguished names.
		c.addRaw(extractCN(cert.Subject))
		c.addRaw(extractCN(cert.Issuer))

		// SAN entries and other stored names.
		for _, name := range cert.Names {
			switch name.Type {
			case "DNS":
				c.addRaw(name.Name)
			case "URI":
				c.addRaw(hostFromURL(name.Name))
			case "subject":
				c.addRaw(extractCN(name.Name))
			}
		}

		// CRL / OCSP / issuer distribution points from the raw certificate.
		for _, u := range certDistributionHosts(cert.RawData) {
			c.addRaw(u)
		}
	}

	return nil
}

func (c *fqdnCollector) AddCtrl(*models.TestCtrl) error { return nil }

func (c *fqdnCollector) Finish() error { return nil }

// addRaw normalizes and validates a candidate name before storing it.
func (c *fqdnCollector) addRaw(raw string) {
	n := normalizeFQDN(raw)
	if n != "" && isValidFQDN(n) {
		c.candidates[n] = struct{}{}
	}
}

// results returns the unique, sorted FQDNs that are not also SNIs.
func (c *fqdnCollector) results() []string {
	out := make([]string, 0, len(c.candidates))
	for name := range c.candidates {
		if _, isSNI := c.snis[name]; isSNI {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// normalizeFQDN lowercases, trims spaces/dots and strips a leading wildcard
// label ("*.").
func normalizeFQDN(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.Trim(s, ". ")
	return s
}

// isValidFQDN reports whether s is a syntactically valid FQDN (and not an IP
// address).
func isValidFQDN(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if net.ParseIP(s) != nil {
		return false
	}
	return fqdnRegex.MatchString(s)
}

// extractCN pulls the CN value out of a distinguished name string.
func extractCN(dn string) string {
	m := cnRegex.FindStringSubmatch(dn)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// hostFromURL returns the host part of a URL, without the port.
func hostFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// certDistributionHosts parses the base64 (DER) raw certificate and returns the
// host names found in its CRL distribution points, OCSP servers and issuing
// certificate URLs.
func certDistributionHosts(rawData string) []string {
	if rawData == "" {
		return nil
	}

	der, err := base64.StdEncoding.DecodeString(rawData)
	if err != nil {
		return nil
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}

	var hosts []string
	for _, u := range cert.CRLDistributionPoints {
		hosts = append(hosts, hostFromURL(u))
	}
	for _, u := range cert.OCSPServer {
		hosts = append(hosts, hostFromURL(u))
	}
	for _, u := range cert.IssuingCertificateURL {
		hosts = append(hosts, hostFromURL(u))
	}
	return hosts
}

// writeLines writes one entry per line to the destination file.
func writeLines(destination string, lines []string) error {
	path, err := tools.CreateFileWithDir(destination)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return nil
}
