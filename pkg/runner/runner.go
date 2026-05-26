package runner

import (
	"context"
	//"errors"
	"log/slog"
	//"net/url"
	//"net/mail"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	//"math/rand/v2"
	"net/netip"
	"os/signal"
	"syscall"
	//"encoding/hex"
	"encoding/base64"
	//"strconv"

	"bytes"
	"crypto/x509"

	"golang.org/x/term"

	//"github.com/helviojunior/certcrawler/internal"
	"github.com/helviojunior/certcrawler/internal/ascii"
	"github.com/helviojunior/certcrawler/internal/tools"
	"github.com/helviojunior/certcrawler/pkg/database"
	"github.com/helviojunior/certcrawler/pkg/dns"
	"github.com/helviojunior/certcrawler/pkg/models"
	"github.com/helviojunior/certcrawler/pkg/writers"
	"gorm.io/gorm"
)

// titleRegex extracts the content of the first <title> tag in an HTML page.
var titleRegex = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Runner is a runner that probes web targets using a driver
type Runner struct {

	//Test id
	uid string

	// DNS FQDN to scan.
	Targets chan netip.AddrPort

	//Status
	status *Status

	conn  *gorm.DB
	mutex sync.Mutex

	//Context
	ctx    context.Context
	cancel context.CancelFunc

	// writers are the result writers to use
	writers []writers.Writer

	// log handler
	log *slog.Logger

	// options for the Runner to consider
	options Options

	Timeout time.Duration
}

type Status struct {
	Total           int
	Complete        int
	Skiped          int
	ConnectionError int
	TLSError        int
	Spin            string
	Running         bool
	IsTerminal      bool
	log             *slog.Logger
}

func (st *Status) Print() {

	if st.IsTerminal {
		st.Spin = ascii.GetNextSpinner(st.Spin)

		fmt.Fprintf(os.Stderr, "%s\n %s (%s/%s) conn error: %s, tls error: %s               \r\033[A",
			"                                                                        ",
			ascii.ColoredSpin(st.Spin),
			tools.FormatInt(st.Complete),
			tools.FormatInt(st.Total),
			tools.FormatInt(st.ConnectionError),
			tools.FormatInt(st.TLSError))
	} else {
		st.log.Info("STATUS",
			"complete", st.Complete, "total", st.Total, "conn error", st.ConnectionError,
			"tls error", st.TLSError)
	}
}

func (run *Runner) GetLog() *slog.Logger {
	return run.log
}

func (run *Runner) AddSkiped() {
	run.status.Complete += 1
	run.status.Skiped += 1
}

func (st *Status) AddResult(result *models.Host) {
	st.Complete += 1
}

// New gets a new Runner ready for probing.
// It's up to the caller to call Close() on the runner
func NewRunner(logger *slog.Logger, opts Options, writers []writers.Writer, dbUri string) (*Runner, error) {
	ctx, cancel := context.WithCancel(context.Background())

	c, err := database.Connection(dbUri, false, false)
	if err != nil {
		return nil, err
	}

	return &Runner{
		Targets: make(chan netip.AddrPort),
		uid:     fmt.Sprintf("%d", time.Now().UnixMilli()),
		ctx:     ctx,
		conn:    c,
		mutex:   sync.Mutex{},
		cancel:  cancel,
		log:     logger,
		writers: writers,
		options: opts,
		Timeout: 2 * time.Second,
		status: &Status{
			Total:           0,
			Complete:        0,
			ConnectionError: 0,
			TLSError:        0,
			Skiped:          0,
			Spin:            "",
			Running:         true,
			IsTerminal:      term.IsTerminal(int(os.Stdin.Fd())),
			log:             logger,
		},
	}, nil
}

// runWriters takes a result and passes it to writers
func (run *Runner) runWriters(host *models.Host) error {
	for _, writer := range run.writers {
		if err := writer.Write(host); err != nil {
			return err
		}
	}

	return nil
}

func (run *Runner) mustCheck(serverName string, endpoint netip.AddrPort) bool {
	if run.options.ForceCheck || run.conn == nil {
		return true
	}

	run.mutex.Lock()
	defer run.mutex.Unlock()

	response := run.conn.Raw("SELECT count(id) as count from test_control WHERE ip = ? AND port = ? AND fqdn = ?", endpoint.Addr().String(), fmt.Sprintf("%d", endpoint.Port()), serverName)
	if response != nil {
		var cnt int
		_ = response.Row().Scan(&cnt)
		if cnt > 0 {
			run.log.Debug("[Host already checked]", "ip", endpoint.Addr().String(), "port", endpoint.Port(), "name", serverName)
			return false
		}
	}

	return true
}

func (run *Runner) runCtrlWriters(serverName string, endpoint netip.AddrPort) error {
	for _, writer := range run.writers {
		if err := writer.AddCtrl(&models.TestCtrl{
			Ip:   endpoint.Addr().String(),
			Port: uint(endpoint.Port()),
			FQDN: serverName,
		}); err != nil {
			return err
		}
	}

	return nil
}

// IsSelfSigned checks if a certificate is self-signed
func IsSelfSigned(cert *x509.Certificate) bool {
	// Check if subject and issuer are equal
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}

	// Try to verify the certificate with its own public key
	err := cert.CheckSignatureFrom(cert)
	return err == nil
}

func (run *Runner) Run(total int) Status {
	wg := sync.WaitGroup{}
	swg := sync.WaitGroup{}

	run.status.Total = total

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		run.status.Running = false
	}()

	if !run.options.Logging.Silence {
		swg.Add(1)
		go func() {
			defer swg.Done()
			for run.status.Running {
				select {
				case <-run.ctx.Done():
					return
				default:
					run.status.Print()
					if run.status.IsTerminal {
						time.Sleep(time.Duration(time.Second / 4))
					} else {
						time.Sleep(time.Duration(time.Second * 30))
					}
				}
			}
		}()
	}

	// will spawn Scan.Theads number of "workers" as goroutines
	for w := 0; w < run.options.Scan.Threads; w++ {
		wg.Add(1)

		// start a worker
		go func() {
			defer wg.Done()
			tools.RandSleep()
			hnCount := len(run.options.HostnameList)
			for run.status.Running {
				select {
				case <-run.ctx.Done():
					return
				case endpoint, ok := <-run.Targets:
					if !ok || !run.status.Running {
						return
					}
					logger := run.log.With("Host", endpoint.String())

					if !run.mustCheck("", endpoint) {
						run.status.Complete += hnCount
						continue
					}

					if !run.isPortOpen(endpoint) {
						logger.Debug("tcp port closed")
						run.status.Complete += hnCount
						run.status.ConnectionError += hnCount
						run.runCtrlWriters("", endpoint)
						continue
					}

					var err error
					var host *models.Host
					for _, h := range run.options.HostnameList {
						l2 := run.log.With("Host", endpoint.String(), "host", h)

						if run.mustCheck(h, endpoint) {

							run.runCtrlWriters(h, endpoint)

							h1, err := run.getCert(h, endpoint)

							if err != nil {
								l2.Debug("error getting cert", "err", err)
								run.status.TLSError += 1
							} else {
								if h1 != nil {
									if host == nil {
										host = h1
									} else {
										for _, h2 := range h1.Certificates {
											host.AddCertificate(h2)
										}
									}
								}
							}
							if host != nil {
								host.AddFQDN(h)
							}
						}

						run.status.Complete += 1
					}

					// Detect the HTTP/HTTPS application protocol for this
					// endpoint (populated by the nmap reader).
					proto := ""
					if run.options.ServiceMap != nil {
						proto = run.options.ServiceMap[endpoint.String()]
					}

					// For plain HTTP/HTTPS endpoints without a certificate we
					// still want to store the banner and title, so create a
					// minimal host record.
					if host == nil && (proto == "http" || proto == "https") {
						host = &models.Host{
							Ip:           endpoint.Addr().String(),
							Port:         uint(endpoint.Port()),
							Certificates: []*models.Certificate{},
						}
					}

					if host != nil {
						// Best-effort HTTP banner + title collection. Any
						// failure here must not prevent the remaining
						// information from being stored.
						if proto == "http" || proto == "https" {
							serverName := ""
							if len(run.options.HostnameList) > 0 {
								serverName = run.options.HostnameList[0]
							}
							if banner, title, herr := run.getHTTPInfo(proto, serverName, endpoint); herr != nil {
								logger.Debug("error getting http banner/title", "err", herr)
							} else {
								host.Banner = banner
								host.Title = title
							}
						}

						if len(host.Certificates) > 0 {
							if host.Ptr, host.Cloud, err = dns.GetCloudProduct(host.Ip); err != nil {
								run.log.Debug("Error getting DNS record", "err", err)
							}
							if host.Ptr != "" {
								host.AddFQDN(host.Ptr)
							}
						}
						if err := run.runWriters(host); err != nil {
							logger.Error("failed to write result", "err", err)
						}
					}

				}
			}

		}()
	}

	wg.Wait()
	run.status.Running = false
	swg.Wait()

	return *run.status
}

func (run *Runner) getCert(serverName string, endpoint netip.AddrPort) (*models.Host, error) {
	result := &models.Host{
		Ip:   endpoint.Addr().String(),
		Port: uint(endpoint.Port()),
		//FQDN     :serverName,
		Certificates: []*models.Certificate{},
	}

	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,

		// Allow SSLv3 (0x0300) up through TLS1.3
		MinVersion: tls.VersionSSL30,
		MaxVersion: tls.VersionTLS13,
	}
	dialer := &net.Dialer{
		Timeout: run.Timeout,
	}

	// tls.Dial returns *tls.Conn
	conn, err := tls.DialWithDialer(dialer, "tcp", endpoint.String(), cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Now conn is *tls.Conn, so ConnectionState is available
	state := conn.ConnectionState()

	for _, cert := range state.PeerCertificates {
		nc := &models.Certificate{
			ProbedAt:    time.Now(),
			Fingerprint: tools.GetHash(cert.Signature),
			Subject:     cert.Subject.String(),
			Issuer:      cert.Issuer.String(),
			NotBefore:   cert.NotBefore,
			NotAfter:    cert.NotAfter,
			IsCA:        cert.IsCA,
			IsRootCA:    cert.IsCA && (cert.Subject.String() == cert.Issuer.String()),
			SelfSigned:  IsSelfSigned(cert),
			RawData:     base64.StdEncoding.EncodeToString([]byte(cert.Raw)),
			Names:       []*models.CertNames{},
		}
		nc.Names = append(nc.Names, &models.CertNames{
			Type: "subject",
			Name: cert.Subject.String(),
		})
		/*
			nc.Names = append(nc.Names, &models.CertNames{
				Type 	: "subject",
				Name    : cert.Issuer.String(),
			})*/

		if len(cert.DNSNames) > 0 {
			for _, n := range cert.DNSNames {
				nc.Names = append(nc.Names, &models.CertNames{
					Type: "DNS",
					Name: n,
				})
			}
		}
		if len(cert.IPAddresses) > 0 {
			for _, n := range cert.IPAddresses {
				nc.Names = append(nc.Names, &models.CertNames{
					Type: "IPAddress",
					Name: n.String(),
				})
			}

		}
		if len(cert.EmailAddresses) > 0 {
			for _, n := range cert.EmailAddresses {
				nc.Names = append(nc.Names, &models.CertNames{
					Type: "EmailAddress",
					Name: n,
				})
			}
		}
		if len(cert.URIs) > 0 {
			for _, n := range cert.URIs {
				nc.Names = append(nc.Names, &models.CertNames{
					Type: "URI",
					Name: n.String(),
				})
			}
		}

		result.Certificates = append(result.Certificates, nc)

	}

	return result, nil
}

// getHTTPInfo performs a single GET request against the endpoint (without
// following redirects) and returns the full HTTP response header as the banner
// and the page <title> content, when present. It is best-effort: callers
// should treat an error as "no banner/title available" and continue.
func (run *Runner) getHTTPInfo(scheme string, serverName string, endpoint netip.AddrPort) (string, string, error) {
	timeout := run.Timeout
	if run.options.Scan.Timeout > 0 {
		timeout = time.Duration(run.options.Scan.Timeout) * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
			MinVersion:         tls.VersionSSL30,
			MaxVersion:         tls.VersionTLS13,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Do not follow redirects: keep the original response headers.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf("%s://%s/", scheme, endpoint.String())
	req, err := http.NewRequestWithContext(run.ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	if serverName != "" {
		req.Host = serverName
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// Banner: full HTTP response header (status line + headers), no body.
	banner := ""
	if bannerBytes, derr := httputil.DumpResponse(resp, false); derr == nil {
		banner = string(bannerBytes)
	}

	// Title: parse the first <title> from a bounded amount of the body.
	title := ""
	if body, rerr := io.ReadAll(io.LimitReader(resp.Body, 512*1024)); rerr == nil {
		if m := titleRegex.FindSubmatch(body); len(m) > 1 {
			title = strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
		}
	}

	return banner, title, nil
}

func (run *Runner) isPortOpen(endpoint netip.AddrPort) bool {
	conn, err := net.DialTimeout("tcp", endpoint.String(), run.Timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (run *Runner) Close() {
	for _, writer := range run.writers {
		writer.Finish()
	}
}
