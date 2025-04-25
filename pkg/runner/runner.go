package runner

import (
	"context"
	//"errors"
	"log/slog"
	//"net/url"
	//"net/mail"
	"crypto/tls"
    "net"
	"os"
	"fmt"
	"sync"
	"time"
	"strings"
	//"math/rand/v2"
	"os/signal"
    "syscall"
    "net/netip"
    //"encoding/hex"
    "encoding/base64"
    //"strconv"

	//"github.com/helviojunior/certcrawler/internal"
	"github.com/helviojunior/certcrawler/internal/ascii"
	"github.com/helviojunior/certcrawler/internal/tools"
	"github.com/helviojunior/certcrawler/pkg/models"
	"github.com/helviojunior/certcrawler/pkg/writers"
	"github.com/helviojunior/certcrawler/pkg/database"
	"gorm.io/gorm"
)

// Runner is a runner that probes web targets using a driver
type Runner struct {
	
	//Test id
	uid string

	// DNS FQDN to scan.
	Targets chan netip.AddrPort

	//Status
	status *Status

	conn          *gorm.DB
	mutex         sync.Mutex

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
	Total int
	Complete int
	Skiped int
	ConnectionError int
	TLSError int
	Spin string
	Running bool
}

func (st *Status) Print() { 

	st.Spin = ascii.GetNextSpinner(st.Spin)

	fmt.Fprintf(os.Stderr, "%s\n %s (%s/%s) conn error: %s, tls error: %s               \r\033[A", 
    	"                                                                        ",
    	ascii.ColoredSpin(st.Spin), 
    	tools.FormatInt(st.Complete), 
    	tools.FormatInt(st.Total), 
    	tools.FormatInt(st.ConnectionError), 
    	tools.FormatInt(st.TLSError))
	
} 

func (run *Runner) GetLog() *slog.Logger{ 
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
		Targets:      make(chan netip.AddrPort),
		uid: fmt.Sprintf("%d", time.Now().UnixMilli()),
		ctx:        ctx,
		conn:       c,
		mutex:      sync.Mutex{},
		cancel:     cancel,
		log:        logger,
		writers:    writers,
		options:    opts,
		Timeout:    2 * time.Second,
		status:     &Status{
			Total: 0,
			Complete: 0,
			ConnectionError: 0,
			TLSError: 0,
			Skiped: 0,
			Spin: "",
			Running: true,
		},
	}, nil
}

func ContainsCloudProduct(s string) (bool, string, string) {
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
			Ip       :endpoint.Addr().String(),
			Port     :uint(endpoint.Port()),
			FQDN     :serverName,
		}); err != nil {
			return err
		}
	}

	return nil
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
			        	time.Sleep(time.Duration(time.Second/4))
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

					var host *models.Host
					for _, h := range run.options.HostnameList {
						l2 := run.log.With("Host", endpoint.String(), "host", h)

						if run.mustCheck(h, endpoint) {

							run.runCtrlWriters(h, endpoint)
	
						    h1, err := run.getCert(h, endpoint)
						    
						    if err != nil {
						    	l2.Debug("error getting cert", "err", err)
						    	run.status.TLSError += 1
						    }else{
							    if h1 != nil {
							    	if host == nil {
							    		host = h1
							    	}else{
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

					if host != nil {
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
		Ip       :endpoint.Addr().String(),
		Port     :uint(endpoint.Port()),
		Host     :endpoint.String(),
		//FQDN     :serverName,
		Certificates : []*models.Certificate{},
	}

	cfg := &tls.Config{
        ServerName:         serverName,
        InsecureSkipVerify: true,

        // Allow SSLv3 (0x0300) up through TLS1.3
        MinVersion:         tls.VersionSSL30, 
        MaxVersion:         tls.VersionTLS13,
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
    		ProbedAt 			 : time.Now(),
    		Fingerprint          : tools.GetHash(cert.Signature),
    		Subject              : cert.Subject.String(),
    		Issuer               : cert.Issuer.String(),
    		NotBefore            : cert.NotBefore,
    		NotAfter             : cert.NotAfter,
    		IsCA                 : cert.IsCA,
    		IsRootCA             : cert.IsCA && (cert.Subject.String() == cert.Issuer.String()),
    		SelfSigned           : (cert.Subject.String() == cert.Issuer.String()),
    		RawData              : base64.StdEncoding.EncodeToString([]byte(cert.Raw)),
    		Names                : []*models.CertNames{},
    	}
    	nc.Names = append(nc.Names, &models.CertNames{
    		Type 	: "subject",
    		Name    : cert.Subject.String(),
    	})
    	nc.Names = append(nc.Names, &models.CertNames{
    		Type 	: "subject",
    		Name    : cert.Issuer.String(),
    	})

        if len(cert.DNSNames) > 0 {
        	for _, n := range cert.DNSNames {
	        	nc.Names = append(nc.Names, &models.CertNames{
		    		Type 	: "DNS",
		    		Name    : n,
		    	})
		    }
        }
        if len(cert.IPAddresses) > 0 {
        	for _, n := range cert.IPAddresses {
	        	nc.Names = append(nc.Names, &models.CertNames{
		    		Type 	: "IPAddress",
		    		Name    : n.String(),
		    	})
		    }

        }
        if len(cert.EmailAddresses) > 0 {
            for _, n := range cert.EmailAddresses {
	        	nc.Names = append(nc.Names, &models.CertNames{
		    		Type 	: "EmailAddress",
		    		Name    : n,
		    	})
		    }
        }
        if len(cert.URIs) > 0 {
            for _, n := range cert.URIs {
	        	nc.Names = append(nc.Names, &models.CertNames{
		    		Type 	: "URI",
		    		Name    : n.String(),
		    	})
		    }
        }

    	result.Certificates = append(result.Certificates, nc)

    }
    
    return result, nil
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

