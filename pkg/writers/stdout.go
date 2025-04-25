package writers

import (
	//"fmt"
	//"os"
    "strings"

	"github.com/helviojunior/certcrawler/pkg/models"
	logger "github.com/helviojunior/certcrawler/pkg/log"
)

// StdoutWriter is a Stdout writer
type StdoutWriter struct {
	WriteAll  bool
}

// NewStdoutWriter initialises a stdout writer
func NewStdoutWriter() (*StdoutWriter, error) {
	return &StdoutWriter{
		WriteAll: false,
	}, nil
}

// Write results to stdout
func (s *StdoutWriter) Write(host *models.Host) error {

	/*
	r := fmt.Sprintf("%s %d:\n", host.Ip, host.Port)
    for i, cert := range host.Certificates {
        r += fmt.Sprintf("  |--> Certificate %d:\n", i)
        r += fmt.Sprintf("  |     |--> Subject:    %s\n", cert.Subject)
        r += fmt.Sprintf("  |     |--> Issuer:     %s\n", cert.Issuer)
        r += fmt.Sprintf("  |     |--> NotBefore:  %s\n", cert.NotBefore)
        r += fmt.Sprintf("  |     |--> NotAfter:   %s\n", cert.NotAfter)
        if len(cert.Names) > 2 {
            r += "  |     |--> Alternate Names:\n"
            for _, altName := range cert.Names {
            	r += fmt.Sprintf("  |     |     |--> %s\n", altName.Name)
            }
        }
        r += "  |\n"
    }
    r += "  +-- END \n\n"
    logger.Infof("%s", r)
    */

    for _, cert := range host.Certificates {
        if !cert.IsCA {
            subject := s.FormatCN(cert.Subject)
        	logger.Info("Certificate found", "ip", host.Ip, "port", host.Port, "name", s.FormatCN(cert.Subject))
        	if len(cert.Names) > 2 {
                for _, altName := range cert.Names {
                    n := s.FormatCN(altName.Name)
                    if altName.Type != "subject" && subject != n {
                    	logger.Info("Certificate found", "ip", host.Ip, "port", host.Port, "name", n)
                    }
                }
            }
        }
    }

	return nil
}

func (s *StdoutWriter) FormatCN(cn string) string {
    txt := cn
    if strings.ToLower(txt[0:3]) == "cn=" {
        p := strings.Split(txt, ",")
        if len(p) >= 1 {
            txt = strings.Replace(strings.Replace(p[0], "CN=", "", -1), "cn=", "", -1)
        }
    }
    if txt == "" {
        txt = cn
    }
    txt = strings.Replace(txt, "\"", "", -1)
    txt = strings.Replace(txt, "'", "", -1)
    return txt
} 

func (s *StdoutWriter) Finish() error {
    return nil
}


func (s *StdoutWriter) AddCtrl(*models.TestCtrl) error {
	return nil
}
