package writers

import (
	//"fmt"
	//"os"

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
    	logger.Infof("%s %d:\n       %s", host.Ip, host.Port, cert.Subject)
    	if len(cert.Names) > 2 {
            for _, altName := range cert.Names {
            	logger.Infof("%s %d:\n       %s", host.Ip, host.Port, altName.Name)
            }
        }
    }

	return nil
}

func (s *StdoutWriter) Finish() error {
    return nil
}