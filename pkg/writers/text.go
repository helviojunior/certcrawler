package writers

import (
	"time"
	"os"
	//"strings"
	"fmt"

	"github.com/helviojunior/certcrawler/pkg/models"
)

// StdoutWriter is a Stdout writer
type TextWriter struct {
	FilePath  string
	finalPath string
}

// NewStdoutWriter initialises a stdout writer
func NewTextWriter(destination string) (*TextWriter, error) {
	// open the file and write the CSV headers to it
	file, err := os.OpenFile(destination, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if _, err := file.WriteString(txtHeader()); err != nil {
		return nil, err
	}

	return &TextWriter{
		FilePath:  destination,
		finalPath: destination,
	}, nil
}

func txtHeader() string {
	txt := "######################################\r\n## Date: " + time.Now().Format(time.RFC3339) + "\r\n\r\n"

	return txt
}

func (t *TextWriter) Finish() error {
	file, err := os.OpenFile(t.finalPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString("\r\nFinished at: " + time.Now().Format(time.RFC3339) + "\r\n\r\n"); err != nil {
		return err
	}

	return nil
}

// Write results to stdout
func (t *TextWriter) Write(result *models.Host) error {

	file, err := os.OpenFile(t.finalPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(t.formatResult(result) + "\r\n"); err != nil {
		return err
	}

	return nil
}

func (t *TextWriter) formatResult(host *models.Host) string {

	r := fmt.Sprintf("%s %d:\n", host.Ip, host.Port)
	if host.Cloud != "" {
		r += fmt.Sprintf("  |--> Cloud %s:\n", host.Cloud)
	}

    for i, cert := range host.Certificates {
    	ca := ""
    	if cert.IsRootCA {
    		ca = "Root CA"
    	}else if cert.IsCA {
    		ca = "Intermediate CA"
    	}else{
    		ca = "No"
    	}
        r += fmt.Sprintf("  |--> Certificate %d:\n", i)
        r += fmt.Sprintf("  |     |--> Subject:     %s\n", cert.Subject)
        r += fmt.Sprintf("  |     |--> Issuer:      %s\n", cert.Issuer)
        r += fmt.Sprintf("  |     |--> NotBefore:   %s\n", cert.NotBefore)
        r += fmt.Sprintf("  |     |--> NotAfter:    %s\n", cert.NotAfter)
        r += fmt.Sprintf("  |     |--> CA:          %s\n", ca)
        r += fmt.Sprintf("  |     |--> Fingerprint: %s\n", cert.Fingerprint)
        if len(cert.Names) > 2 {
            r += "  |     |--> Alternate Names:\n"
            for _, altName := range cert.Names {
            	r += fmt.Sprintf("  |     |     |--> %s\n", altName.Name)
            }
        }
        r += "  |\n"
    }
    r += "  +-- END \n\n"

	return r
}


func (t *TextWriter) AddCtrl(*models.TestCtrl) error {
	return nil
}
