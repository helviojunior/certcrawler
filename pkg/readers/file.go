package readers

import (
	"bufio"
	//"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	//"github.com/helviojunior/certcrawler/internal/tools"
	"github.com/helviojunior/certcrawler/pkg/log"
)

// FileReader is a reader that expects a file with targets that
// is newline delimited.
type FileReader struct {
	Options *FileReaderOptions
}

// FileReaderOptions are options for the file reader
type FileReaderOptions struct {
	AddrFile    	string
	HostFile		string
}

// NewFileReader prepares a new file reader
func NewFileReader(opts *FileReaderOptions) *FileReader {
	return &FileReader{
		Options: opts,
	}
}

// Read from a file.
func (fr *FileReader) ReadAddrList(outList *[]netip.AddrPort) error {
	
	var file *os.File
	var err error

	file, err = os.Open(fr.Options.AddrFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		candidate := scanner.Text()
		if candidate == "" {
			continue
		}

		p := strings.Split(candidate, ":")
		if len(p) != 2 {
			ip, err := netip.ParseAddr(candidate)
	        if err != nil {
	            log.Debugf("Invalid IP (%s): %s", candidate, err.Error())
		        continue
	        }
			
			*outList = append(*outList, netip.AddrPortFrom(ip, 443))

		}else{

			ip, err := netip.ParseAddr(p[0])
	        if err != nil {
	            log.Debugf("Invalid IP (%s): %s", p[0], err.Error())
		        continue
	        }

			port, err := strconv.Atoi(p[1])
		    if err != nil {
		        log.Debugf("Invalid port (%s): %s", p[1], err.Error())
		        continue
		    }

			*outList = append(*outList, netip.AddrPortFrom(ip, uint16(port)))
		}

	}

	return scanner.Err()
}

func (fr *FileReader) ReadHostList(outList *[]string) error {
	return fr.readFileList(fr.Options.HostFile, outList)
}

// Read from a file.
func (fr *FileReader) readFileList(fileName string, outList *[]string) error {

	var file *os.File
	var err error

	file, err = os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		candidate := scanner.Text()
		if candidate == "" {
			continue
		}

		candidate = strings.Trim(strings.ToLower(candidate), ". ")

        //Check if hostname is valid
        _, err := url.Parse("https://" + candidate)
        if err != nil {
        	log.Debug("Invalid hostname", "err", err)
        	continue
        }
    
		*outList = append(*outList, candidate)
	}

	return scanner.Err()
}
