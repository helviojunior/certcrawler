package cmd

import (
	//"crypto/tls"
	"net/url"
	"os/user"
	"os"
	"fmt"
	"errors"
	"os/signal"
    "syscall"
    "time"

	
	//"github.com/helviojunior/certcrawler/internal/tools"
	"github.com/helviojunior/certcrawler/internal/ascii"
	"github.com/helviojunior/certcrawler/pkg/dns"
	"github.com/helviojunior/certcrawler/pkg/log"
	"github.com/helviojunior/certcrawler/pkg/runner"
	"github.com/helviojunior/certcrawler/pkg/readers"
    resolver "github.com/helviojunior/gopathresolver"
	"github.com/spf13/cobra"
)

var (
	opts = &runner.Options{}
	fileOptions = &readers.FileReaderOptions{}
	tProxy = ""
	forceCheck = false
)

var rootCmd = &cobra.Command{
	Use:   "certcrawler",
	Short: "CertCrawler is a modular SSL/TLS certificate crawler",
	Long:  ascii.Logo(),
	Example: `
   - certcrawler crawler file -d sec4us.com.br -f /tmp/endpoint.txt -o certcrawler.txt
   - certcrawler crawler file -d /tmp/hostnames.txt -f /tmp/endpoint.txt --write-db

   - certcrawler crawler nmap -d sec4us.com.br -f /tmp/nmap.xml -o certcrawler.txt
   - certcrawler crawler nmap -d /tmp/hostnames.txt -f /tmp/nmap.xml --write-db`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		
		usr, err := user.Current()
	    if err != nil {
	       return err
	    }

	    opts.Writer.UserPath = usr.HomeDir

	    if cmd.CalledAs() != "version" && !opts.Logging.Silence {
			fmt.Println(ascii.Logo())
		}

		if opts.Logging.Silence {
			log.EnableSilence()
		}

		if opts.Logging.Debug && !opts.Logging.Silence {
			log.EnableDebug()
			log.Debug("debug logging enabled")
		}

        if opts.Writer.TextFile != "" {

        	opts.Writer.TextFile, err = resolver.ResolveFullPath(opts.Writer.TextFile)
	        if err != nil {
	            return err
	        }

            opts.Writer.Text = true
        }

        //Check Proxy config
        if tProxy != "" {
        	u, err := url.Parse(tProxy)
        	if err != nil {
	        	return errors.New("Error parsing URL: " + err.Error())
	        }

	        opts.Proxy = u
	        //fileOptions.ProxyUri = opts.Proxy

			port := u.Port()
			if port == "" {
				port = "1080"
			}
	        log.Warn("Setting proxy to " + u.Scheme + "://" + u.Hostname() + ":" + port)
        }else{
        	opts.Proxy = nil
        }
        
        dns.InitResolver("", tProxy)

		return nil
	},
}

func Execute() {
	
	ascii.SetConsoleColors()

	c := make(chan os.Signal)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        ascii.ClearLine()
        fmt.Fprintf(os.Stderr, "\r\n")
        ascii.ClearLine()
        ascii.ShowCursor()
        log.Warn("interrupted, shutting down...                            ")
        ascii.ClearLine()
        fmt.Printf("\n")
        os.Exit(2)
    }()

	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SilenceErrors = true
	err := rootCmd.Execute()
	if err != nil {
		var cmd string
		c, _, cerr := rootCmd.Find(os.Args[1:])
		if cerr == nil {
			cmd = c.Name()
		}

		v := "\n"

		if cmd != "" {
			v += fmt.Sprintf("An error occured running the `%s` command\n", cmd)
		} else {
			v += "An error has occured. "
		}

		v += "The error was:\n\n" + fmt.Sprintf("```%s```", err)
		fmt.Println(ascii.Markdown(v))

		os.Exit(1)
	}

	//Time to wait the logger flush
	time.Sleep(time.Second/4)
	ascii.ClearLine()
    ascii.ShowCursor()
    fmt.Printf("\n")
}

func init() {
	// Disable Certificate Validation (Globally)
	//http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	rootCmd.PersistentFlags().BoolVarP(&opts.Logging.Debug, "debug-log", "D", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&opts.Logging.Silence, "quiet", "q", false, "Silence (almost all) logging")

    // Logging control for subcommands
    rootCmd.PersistentFlags().BoolVar(&opts.Logging.LogScanErrors, "log-scan-errors", false, "Log scan errors (timeouts, DNS errors, etc.) to stderr (warning: can be verbose!)")

	rootCmd.PersistentFlags().StringVarP(&opts.Writer.TextFile, "write-text-file", "o", "", "The file to write Text lines to")
    

	//rootCmd.PersistentFlags().BoolVarP(&opts.DnsOverHttps.SkipSSLCheck, "ssl-insecure", "K", true, "SSL Insecure")
	rootCmd.PersistentFlags().StringVarP(&tProxy, "proxy", "X", "", "Proxy to pass traffic through: <scheme://ip:port> (e.g., socks4://user:pass@proxy_host:1080")
	//rootCmd.PersistentFlags().StringVarP(&opts.DnsOverHttps.ProxyUser, "proxy-user", "", "", "Proxy User")
	//rootCmd.PersistentFlags().StringVarP(&opts.DnsOverHttps.ProxyPassword, "proxy-pass", "", "", "Proxy Password")

    // "Threads" & other
    rootCmd.PersistentFlags().IntVarP(&opts.Scan.Threads, "threads", "t", 6, "Number of concurrent threads (goroutines) to use")
    rootCmd.PersistentFlags().IntVarP(&opts.Scan.Timeout, "timeout", "T", 60, "Number of seconds before considering a page timed out")

    // Write options for scan subcommands
    rootCmd.PersistentFlags().BoolVar(&opts.Writer.Db, "write-db", false, "Write results to a SQLite database")
    rootCmd.PersistentFlags().StringVar(&opts.Writer.DbURI, "write-db-uri", "sqlite://certcrawler.sqlite3", "The database URI to use. Supports SQLite, Postgres, and MySQL (e.g., postgres://user:pass@host:port/db)")
    rootCmd.PersistentFlags().BoolVar(&opts.Writer.DbDebug, "write-db-enable-debug", false, "Enable database query debug logging (warning: verbose!)")
    rootCmd.PersistentFlags().BoolVar(&opts.Writer.Csv, "write-csv", false, "Write results as CSV (has limited columns)")
    rootCmd.PersistentFlags().StringVar(&opts.Writer.CsvFile, "write-csv-file", "certcrawler.csv", "The file to write CSV rows to")
    rootCmd.PersistentFlags().BoolVar(&opts.Writer.Jsonl, "write-jsonl", false, "Write results as JSON lines")
    rootCmd.PersistentFlags().StringVar(&opts.Writer.JsonlFile, "write-jsonl-file", "certcrawler.jsonl", "The file to write JSON lines to")
    rootCmd.PersistentFlags().BoolVar(&opts.Writer.None, "write-none", false, "Use an empty writer to silence warnings")
    
}
