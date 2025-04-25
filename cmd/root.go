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
	Short: "certcrawler is a modular DNS recon tool",
	Long:  ascii.Logo(),
	Example: `
   - certcrawler recon -d helviojunior.com.br -o certcrawler.txt
   - certcrawler recon -d helviojunior.com.br --write-jsonl
   - certcrawler recon -L domains.txt --write-db   

   - certcrawler brute -d helviojunior.com.br -w /tmp/wordlist.txt -o certcrawler.txt
   - certcrawler brute -d helviojunior.com.br -w /tmp/wordlist.txt --write-jsonl
   - certcrawler brute -L domains.txt -w /tmp/wordlist.txt --write-db   

   - certcrawler resolve bloodhound -L /tmp/bloodhound_computers.json -o certcrawler.txt
   - certcrawler resolve bloodhound -L /tmp/bloodhound_files.zip --write-jsonl
   - certcrawler resolve bloodhound -L /tmp/bloodhound_computers.json --write-db

   - certcrawler resolve file -L /tmp/host_list.txt -o certcrawler.txt
   - certcrawler resolve file -L /tmp/host_list.txt --write-jsonl
   - certcrawler resolve file -L /tmp/host_list.txt --write-db`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		
		usr, err := user.Current()
	    if err != nil {
	       return err
	    }

	    opts.Writer.UserPath = usr.HomeDir

	    if cmd.CalledAs() != "version" {
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

    rootCmd.PersistentFlags().BoolVar(&opts.Writer.ELastic, "write-elastic", false, "Write results to a SQLite database")
    rootCmd.PersistentFlags().StringVar(&opts.Writer.ELasticURI, "write-elasticsearch-uri", "http://localhost:9200/certcrawler", "The elastic search URI to use. (e.g., http://user:pass@host:9200/index)")

    
}
