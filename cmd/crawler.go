package cmd

import (
    "errors"
    "log/slog"
    "os"
    //"fmt"
    "net/netip"

    "github.com/helviojunior/certcrawler/internal/ascii"
    "github.com/helviojunior/certcrawler/internal/tools"
    "github.com/helviojunior/certcrawler/pkg/log"
    "github.com/helviojunior/certcrawler/pkg/runner"
    //"github.com/helviojunior/certcrawler/pkg/database"
    "github.com/helviojunior/certcrawler/pkg/writers"
    "github.com/helviojunior/certcrawler/pkg/readers"
    "github.com/spf13/cobra"
)

var crawlerRunner *runner.Runner

var crawlerWriters = []writers.Writer{}
var bruteCmd = &cobra.Command{
    Use:   "crawler",
    Short: "Perform brute-force enumeration",
    Long: ascii.LogoHelp(ascii.Markdown(`
# brute

Perform brute-force enumeration.

By default, certcrawler will only show information regarding the brute-force process. 
However, that is only half the fun! You can add multiple _writers_ that will 
collect information such as response codes, content, and more. You can specify 
multiple writers using the _--writer-*_ flags (see --help).
`)),
    Example: `
   - certcrawler brute -d helviojunior.com.br -w /tmp/wordlist.txt -o certcrawler.txt
   - certcrawler brute -d helviojunior.com.br -w /tmp/wordlist.txt --write-jsonl
   - certcrawler brute -L domains.txt -w /tmp/wordlist.txt --write-db`,
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        var err error

        // Annoying quirk, but because I'm overriding PersistentPreRun
        // here which overrides the parent it seems.
        // So we need to explicitly call the parent's one now.
        if err = rootCmd.PersistentPreRunE(cmd, args); err != nil {
            return err
        }

        // Configure writers that subcommand scanners will pass to
        // a runner instance.

        //The first one is the general writer (global user)
        w, err := writers.NewDbWriter("sqlite:///" + opts.Writer.UserPath +"/.certcrawler.db", false)
        if err != nil {
            return err
        }
        crawlerWriters = append(crawlerWriters, w)

        //The second one is the STDOut
        if opts.Logging.Silence != true {
            w, err := writers.NewStdoutWriter()
            if err != nil {
                return err
            }
            crawlerWriters = append(crawlerWriters, w)
        }
    
        if opts.Writer.Text {
            w, err := writers.NewTextWriter(opts.Writer.TextFile)
            if err != nil {
                return err
            }
            crawlerWriters = append(crawlerWriters, w)
        }

        if opts.Writer.Jsonl {
            w, err := writers.NewJsonWriter(opts.Writer.JsonlFile)
            if err != nil {
                return err
            }
            crawlerWriters = append(crawlerWriters, w)
        }

        if opts.Writer.Db {
            w, err := writers.NewDbWriter(opts.Writer.DbURI, opts.Writer.DbDebug)
            if err != nil {
                return err
            }
            crawlerWriters = append(crawlerWriters, w)
        }

        if opts.Writer.Csv {
            w, err := writers.NewCsvWriter(opts.Writer.CsvFile)
            if err != nil {
                return err
            }
            crawlerWriters = append(crawlerWriters, w)
        }

        /*
        if opts.Writer.ELastic {
            w, err := writers.NewElasticWriter(opts.Writer.ELasticURI)
            if err != nil {
                return err
            }
            crawlerWriters = append(crawlerWriters, w)
        }*/

        if opts.Writer.None {
            w, err := writers.NewNoneWriter()
            if err != nil {
                return err
            }
            crawlerWriters = append(crawlerWriters, w)
        }

        if len(crawlerWriters) == 0 {
            log.Warn("no writers have been configured. to persist probe results, add writers using --write-* flags")
        }

        return nil
    },
    PreRunE: func(cmd *cobra.Command, args []string) error {
        if opts.HostName == "" && fileOptions.HostFile == "" {
            return errors.New("a Hostname or Hostname list file must be specified")
        }

        if fileOptions.HostFile != "" {
            if !tools.FileExists(fileOptions.HostFile) {
                return errors.New("Hostname list file is not readable")
            }
        }

        if fileOptions.AddrFile == "" {
            return errors.New("an address list file must be specified")
        }

        if !tools.FileExists(fileOptions.AddrFile) {
            return errors.New("the address list file is not readable")
        }

        return nil
    },
    Run: func(cmd *cobra.Command, args []string) {

        log.Debug("Starting certificate crawling")

        addrList := []netip.AddrPort{}
        hostnameList := []string{}
        reader := readers.NewFileReader(fileOptions)
        total := 0

        if fileOptions.HostFile != "" {
            log.Debugf("Reading Hostname list file: %s", fileOptions.HostFile)
            if err := reader.ReadHostList(&hostnameList); err != nil {
                log.Error("error in reader.Read", "err", err)
                os.Exit(2)
            }
        }else{
            hostnameList = append(hostnameList, opts.HostName)
        }
        log.Debugf("Loaded %s hostname(s)", tools.FormatInt(len(hostnameList)))

        log.Debugf("Reading address list file: %s", fileOptions.HostFile)
        if err := reader.ReadAddrList(&addrList); err != nil {
            log.Error("error in reader.Read", "err", err)
            os.Exit(2)
        }
        total = len(addrList) * len(hostnameList)

        if len(hostnameList) == 0 {
            log.Error("Hostname list is empty")
            os.Exit(2)
        }

        if len(addrList) == 0 {
            log.Error("Address list is empty")
            os.Exit(2)
        }

        log.Infof("Enumerating %s hosts", tools.FormatInt(total))

        // An slog-capable logger to use with drivers and runners
        logger := slog.New(log.Logger)
        // Get the runner up. Basically, all of the subcommands will use this.
        crawlerRunner, err := runner.NewRunner(logger, *opts, crawlerWriters, hostnameList)
        if err != nil {
            log.Error("error creating new runner", "err", err)
            os.Exit(2)
        }

        go func() {
            defer close(crawlerRunner.Targets)

            ascii.HideCursor()

            for _, a := range addrList {

                crawlerRunner.Targets <- a

            }
        
        
        }()

        crawlerRunner.Run(total)
        crawlerRunner.Close()

    },
}

func init() {
    rootCmd.AddCommand(bruteCmd)
    
    bruteCmd.Flags().StringVarP(&opts.HostName, "hostname", "d", "", "Single Domain. (ex: www.sec4us.com.br)")
    bruteCmd.Flags().StringVarP(&fileOptions.HostFile, "dns-list", "L", "", "File containing a list of hostnames")
    bruteCmd.Flags().StringVarP(&fileOptions.AddrFile, "addresses", "w", "", "File containing a list of addresses")
    
}