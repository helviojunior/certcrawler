package cmd

import (
    "errors"
    "os"
    "net/url"
    "log/slog"

    "github.com/helviojunior/certcrawler/internal/ascii"
    "github.com/helviojunior/certcrawler/internal/tools"
    "github.com/helviojunior/certcrawler/pkg/log"
    "github.com/helviojunior/certcrawler/pkg/runner"
    "github.com/helviojunior/certcrawler/pkg/readers"
    "github.com/helviojunior/certcrawler/pkg/writers"
    resolver "github.com/helviojunior/gopathresolver"
    "github.com/spf13/cobra"
)


var tempFolder string
var crawlerRunner *runner.Runner
var crawlerWriters = []writers.Writer{}
var crawlerCmd = &cobra.Command{
    Use:   "crawler",
    Short: "Perform SSL/TLS certificate crawler",
    Long: ascii.LogoHelp(ascii.Markdown(`
# crawler

Perform SSL/TLS certificate crawler

By default, certcrawler will only show information regarding the crawling process. 
However, that is only half the fun! You can add multiple _writers_ that will 
collect information such as response codes, content, and more. You can specify 
multiple writers using the _--writer-*_ flags (see --help).
`)),
    Example: `
   - certcrawler crawler file -d sec4us.com.br -f /tmp/endpoint.txt -o certcrawler.txt
   - certcrawler crawler file -d /tmp/hostnames.txt -f /tmp/endpoint.txt --write-db

   - certcrawler crawler nmap -d sec4us.com.br -f /tmp/nmap.xml -o certcrawler.txt
   - certcrawler crawler nmap -d /tmp/hostnames.txt -f /tmp/nmap.xml --write-db`,
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

        controlDb := "sqlite:///"+ opts.Writer.UserPath + "/.certcrawler.db"

        basePath := ""
        if opts.StoreTempAsWorkspace {
            basePath = "./"
        }

        if tempFolder, err = tools.CreateDir(tools.TempFileName(basePath, "certcrawler_", "")); err != nil {
            log.Error("error creatting temp folder", "err", err)
            os.Exit(2)
        }

        if opts.Writer.NoControlDb {
            controlDb = "sqlite:///"+ tools.TempFileName(tempFolder, "certcrawler_", ".db")
        }

        //The first one is the general writer (global user)
        w, err := writers.NewDbWriter(controlDb, false)
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
        if opts.HostName == "" {
            return errors.New("a Hostname or Hostname list file must be specified")
        }

        fp, err := resolver.ResolveFullPath(opts.HostName)
        if err == nil {
            if tools.FileExists(opts.HostName) {
                fileOptions.HostFile = fp
                opts.HostName = ""
            }
        }

        //Check if hostname is valid
        if opts.HostName != "" {
            _, err := url.Parse("https://" + opts.HostName)
            if err != nil {
                return errors.New("Invalid hostname: " + err.Error())
            }
        }

        reader := readers.NewFileReader(fileOptions)

        if fileOptions.HostFile != "" {
            log.Debugf("Reading Hostname list file: %s", fileOptions.HostFile)
            if err := reader.ReadHostList(&opts.HostnameList); err != nil {
                log.Error("error in reader.Read", "err", err)
                return err
            }
            log.Infof("Using hosts list file: %s", fileOptions.HostFile)
        }else{
            opts.HostnameList = append(opts.HostnameList, opts.HostName)
            log.Infof("Using hosts: %s", opts.HostName)
        }

        if len(opts.HostnameList) == 0 {
            return errors.New("Hostname list is empty")
        }

        log.Debugf("Loaded %s hostname(s)", tools.FormatInt(len(opts.HostnameList)))

        return nil
    },
    
}

func internalCrawlerRun(cmd *cobra.Command, args []string) {

    log.Infof("Using address list file: %s", fileOptions.AddrFile)

    if len(opts.AddrressList) == 0 {
        log.Error("Address list is empty")
        os.Exit(2)
    }

    total := len(opts.AddrressList) * len(opts.HostnameList)
    log.Infof("Enumerating %s hosts", tools.FormatInt(total))

    // An slog-capable logger to use with drivers and runners
    logger := slog.New(log.Logger)
    // Get the runner up. Basically, all of the subcommands will use this.
    crawlerRunner, err := runner.NewRunner(logger, *opts, crawlerWriters, "sqlite:///" + opts.Writer.UserPath +"/.certcrawler.db")
    if err != nil {
        log.Error("error creating new runner", "err", err)
        os.Exit(2)
    }

    go func() {
        defer close(crawlerRunner.Targets)

        ascii.HideCursor()

        for _, a := range opts.AddrressList {

            crawlerRunner.Targets <- a

        }
    
    
    }()

    crawlerRunner.Run(total)
    crawlerRunner.Close()

}

func init() {
    rootCmd.AddCommand(crawlerCmd)
    
    crawlerCmd.PersistentFlags().StringVarP(&opts.HostName, "hostname", "d", "", "Hostname or Hostname file list")
    crawlerCmd.PersistentFlags().BoolVarP(&opts.ForceCheck, "force", "F", false, "Force to check all hosts again.")
    crawlerCmd.PersistentFlags().BoolVar(&opts.Writer.NoControlDb, "disable-control-db", false, "Disable utilization of database ~/.certcrawler.db.")
    crawlerCmd.PersistentFlags().BoolVar(&opts.StoreTempAsWorkspace, "local-temp", false, "Use execution path to store temp files")
    
}