package cmd

import (
    "errors"
    "os"
    //"fmt"

    "github.com/helviojunior/certcrawler/internal/ascii"
    "github.com/helviojunior/certcrawler/internal/tools"
    "github.com/helviojunior/certcrawler/pkg/log"
    "github.com/helviojunior/certcrawler/pkg/readers"
    resolver "github.com/helviojunior/gopathresolver"
    "github.com/spf13/cobra"
)

var crawlerFileCmd = &cobra.Command{
    Use:   "file",
    Short: "Perform SSL/TLS certificate crawler",
    Long: ascii.LogoHelp(ascii.Markdown(`
# crawler file

Perform SSL/TLS certificate crawler

By default, certcrawler will only show information regarding the crawling process. 
However, that is only half the fun! You can add multiple _writers_ that will 
collect information such as response codes, content, and more. You can specify 
multiple writers using the _--writer-*_ flags (see --help).
`)),
    Example: `
   - certcrawler crawler file -d sec4us.com.br -f /tmp/endpoint.txt -o certcrawler.txt
   - certcrawler crawler file -d /tmp/hostnames.txt -f /tmp/endpoint.txt --write-db`,
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        var err error

        // Annoying quirk, but because I'm overriding PersistentPreRun
        // here which overrides the parent it seems.
        // So we need to explicitly call the parent's one now.
        if err = crawlerCmd.PersistentPreRunE(cmd, args); err != nil {
            return err
        }

        return nil
    },
    PreRunE: func(cmd *cobra.Command, args []string) error {
        var err error

        if err = crawlerCmd.PreRunE(cmd, args); err != nil {
            return err
        }

        if fileOptions.AddrFile == "" {
            return errors.New("an address list file must be specified")
        }

        fileOptions.AddrFile, err = resolver.ResolveFullPath(fileOptions.AddrFile)
        if err != nil {
            return errors.New("invalid address file path: " + err.Error())
        }

        if !tools.FileExists(fileOptions.AddrFile) {
            return errors.New("the address list file is not readable")
        }

        reader := readers.NewFileReader(fileOptions)
        log.Debugf("Reading address list file: %s", fileOptions.HostFile)
        if err := reader.ReadAddrList(&opts.AddrressList); err != nil {
            log.Error("error in reader.Read", "err", err)
            os.Exit(2)
        }
        return nil
    },
    Run: func(cmd *cobra.Command, args []string) {
        //Just run the parent function
        internalCrawlerRun(cmd, args)
    },
    
}

func init() {
    crawlerCmd.AddCommand(crawlerFileCmd)
    
    crawlerFileCmd.Flags().StringVarP(&fileOptions.AddrFile, "file", "f", "", "A file with targets to scan.")
    
}