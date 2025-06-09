package cmd

import (
    "errors"

    "github.com/helviojunior/certcrawler/internal/ascii"
    "github.com/helviojunior/certcrawler/internal/tools"
    "github.com/helviojunior/certcrawler/pkg/log"
    "github.com/helviojunior/certcrawler/pkg/readers"
    resolver "github.com/helviojunior/gopathresolver"
    "github.com/spf13/cobra"
)

var nmapCmdOptions = &readers.NmapReaderOptions{}
var crawlerNmapCmd = &cobra.Command{
    Use:   "nmap",
    Short: "Perform SSL/TLS certificate crawler from an Nmap XML file",
    Long: ascii.LogoHelp(ascii.Markdown(`
# crawler nmap

Scan targets from an Nmap XML file.

When performing Nmap scans, specify the -oX nmap.xml flag to store data in an
XML-formatted file that certcrawler can parse.

By default, this command will try and get certificate of all ports specified in an
nmap.xml results file. That means it will try and do silly things like
get TLS from a SSH services, which obviously won't work. It's for this reason that
you'd want to specify the ports to parse using the --port flag. 

On ports, when specifying --port (can be multiple), target candidates will only
be generated for results that match one of the specified ports.
`)),
    Example: `
   - certcrawler crawler file -d sec4us.com.br -f /tmp/targets.xml -o certcrawler.txt
   - certcrawler crawler file -d /tmp/hostnames.txt -f /tmp/targets.xml --write-db
   - certcrawler crawler file -d /tmp/hostnames.txt -f /tmp/targets.xml --port 443 --port 8443`,
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

        if nmapCmdOptions.Source == "" {
            return errors.New("a Nmap XML file must be specified")
        }

        nmapCmdOptions.Source, err = resolver.ResolveFullPath(nmapCmdOptions.Source)
        if err != nil {
            return errors.New("invalid Nmap XML file path: " + err.Error())
        }

        if !tools.FileExists(nmapCmdOptions.Source) {
            return errors.New("the Nmap XML file is not readable")
        }

        nmapReader := readers.NewNmapReader(nmapCmdOptions)
        log.Debugf("Reading address list file: %s", fileOptions.HostFile)
        if err := nmapReader.Read(&opts.AddrressList); err != nil {
            log.Error("error in nmapReader.Read", "err", err)
            return err
        }

        fileOptions.AddrFile = nmapCmdOptions.Source

        return nil
    },
    Run: func(cmd *cobra.Command, args []string) {
        //Just run the parent function
        internalCrawlerRun(cmd, args)
    },
    
}

func init() {
    crawlerCmd.AddCommand(crawlerNmapCmd)
    
    crawlerNmapCmd.Flags().StringVarP(&nmapCmdOptions.Source, "file", "f", "", "A file with targets to scan.")
    crawlerNmapCmd.Flags().IntSliceVar(&nmapCmdOptions.Ports, "port", []int{}, "A port filter to apply. Supports multiple --port flags")
    
}