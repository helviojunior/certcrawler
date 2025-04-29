package cmd

import (
	"bufio"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "regexp"
    "strings"

    "github.com/helviojunior/certcrawler/internal/ascii"
    "github.com/helviojunior/certcrawler/pkg/database"
    "github.com/helviojunior/certcrawler/pkg/log"
    "github.com/helviojunior/certcrawler/pkg/models"
    "github.com/helviojunior/certcrawler/pkg/writers"
    "github.com/spf13/cobra"
    "gorm.io/gorm/clause"
)

var rptFilter = ""
var rptWriters = []writers.Writer{}
var filterList = []string{}
var reportCmd = &cobra.Command{
    Use:   "report",
    Short: "Work with certcrawler reports",
    Long: ascii.LogoHelp(ascii.Markdown(`
# report

Work with certcrawler reports.
`)),
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        var err error

        // Annoying quirk, but because I'm overriding PersistentPreRun
        // here which overrides the parent it seems.
        // So we need to explicitly call the parent's one now.
        if err = rootCmd.PersistentPreRunE(cmd, args); err != nil {
            return err
        }

        re := regexp.MustCompile("[^a-zA-Z0-9@-_.]")
        s := strings.Split(rptFilter, ",")
        for _, s1 := range s {
            s2 := strings.ToLower(strings.Trim(s1, " "))
            s2 = re.ReplaceAllString(s2, "")
            if s2 != "" {
                filterList = append(filterList, s2)
            }
        }
        
        if len(filterList) > 0 {
            log.Warn("Filter list: " + strings.Join(filterList, ", "))
        }

        //The second one is the STDOut
        if opts.Logging.Silence != true {
            w, err := writers.NewStdoutWriter()
            if err != nil {
                return err
            }
            rptWriters = append(rptWriters, w)
        }
    
        if opts.Writer.Text {
            w, err := writers.NewTextWriter(opts.Writer.TextFile)
            if err != nil {
                return err
            }
            rptWriters = append(rptWriters, w)
        }
        return nil
    },
}

func init() {
    rootCmd.AddCommand(reportCmd)

    reportCmd.PersistentFlags().StringVar(&rptFilter, "filter", "", "Comma-separated terms to filter results")
}


func prepareSQL(fields []string) string {
    sql := ""
    for _, f := range fields {
        for _, w := range filterList {
            if sql != "" {
                sql += " or "
            }
            sql += " " + f + " like '%"+ w + "%' "
        }
    }
    if sql != "" {
        sql = " and (" + sql + ")"
    }
    return sql
}


func convertFromDbTo(from string, writers []writers.Writer) error {

    if len(writers) == 0 {
        log.Warn("no writers have been configured. to persist probe results, add writers using --write-* flags")
    }

	log.Info("starting conversion...")

    conn, err := database.Connection(fmt.Sprintf("sqlite:///%s", from), true, false)
    if err != nil {
        return err
    }

    var results = []*models.Host{}
    var ids = []int{}
    var rCount = 0

    if len(filterList) > 0 {
        sqlHosts := prepareSQL([]string{"h.ptr", "cn.name"})

        if err := conn.Raw("SELECT distinct h.id from hosts_certs as hc inner join cert_names as cn on cn.certificate_id = hc.host_id inner join hosts as h on h.id = hc.host_id WHERE cn.name != '' " + sqlHosts).Find(&ids).Error; err != nil {
            return err
        }
        if err := conn.Model(&models.Host{}).Preload(clause.Associations).Where("id in ?", ids).Preload("Certificates").Preload("Certificates.Names").Find(&results).Error; err != nil {
            return err
        }
    }else{
        if err := conn.Model(&models.Host{}).Preload(clause.Associations).Where("host != ''").Preload("Certificates").Preload("Certificates.Names").Find(&results).Error; err != nil {
            return err
        }
    }

    for _, result := range results {
        if len(result.Certificates) > 0 {
            rCount++
            for _, w := range writers {
                if err := w.Write(result); err != nil {
                    return err
                }
            }
        }
        
    }

    log.Info("converted from a database", "rows", rCount)
    return nil
}

func convertFromJsonlTo(from string, writers []writers.Writer) error {
    
    if len(writers) == 0 {
        log.Warn("no writers have been configured. to persist probe results, add writers using --write-* flags")
    }

	log.Info("starting conversion...")

    file, err := os.Open(from)
    if err != nil {
        return err
    }
    defer file.Close()

    var c = 0

    reader := bufio.NewReader(file)
    for {
        line, err := reader.ReadBytes('\n')
        if err != nil {
            if err == io.EOF {
                if len(line) == 0 {
                    break // End of file
                }
                // Handle the last line without '\n'
            } else {
                return err
            }
        }

        var host models.Host
        if err := json.Unmarshal(line, &host); err != nil {
            log.Error("could not unmarshal JSON line", "err", err)
            continue
        }

        for _, w := range writers {
            if err := w.Write(&host); err != nil {
                return err
            }
        }

        c++

        if err == io.EOF {
            break
        }
    }

    log.Info("converted from a JSON Lines file", "rows", c)
    return nil
}