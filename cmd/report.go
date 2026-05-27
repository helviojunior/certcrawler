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
			sql += " " + f + " like '%" + w + "%' "
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

	var rCount = 0

	// Build the optional filter as a sub-query so it carries no bound
	// parameters (the LIKE terms are sanitized and inlined by prepareSQL).
	// Using an "id IN (...)" list instead would re-introduce the very
	// "too many SQL variables" failure we are batching to avoid.
	filterClause := ""
	if len(filterList) > 0 {
		sqlHosts := prepareSQL([]string{"h.ptr", "cn.name"})
		filterClause = "id IN (SELECT distinct h.id from hosts_certs as hc inner join cert_names as cn on cn.certificate_id = hc.certificate_id inner join hosts as h on h.id = hc.host_id WHERE cn.name != '' " + sqlHosts + ")"
	}

	// Page through the hosts with a primary-key cursor. Loading every row at
	// once makes GORM build a single "host_id IN (...)" clause for the
	// preloaded associations, which overflows SQLite's variable limit on
	// large databases. The cursor keeps each preload bounded by batchSize.
	const batchSize = 100
	var lastID uint = 0
	for {
		var batch = []*models.Host{}

		query := conn.Model(&models.Host{}).
			Preload(clause.Associations).
			Preload("Certificates").
			Preload("Certificates.Names").
			Where("id > ?", lastID).
			Order("id").
			Limit(batchSize)

		if filterClause != "" {
			query = query.Where(filterClause)
		}

		if err := query.Find(&batch).Error; err != nil {
			return err
		}

		if len(batch) == 0 {
			break
		}

		// Capture the cursor before ResetID() zeroes the primary keys below.
		lastID = batch[len(batch)-1].ID

		for _, result := range batch {
			if len(result.Certificates) > 0 {
				rCount++
				result.ResetID()
				for _, w := range writers {
					if err := w.Write(result); err != nil {
						return err
					}
				}
			}
		}

		if len(batch) < batchSize {
			break
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
