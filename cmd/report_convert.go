package cmd

import (

    "errors"
    "fmt"
    "path/filepath"
    "strings"

    "github.com/helviojunior/certcrawler/internal/ascii"
    "github.com/helviojunior/certcrawler/internal/tools"
    "github.com/helviojunior/certcrawler/pkg/log"
    "github.com/helviojunior/certcrawler/pkg/writers"
    resolver "github.com/helviojunior/gopathresolver"
    "github.com/spf13/cobra"
)

var conversionCmdExtensions = []string{".sqlite3", ".db", ".jsonl"}
var convertCmdFlags = struct {
    fromFile string
    toFile   string

    fromExt string
    toExt   string
}{}
var convertCmd = &cobra.Command{
    Use:   "convert",
    Short: "Convert between SQLite and JSON Lines file formats",
    Long: ascii.LogoHelp(ascii.Markdown(`
# report convert

Convert between SQLite and JSON Lines file formats.

A --from-file and --to-file must be specified. The extension used for the
specified filenames will be used to determine the conversion direction and
target.`)),
    Example: `
   - certcrawler report convert --from-file ~/.certcrawler.sqlite3 --to-file data.jsonl
   - certcrawler report convert --from-file certcrawler.jsonl --to-file db.sqlite3`,
    PreRunE: func(cmd *cobra.Command, args []string) error {
        var err error

        if convertCmdFlags.fromFile == "" {
            return errors.New("from file not set")
        }
        if convertCmdFlags.toFile == "" {
            return errors.New("to file not set")
        }

        convertCmdFlags.fromFile, err = resolver.ResolveFullPath(convertCmdFlags.fromFile)
        if err != nil {
            return err
        }

        convertCmdFlags.toFile, err = resolver.ResolveFullPath(convertCmdFlags.toFile)
        if err != nil {
            return err
        }

        convertCmdFlags.fromExt = strings.ToLower(filepath.Ext(convertCmdFlags.fromFile))
        convertCmdFlags.toExt = strings.ToLower(filepath.Ext(convertCmdFlags.toFile))

        if convertCmdFlags.fromExt == "" || convertCmdFlags.toExt == "" {
            return errors.New("source and destination files must have extensions")
        }

        if convertCmdFlags.fromFile == convertCmdFlags.toFile {
            return errors.New("source and destination files cannot be the same")
        }

        if !tools.SliceHasStr(conversionCmdExtensions, convertCmdFlags.fromExt) {
            return errors.New("unsupported from file type")
        }
        if !tools.SliceHasStr(conversionCmdExtensions, convertCmdFlags.toExt) &&  convertCmdFlags.toExt != ".txt" {
            return errors.New("unsupported to file type")
        }

        return nil
    },
    Run: func(cmd *cobra.Command, args []string) {
        var writer writers.Writer
        var err error
        if convertCmdFlags.toExt == ".sqlite3" || convertCmdFlags.toExt == ".db" {
            writer, err = writers.NewDbWriter(fmt.Sprintf("sqlite:///%s", convertCmdFlags.toFile), false)
            if err != nil {
                log.Error("could not get a database writer up", "err", err)
                return
            }
        } else if convertCmdFlags.toExt == ".jsonl" {
            toFile, err := tools.CreateFileWithDir(convertCmdFlags.toFile)
            if err != nil {
                log.Error("could not create target file", "err", err)
                return
            }
            writer, err = writers.NewJsonWriter(toFile)
            if err != nil {
                log.Error("could not get a JSON writer up", "err", err)
                return
            }
        } else if convertCmdFlags.toExt == ".txt" {
            toFile, err := tools.CreateFileWithDir(convertCmdFlags.toFile)
            if err != nil {
                log.Error("could not create target file", "err", err)
                return
            }
            writer, err = writers.NewTextWriter(toFile)
            if err != nil {
                log.Error("could not get a JSON writer up", "err", err)
                return
            }

        }

        rptWriters = append(rptWriters, writer)

        if convertCmdFlags.fromExt == ".sqlite3" || convertCmdFlags.fromExt == ".db" {
            if err := convertFromDbTo(convertCmdFlags.fromFile, rptWriters); err != nil {
                log.Error("failed to convert from SQLite", "err", err)
                return
            }
        } else if convertCmdFlags.fromExt == ".jsonl" {
            if err := convertFromJsonlTo(convertCmdFlags.fromFile, rptWriters); err != nil {
                log.Error("failed to convert from JSON Lines", "err", err)
                return
            }
        }

        for _, w := range rptWriters {
            w.Finish()
        }
    },
}

func init() {
    reportCmd.AddCommand(convertCmd)

    convertCmd.Flags().StringVar(&convertCmdFlags.fromFile, "from-file", "~/.certcrawler.db", "The file to convert from")
    convertCmd.Flags().StringVar(&convertCmdFlags.toFile, "to-file", "", "The file to convert to. Use .sqlite3 for conversion to SQLite, and .jsonl for conversion to JSON Lines")
}
