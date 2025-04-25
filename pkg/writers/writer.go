package writers

import "github.com/helviojunior/certcrawler/pkg/models"

// Writer is a results writer
type Writer interface {
	Write(*models.Host) error
	AddCtrl(*models.TestCtrl) error
	Finish() error
}
