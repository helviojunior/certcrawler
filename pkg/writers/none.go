package writers

import (
	"github.com/helviojunior/certcrawler/pkg/models"
)

// NoneWriter is a None writer
type NoneWriter struct {
}

// NewNoneWriter initialises a none writer
func NewNoneWriter() (*NoneWriter, error) {
	return &NoneWriter{}, nil
}

// Write does nothing
func (s *NoneWriter) Write(result *models.Host) error {
	return nil
}

func (s *NoneWriter) Finish() error {
    return nil
}