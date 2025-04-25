package writers

import (
	"sync"

	"github.com/helviojunior/certcrawler/pkg/database"
	"github.com/helviojunior/certcrawler/pkg/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DbWriter is a Database writer
type DbWriter struct {
	URI           string
	conn          *gorm.DB
	mutex         sync.Mutex
}

// NewDbWriter initialises a database writer
func NewDbWriter(uri string, debug bool) (*DbWriter, error) {
	c, err := database.Connection(uri, false, debug)
	if err != nil {
		return nil, err
	}
	
	if _, ok := c.Statement.Clauses["ON CONFLICT"]; !ok {
		c = c.Clauses(clause.OnConflict{UpdateAll: true})
	}

	return &DbWriter{
		URI:           uri,
		conn:          c,
		mutex:         sync.Mutex{},
	}, nil
}

// Write results to the database
func (dw *DbWriter) Write(host *models.Host) error {
	dw.mutex.Lock()
	defer dw.mutex.Unlock()
	
	//dw.conn.CreateInBatches(host.Certificates, 50)
	//dw.conn.CreateInBatches(host.FQDNs, 50)

	return dw.conn.CreateInBatches(host, 50).Error
}


func (dw *DbWriter) Finish() error {
	return nil
}

