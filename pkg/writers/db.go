package writers

import (
	"sync"
	"time"
	"github.com/helviojunior/certcrawler/pkg/log"
	"github.com/helviojunior/certcrawler/pkg/database"
	"github.com/helviojunior/certcrawler/pkg/models"
	"gorm.io/gorm"
	//"gorm.io/gorm/clause"
)

var regThreshold = 200

// DbWriter is a Database writer
type DbWriter struct {
	URI           string
	conn          *gorm.DB
	mutex         sync.Mutex
	registers     []models.TestCtrl
}

// NewDbWriter initialises a database writer
func NewDbWriter(uri string, debug bool) (*DbWriter, error) {
	c, err := database.Connection(uri, false, debug)
	if err != nil {
		return nil, err
	}
	
	/*
	if _, ok := c.Statement.Clauses["ON CONFLICT"]; !ok {
		c = c.Clauses(clause.OnConflict{UpdateAll: true})
	}*/

	/*
	if _, ok := c.Statement.Clauses["ON CONFLICT"]; !ok {
		c = c.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "hash"}},
			//DoNothing: true,
			UpdateAll: true,
		})
	}*/

	return &DbWriter{
		URI:           uri,
		conn:          c,
		mutex:         sync.Mutex{},
		registers:     []models.TestCtrl{},
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

func (dw *DbWriter) AddCtrl(ctrl *models.TestCtrl) error {
	dw.mutex.Lock()
	defer dw.mutex.Unlock()

	var err error
	ctrl.ProbedAt = time.Now()

	dw.registers = append(dw.registers, *ctrl)
	if len(dw.registers) >= regThreshold {
		err = dw.conn.CreateInBatches(dw.registers, 50).Error
		dw.registers = []models.TestCtrl{}
	}

	return err
}

func (dw *DbWriter) Finish() error {
	var err error
	dw.mutex.Lock()
	defer dw.mutex.Unlock()

	log.Debug("Finish", "len", len(dw.registers))

	if len(dw.registers) > 0 {
		err = dw.conn.CreateInBatches(dw.registers, 50).Error
		dw.registers = []models.TestCtrl{}
	}

	return err
}

