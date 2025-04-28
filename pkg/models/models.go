package models

import (
	"time"
	"encoding/json"
	//"fmt"
	"strings"


	//"github.com/helviojunior/certcrawler/pkg/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)


type TestCtrl struct {
	ID       uint `json:"id" gorm:"primarykey"`

	Ip				string      `json:"ip"`
	Port        	uint        `json:"port"`
	FQDN        	string      `json:"fqdn"`

	ProbedAt        time.Time `json:"probe_at"`
}

func (TestCtrl) TableName() string {
    return "test_control"
}

/*
func (TestCtrl) BeforeCreate(tx *gorm.DB) (err error) {
	tx.Statement.SetColumn("probe_at", time.Now())

	return nil
}*/


// Result is a github.com/helviojunior/certcrawlercertcrawler result
type Certificate struct {
	//Parent *Certificate
    //ParentID uint `json:"parent_id" gorm:"TYPE:integer REFERENCES certificates"`

	ID uint `json:"id" gorm:"primarykey, TYPE:integer"`

	Fingerprint           string    `json:"fingerprint" gorm:"index:,unique;"`
	Subject               string    `json:"subject"`
	Issuer                string    `json:"issuer"`
	NotBefore             time.Time `json:"not_before"`
	NotAfter              time.Time `json:"not_after"`
	ProbedAt              time.Time `json:"probe_at"`

	IsRootCA       		  bool   	`json:"root_ca"`
	IsCA        		  bool   	`json:"ca"`
	SelfSigned     		  bool   	`json:"self_signed"`

	RawData 			  string    `json:"raw_data"`

	Names        []*CertNames        `json:"names" gorm:"constraint:OnDelete:CASCADE"`

	Hosts        []*Host `gorm:"many2many:hosts_certs;"`
}

func (Certificate) TableName() string {
    return "certificates"
}

func (cert *Certificate) String() string {
    return cert.Subject
}

/* Custom Marshaller for Result */
func (result Certificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID                    uint      `json:"id"`
		//ParentID              uint      `json:"parent_id"`
		Fingerprint           string    `json:"fingerprint"`
		Subject               string    `json:"subject"`
		Issuer                string    `json:"issuer"`
		NotBefore             string    `json:"not_before"`
		NotAfter              string    `json:"not_after"`
		ProbedAt              string    `json:"probe_at"`
		IsRootCA              bool      `json:"root_ca"`
		IsCA                  bool      `json:"ca"`
		SelfSigned            bool      `json:"self_signed"`
		RawData               string    `json:"raw_data"`
		Names        []*CertNames        `json:"names"`

	}{
		ID   				: result.ID,
		//ParentID 			: result.ParentID,
		Fingerprint			: strings.Trim(strings.ToLower(result.Fingerprint), ". "),
		Subject				: result.Subject,
		Issuer				: result.Issuer,
		NotBefore    		: result.NotBefore.Format(time.RFC3339),
		NotAfter    		: result.NotAfter.Format(time.RFC3339),
		ProbedAt    		: result.ProbedAt.Format(time.RFC3339),
		IsRootCA 			: result.IsRootCA,
		IsCA 				: result.IsCA,
		SelfSigned 			: result.SelfSigned,
		RawData 			: result.RawData,
		Names 			    : result.Names,
	})
}

func (Certificate) BeforeCreate(tx *gorm.DB) (err error) {
	tx.Statement.AddClause(clause.OnConflict{
		//Columns:   cols,
		Columns:   []clause.Column{{Name: "fingerprint"}},
		DoUpdates: clause.AssignmentColumns([]string{ "subject" }),
		//DoNothing: true,
		//UpdateAll: true,
	})
	return nil
}

type CertNames struct {
	ID       uint `json:"id" gorm:"primarykey"`
	CertificateID   uint `json:"cert_id" gorm:"index:idx_cert"`

	Type		string      `json:"type"`
	Name        string      `json:"name"`
}

func (CertNames) TableName() string {
    return "cert_names"
}

type Host struct {
	ID       uint `json:"id" gorm:"primarykey"`

	Ip				string      `json:"ip"`
	Port        	uint        `json:"port"`
	Cloud        	string      `json:"cloud"`
	Ptr        		string      `json:"ptr"`
	Host			string      `json:"host" gorm:"index:,unique;"`
	//FQDN        	string      `json:"fqdn" gorm:uniqueIndex:idx_host_port"`

	Certificates    []*Certificate `gorm:"many2many:hosts_certs;"`
	FQDNs           []*FQDN 		  `json:"fqdn" gorm:"constraint:OnDelete:CASCADE"`
}

func (Host) TableName() string {
    return "hosts"
}

func (Host) BeforeCreate(tx *gorm.DB) (err error) {
	tx.Statement.AddClause(clause.OnConflict{
		//Columns:   cols,
		Columns:   []clause.Column{{Name: "host"}},
		DoUpdates: clause.AssignmentColumns([]string{ "ip", "port" }),
		//DoNothing: true,
		//UpdateAll: true,
	})
	return nil
}

type FQDN struct {
	ID       uint `json:"id" gorm:"primarykey"`
	HostID   uint `json:"host_id"`

	FQDN        	string      `json:"fqdn"`
}

func (FQDN) TableName() string {
    return "fqdn"
}

func (host *Host) AddCertificate(cert *Certificate) {
	if !host.HasCert(cert) {
		host.Certificates = append(host.Certificates, cert)
	}
}

func (host *Host) HasCert(cert *Certificate) bool {
	for _, c := range host.Certificates {
		if c.Fingerprint == cert.Fingerprint {
			return true
		}
	}

	return false
}

func (host *Host) AddFQDN(fqdn string) {
	fqdn = strings.Trim(strings.ToLower(fqdn), ". ")
	if !host.HasFQDN(fqdn) {
		host.FQDNs = append(host.FQDNs, &FQDN{FQDN:fqdn,})
	}
}

func (host *Host) HasFQDN(fqdn string) bool {
	fqdn = strings.Trim(strings.ToLower(fqdn), ". ")
	for _, f := range host.FQDNs {
		if f.FQDN == fqdn {
			return true
		}
	}

	return false
}

