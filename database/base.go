package database

import (
	"time"

	"github.com/jaevor/go-nanoid"
	"gorm.io/gorm"
)

type Base struct {
	ID        string `gorm:"primary_key;"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `sql:"index"`
}

// BeforeCreate will set a nanoid rather than numeric ID.
func (base *Base) BeforeCreate(tx *gorm.DB) (err error) {
	canonicID, err := nanoid.Standard(21)
	if err != nil {
		panic(err)
	}

	nanoId := canonicID()

	base.ID = nanoId // set ID with nanoId

	return
}
