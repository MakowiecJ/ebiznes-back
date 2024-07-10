package models

import (
	"gorm.io/gorm"
	"time"
)

type Payment struct {
	gorm.Model
	CartID     uint      `gorm:"not null"`
	TotalPrice float64   `gorm:"default:0"`
	PaidAt     time.Time `gorm:"not null"`
}
