package models

import (
	"gorm.io/gorm"
)

type Cart struct {
	gorm.Model
	Products   []CartProduct `gorm:"foreignKey:CartID"`
	TotalPrice float64       `gorm:"default:0"`
}

type CartProduct struct {
	gorm.Model
	CartID    uint
	ProductID uint
	Product   Product `gorm:"foreignKey:ProductID"`
	Quantity  int
}
