package models

import (
	"gorm.io/gorm"
)

type Product struct {
	gorm.Model
	Name       string
	Price      float64
	CategoryID uint
	Category   Category
}

func FilterByCategory(categoryID uint) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("category_id = ?", categoryID)
	}
}

func FilterByPrice(min, max float64) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("price BETWEEN ? AND ?", min, max)
	}
}
