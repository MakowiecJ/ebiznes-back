package database

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"zadanie4/models"
)

var DB *gorm.DB

func Connect() {
	var err error
	DB, err = gorm.Open(sqlite.Open("zad4.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	DB.Migrator().DropTable(&models.CartProduct{}, &models.Product{}, &models.Cart{}, &models.Category{}, &models.Payment{}, &User{})

	DB.AutoMigrate(&models.Product{}, &models.Cart{}, &models.Category{}, &models.CartProduct{}, &models.Payment{}, &User{})
	InitSampleData()
}

func InitSampleData() {
	category1 := models.Category{Name: "Electronics"}
	category2 := models.Category{Name: "Books"}

	DB.Create(&category1)
	DB.Create(&category2)

	product1 := models.Product{Name: "Laptop", Price: 1500.00, CategoryID: category1.ID}
	product2 := models.Product{Name: "Smartphone", Price: 800.00, CategoryID: category1.ID}
	product3 := models.Product{Name: "Novel", Price: 20.00, CategoryID: category2.ID}

	DB.Create(&product1)
	DB.Create(&product2)
	DB.Create(&product3)

	cart := models.Cart{}
	DB.Create(&cart)

	user := User{Username: "admin", Email: "mail", Password: "admin"}
	DB.Create(&user)
	// DB.Model(&cart).Association("Products").Append(&product1, &product2)
}
