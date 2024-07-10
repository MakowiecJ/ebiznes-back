package handlers

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"zadanie4/database"
	"zadanie4/models"
)

func GetCategories(c echo.Context) error {
	var categories []models.Category
	database.DB.Preload("Products").Find(&categories)
	return c.JSON(http.StatusOK, categories)
}

func CreateCategory(c echo.Context) error {
	category := new(models.Category)
	if err := c.Bind(category); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	database.DB.Create(&category)
	return c.JSON(http.StatusCreated, category)
}
