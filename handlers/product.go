package handlers

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"zadanie4/database"
	"zadanie4/models"
)

func GetProducts(c echo.Context) error {
	var products []models.Product
	database.DB.Preload("Category").Find(&products)
	return c.JSON(http.StatusOK, products)
}

func GetProduct(c echo.Context) error {
	id := c.Param("id")
	var product models.Product
	if result := database.DB.Preload("Category").First(&product, id); result.Error != nil {
		return c.JSON(http.StatusNotFound, result.Error)
	}
	return c.JSON(http.StatusOK, product)
}

func CreateProduct(c echo.Context) error {
	product := new(models.Product)
	if err := c.Bind(product); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	database.DB.Create(&product)
	return c.JSON(http.StatusCreated, product)
}

func UpdateProduct(c echo.Context) error {
	id := c.Param("id")
	var product models.Product
	if result := database.DB.First(&product, id); result.Error != nil {
		return c.JSON(http.StatusNotFound, result.Error)
	}
	if err := c.Bind(&product); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	database.DB.Save(&product)
	return c.JSON(http.StatusOK, product)
}

func DeleteProduct(c echo.Context) error {
	id := c.Param("id")
	var product models.Product
	if result := database.DB.First(&product, id); result.Error != nil {
		return c.JSON(http.StatusNotFound, result.Error)
	}
	if result := database.DB.Delete(&product); result.Error != nil {
		return c.JSON(http.StatusInternalServerError, result.Error)
	}
	return c.NoContent(http.StatusNoContent)
}
