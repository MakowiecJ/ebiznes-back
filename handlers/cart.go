package handlers

import (
	"net/http"
	"strconv"
	"time"
	"zadanie4/database"
	"zadanie4/models"

	"github.com/labstack/echo/v4"
)

func GetCarts(c echo.Context) error {
	var carts []models.Cart
	database.DB.Preload("Products.Product").Find(&carts)
	return c.JSON(http.StatusOK, carts)
}

func GetCart(c echo.Context) error {
	id := c.Param("cartId")
	var cart models.Cart
	if result := database.DB.Preload("Products.Product").First(&cart, id); result.Error != nil {
		return c.JSON(http.StatusNotFound, result.Error)
	}
	return c.JSON(http.StatusOK, cart)
}

func CreateCart(c echo.Context) error {
	cart := new(models.Cart)
	if err := c.Bind(cart); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}
	database.DB.Create(&cart)
	return c.JSON(http.StatusCreated, cart)
}

func AddProductToCart(c echo.Context) error {
	cartId, _ := strconv.Atoi(c.Param("cartId"))
	productId, _ := strconv.Atoi(c.FormValue("productId"))
	quantity, _ := strconv.Atoi(c.FormValue("quantity"))

	tx := database.DB.Begin()

	var cart models.Cart
	if result := tx.Preload("Products.Product").First(&cart, cartId); result.Error != nil {
		tx.Rollback()
		return c.JSON(http.StatusNotFound, "Cart not found")
	}

	var product models.Product
	if result := tx.First(&product, productId); result.Error != nil {
		tx.Rollback()
		return c.JSON(http.StatusNotFound, "Product not found")
	}

	exists := false
	for i, cp := range cart.Products {
		if cp.ProductID == uint(productId) {
			// Znaleziono produkt w koszyku, aktualizujemy ilość
			cart.Products[i].Quantity += quantity
			exists = true
			// Aktualizacja rekordu CartProduct w bazie danych
			if err := tx.Model(&cart.Products[i]).Update("quantity", cart.Products[i].Quantity).Error; err != nil {
				tx.Rollback()
				return c.JSON(http.StatusInternalServerError, "Failed to update cart product quantity")
			}
			break
		}
	}

	if !exists {
		newCartProduct := models.CartProduct{
			CartID:    uint(cartId),
			ProductID: uint(productId),
			Quantity:  quantity,
		}
		if err := tx.Create(&newCartProduct).Error; err != nil {
			tx.Rollback()
			return c.JSON(http.StatusInternalServerError, "Failed to create cart product")
		}

		if err := tx.Preload("Product").Find(&newCartProduct).Error; err != nil {
			tx.Rollback()
			return c.JSON(http.StatusInternalServerError, "Failed to load product for cart product")
		}

		cart.Products = append(cart.Products, newCartProduct)
	}
	cart.TotalPrice += product.Price * float64(quantity)

	if err := tx.Save(&cart).Error; err != nil {
		tx.Rollback()
		return c.JSON(http.StatusInternalServerError, "Failed to update cart")
	}

	tx.Commit()

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Product added to cart successfully",
	})
}

func PayCart(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("cartId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, "Invalid cart ID")
	}

	var cart models.Cart
	if result := database.DB.First(&cart, id); result.Error != nil {
		return c.JSON(http.StatusNotFound, result.Error)
	}

	payment := models.Payment{
		CartID:     cart.ID,
		TotalPrice: cart.TotalPrice,
		PaidAt:     time.Now(),
	}
	if result := database.DB.Create(&payment); result.Error != nil {
		return c.JSON(http.StatusInternalServerError, result.Error)
	}

	if result := database.DB.Where("cart_id = ?", id).Delete(&models.CartProduct{}); result.Error != nil {
		return c.JSON(http.StatusInternalServerError, result.Error)
	}

	cart.TotalPrice = 0
	database.DB.Save(&cart)

	return c.JSON(http.StatusOK, "Cart paid and cleared")
}

func GetPayments(c echo.Context) error {
	var payments []models.Payment
	if result := database.DB.Find(&payments); result.Error != nil {
		return c.JSON(http.StatusInternalServerError, result.Error)
	}

	return c.JSON(http.StatusOK, payments)
}
