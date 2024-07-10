package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"zadanie4/database"
	"zadanie4/handlers"
)

func main() {
	database.Connect()

	e := echo.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:3000", "https://ebiznes.azurewebsites.net"},
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.DELETE},
	}))

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.GET("/products", handlers.GetProducts)
	e.GET("/products/:id", handlers.GetProduct)
	e.POST("/products", handlers.CreateProduct)
	e.PUT("/products/:id", handlers.UpdateProduct)
	e.DELETE("/products/:id", handlers.DeleteProduct)

	e.GET("/carts", handlers.GetCarts)
	e.GET("/carts/:cartId", handlers.GetCart)
	e.POST("/carts", handlers.CreateCart)
	e.POST("/carts/:cartId/products", handlers.AddProductToCart)
	e.POST("/carts/:cartId/pay", handlers.PayCart)

	e.GET("/categories", handlers.GetCategories)
	e.POST("/categories", handlers.CreateCategory)

	e.GET("/payments", handlers.GetPayments)

	e.POST("/register", handlers.Register)
	e.POST("/login", handlers.Login)

	r := e.Group("/restricted")
	r.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: []byte("your_secret_key"),
	}))

	e.Logger.Fatal(e.Start(":8080"))
}
