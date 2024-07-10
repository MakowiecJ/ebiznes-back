package handlers

import (
	"net/http"
	"time"
	"zadanie4/database"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("your_secret_key")

type UserRegisterRequest struct {
	Username string `json:"username" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UserLoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func Register(c echo.Context) error {
	req := new(UserRegisterRequest)
	if err := c.Bind(req); err != nil {
		c.Logger().Errorf("Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.Logger().Errorf("Failed to hash password: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Internal server error"})
	}

	user := &database.User{
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
	}

	if err := database.CreateUser(user); err != nil {
		c.Logger().Errorf("Failed to create user: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Internal server error"})
	}

	return c.JSON(http.StatusCreated, echo.Map{"message": "User created successfully"})
}

func Login(c echo.Context) error {
	req := new(UserLoginRequest)
	if err := c.Bind(req); err != nil {
		c.Logger().Errorf("Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request"})
	}

	user, err := database.GetUserByEmail(req.Email)
	if err != nil {
		c.Logger().Errorf("Failed to find user: %v", err)
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid email or password"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.Logger().Errorf("Password comparison failed: %v", err)
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid email or password"})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.Logger().Errorf("Failed to sign token: %v", err)
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Internal server error"})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"id":       user.ID,
		"email":    user.Email,
		"username": user.Username,
		"token":    tokenString,
	})
}
