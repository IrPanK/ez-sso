package auth

import (
	"github.com/gofiber/fiber/v2"
)

func AuthRoutes(app fiber.Router) {
	api := app.Group("")

	api.Get("/login", LoginPage)
	api.Post("/login", HandleLogin)
}
