package main

import (
	"ez-sso/auth"
	"ez-sso/database"
	"ez-sso/utils/firebase"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/spf13/viper"
)

func main() {
	// set env
	viper.SetConfigFile(".env")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}

	engine := html.New("./views", ".html")

	app := fiber.New(fiber.Config{
		Views: engine,
	})

	firebase.Initiate()
	database.Initiate()
	database.DB.AutoMigrate(&auth.User{})
	database.DB.AutoMigrate(&auth.Ticket{})
	database.DB.AutoMigrate(&auth.Account{})

	app.Get("/", func(ctx *fiber.Ctx) error {
		return ctx.Render("index", fiber.Map{
			"Title": "Hello, World!",
		}, "layouts/main")
	})

	auth.AuthRoutes(app)

	app.Listen(":3000")
}
