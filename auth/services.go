package auth

import (
	"context"
	"ez-sso/database"
	"ez-sso/utils/bcrypt"
	admin "ez-sso/utils/firebase"
	"fmt"
	"log"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

type LoginDTO struct {
	Email    string `json:"email" form:"email"`
	Password string `json:"password" form:"password"`
	Service  string `json:"service" form:"service"`
	Id_token string `json:"idToken" form:"idToken"`
}

// TODO: SECURE TOKEN WITH JWT OR ANYTHING !!!!!
// TODO: IMPROVE TOKEN SECURITY !!!!!

func LoginPage(ctx *fiber.Ctx) error {
	token := ctx.Cookies("token")

	if token != "" {
		now := time.Now()

		service := ctx.Query("service")
		if service == "" {
			service = fmt.Sprintf("%s", viper.Get("DEFAULT_SERVICE"))
		}

		ticket := updateTicketAndCookies(ctx, token, service, now)

		targetRedirect := fmt.Sprintf("%s?ticket=%s", service, ticket.ID)

		return ctx.Redirect(targetRedirect)
	}

	return ctx.Render("auth/login", fiber.Map{
		"FIREBASE_API_KEY":             viper.Get("FIREBASE_API_KEY"),
		"FIREBASE_AUTH_DOMAIN":         viper.Get("FIREBASE_AUTH_DOMAIN"),
		"FIREBASE_PROJECT_ID":          viper.Get("FIREBASE_PROJECT_ID"),
		"FIREBASE_STORAGE_BUCKET":      viper.Get("FIREBASE_STORAGE_BUCKET"),
		"FIREBASE_MESSAGING_SENDER_ID": viper.Get("FIREBASE_MESSAGING_SENDER_ID"),
		"FIREBASE_APP_ID":              viper.Get("FIREBASE_APP_ID"),
		"FIREBASE_MEASUREMENT_ID":      viper.Get("FIREBASE_MEASUREMENT_ID"),
	}, "layouts/main")
}

func HandleLogin(ctx *fiber.Ctx) error {
	data := new(LoginDTO)

	if err := ctx.BodyParser(data); err != nil {
		return err
	}

	email := strings.ToLower(data.Email)

	var user User

	if data.Id_token != "" {
		token := verifyIDToken(context.Background(), admin.Admin, data.Id_token)

		result := database.DB.Where(&User{Email: token.Claims["email"].(string)}).First(&user)

		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				user = User{Email: token.Claims["email"].(string)}
				database.DB.Create(&user)
				account := Account{UserId: user.ID, Provider: token.Firebase.SignInProvider, Uid: token.UID}
				database.DB.Create(&account)
			} else {
				// Other error occurred, handle it accordingly
				panic(result.Error)
			}
		} else {
			var foundAccount Account
			for _, account := range user.Accounts {
				if account.Provider == token.Firebase.SignInProvider {
					foundAccount = account
					break
				}
			}

			if foundAccount.ID == "" {
				account := Account{UserId: user.ID, Provider: token.Firebase.SignInProvider, Uid: token.UID}
				database.DB.Create(&account)
			}
		}
	} else {
		result := database.DB.Where(&User{Email: email}).First(&user)

		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"code":    fiber.StatusUnauthorized,
					"success": false,
					"content": "",
					"message": "USER NOT FOUND, PLEASE REGISTER FIRST"})
			} else {
				// Other error occurred, handle it accordingly
				panic(result.Error)
			}
		} else {
			if user.Password == nil {
				return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"code":    fiber.StatusUnauthorized,
					"success": false,
					"content": "",
					"message": "YOU HAVE NOT SET THE PASSWORD, PLEASE REGISTER FIRST"})
			} else if !bcrypt.CheckPasswordHash(data.Password, *user.Password) {
				return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"code":    fiber.StatusUnauthorized,
					"success": false,
					"content": "",
					"message": "WRONG PASSWORD"})

			}
		}

	}

	// TODO: logic buat ticket sampe buat validasi
	now := time.Now()
	service := data.Service
	if service == "" {
		service = fmt.Sprintf("%s", viper.Get("DEFAULT_SERVICE"))
	}

	ticket := updateTicketAndCookies(ctx, user.ID, service, now)

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"code":    fiber.StatusOK,
		"success": true,
		"content": fiber.Map{
			"ticket":   ticket.ID,
			"email":    email,
			"services": service,
		},
		"message": "Success"},
	)
}

func Validate(ctx *fiber.Ctx) error {
	ticketId := ctx.Query("ticket")
	service := ctx.Query("service")
	now := time.Now()

	var ticket Ticket

	result := database.DB.Where(&Ticket{Base: database.Base{ID: ticketId}}).First(&ticket)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"code":    fiber.StatusNotFound,
				"success": false,
				"content": "",
				"message": "Ticket Not Found"},
			)
		} else {
			// Other error occurred, handle it accordingly
			panic(result.Error)
		}
	} else {
		if !now.Before(ticket.ExpiredAt) || ticket.IsExpired || ticket.Status == "BLACKLISTED" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"code":    fiber.StatusUnauthorized,
				"success": false,
				"content": "",
				"message": "Ticket Already Expired"},
			)
		}

		if ticket.Service != service {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"code":    fiber.StatusUnauthorized,
				"success": false,
				"content": "",
				"message": "Wrong Ticket"},
			)
		}
	}

	var user = User{Base: database.Base{ID: ticket.UserId}}
	database.DB.First(&user)

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"code":    fiber.StatusOK,
		"success": true,
		"content": fiber.Map{
			"email": user.Email,
		},
		"message": "Success"},
	)
}

func verifyIDToken(ctx context.Context, app *firebase.App, idToken string) *auth.Token {
	client, err := app.Auth(ctx)
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	token, err := client.VerifyIDToken(ctx, idToken)
	if err != nil {
		log.Fatalf("error verifying ID token: %v\n", err)
	}

	return token
}

func updateTicketAndCookies(ctx *fiber.Ctx, userId string, service string, now time.Time) Ticket {
	blacklistAllTicket(userId, now)
	ticket := createNewTicket(userId, service, now)
	setNewCookies(ctx, userId, now)

	return ticket
}

func blacklistAllTicket(userId string, now time.Time) {
	database.DB.Model(Ticket{}).Where(&Ticket{UserId: userId, IsExpired: false, Status: "ACTIVE"}).Updates(Ticket{IsExpired: true, Status: "BLACKLISTED", BlacklistedAt: &now})
}

func createNewTicket(userId string, service string, now time.Time) Ticket {
	ticket := Ticket{UserId: userId, Service: service, IsExpired: false, Status: "ACTIVE", ExpiredAt: now.Add(5 * time.Minute)}
	database.DB.Create(&ticket)

	return ticket
}

func setNewCookies(ctx *fiber.Ctx, userId string, now time.Time) {
	cookie := new(fiber.Cookie)
	cookie.Name = "token"
	cookie.Value = userId
	cookie.Expires = now.Add(24 * time.Hour)
	ctx.Cookie(cookie)
}
