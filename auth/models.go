package auth

import (
	"ez-sso/database"
	"time"
)

type User struct {
	database.Base
	Email    string
	Password *string
	Accounts []Account
}

type Account struct {
	database.Base
	UserId   string
	Provider string
	Uid      string
}

type Ticket struct {
	database.Base
	UserId        string
	Service       string
	IsExpired     bool
	Status        string
	ExpiredAt     time.Time
	BlacklistedAt *time.Time
}
