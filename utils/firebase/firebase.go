package firebase

import (
	"context"
	"fmt"
	"log"

	firebase "firebase.google.com/go/v4"
	"github.com/spf13/viper"
	"google.golang.org/api/option"
)

var Admin *firebase.App

func Initiate() {
	creds := fmt.Sprintf("%s", viper.Get("creds"))

	opt := option.WithCredentialsJSON([]byte(creds))

	admin, err := firebase.NewApp(context.Background(), nil, opt)

	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	Admin = admin
}
