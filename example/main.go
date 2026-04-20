package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ErikKalkoken/eveauth"
)

func main() {
	client, err := eveauth.NewClient(eveauth.Config{
		ClientID: os.Getenv("SSO_CLIENT_ID"),
		Port:     30123,
	})
	if err != nil {
		panic(err)
	}
	tok, err := client.Authorize(context.Background(), []string{"publicData"})
	if err != nil {
		panic(err)
	}
	fmt.Println(tok)
}
