package main

import (
	"context"
	"github.com/linqcod/jwt-auth-service/pkg/config"
	"github.com/linqcod/jwt-auth-service/pkg/database"
	"log"
)

func init() {
	config.LoadConfig(".env")
}

func main() {

	//init db connection
	db, err := database.ConnectToMongoDb(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// cookies

	//router

	//server

	//server graceful shutdown
}
