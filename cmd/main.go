package main

import (
	"context"
	"fmt"
	"github.com/linqcod/jwt-auth-service/internal/auth/handler"
	"github.com/linqcod/jwt-auth-service/internal/auth/repository"
	"github.com/linqcod/jwt-auth-service/pkg/config"
	"github.com/linqcod/jwt-auth-service/pkg/database"
	"github.com/spf13/viper"
	"log"
	"net/http"
)

func init() {
	config.LoadConfig(".env")
}

func main() {
	//init db connection
	db, err := database.NewMongoDb(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	authCollection := db.Client.Database("auth_mongodb").Collection("tokens")

	authRepository := repository.NewAuthRepository(context.Background(), authCollection)

	authHandler := handler.NewAuthHandler(authRepository)

	//router
	http.HandleFunc("/signin", authHandler.Signin)

	address := fmt.Sprintf(":%s", viper.GetString("SERVER_PORT"))
	//server
	log.Printf("server is running on: %s", address)
	log.Fatal(http.ListenAndServe(address, nil))
	//server graceful shutdown
}
