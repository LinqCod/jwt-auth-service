package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/linqcod/jwt-auth-service/internal/auth/handler"
	"github.com/linqcod/jwt-auth-service/internal/auth/repository"
	"github.com/linqcod/jwt-auth-service/pkg/config"
	"github.com/linqcod/jwt-auth-service/pkg/database"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func init() {
	config.LoadConfig(".env")
}

func main() {
	db, err := database.NewMongoDb(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	authCollection := db.Client.Database("auth_mongodb").Collection("tokens")

	authRepository := repository.NewAuthRepository(context.Background(), authCollection)

	authHandler := handler.NewAuthHandler(authRepository)

	http.HandleFunc("/signin", authHandler.Signin)
	http.HandleFunc("/refresh", authHandler.Refresh)

	address := fmt.Sprintf(":%s", viper.GetString("SERVER_PORT"))
	srv := http.Server{
		Addr: address,
	}

	stopped := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-sigint
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Fatalf("error while trying to shutdown http server: %v", err)
		}
		close(stopped)
	}()

	log.Printf("Starting HTTP server on %s", address)

	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server ListenAndServe Error: %v", err)
	}

	<-stopped

	log.Printf("Have a nice day :)")
}
