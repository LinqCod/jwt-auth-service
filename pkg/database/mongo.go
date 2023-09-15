package database

import (
	"context"
	"errors"
	"fmt"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
)

type MongoDb struct {
	ctx    context.Context
	Client *mongo.Client
}

func NewMongoDb(ctx context.Context) (*MongoDb, error) {
	host := viper.GetString("MONGODB_HOST")
	port := viper.GetString("MONGODB_PORT")

	clientOptions := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%s", host, port))

	mongoClient, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("error while creating mongodb client: %v", err)
	}
	log.Println("mongoDB successfully connected!")

	if err := mongoClient.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("error while trying to ping mongodb: %v", err)
	}
	log.Println("mongoDB successfully ping!")

	return &MongoDb{
		ctx:    ctx,
		Client: mongoClient,
	}, nil
}

func (db *MongoDb) Close() {
	if db.Client == nil {
		log.Fatalf("error while closing db: %v", errors.New("mongo client is nil"))
	}

	err := db.Client.Disconnect(db.ctx)
	if err != nil {
		log.Fatalf("error while closing db: %v", err)
	}

	log.Println("mongodb client closed successfully!")
}
