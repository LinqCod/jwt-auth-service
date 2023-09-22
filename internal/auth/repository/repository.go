package repository

import (
	"context"
	"fmt"
	"github.com/linqcod/jwt-auth-service/internal/auth/model"
	"github.com/linqcod/jwt-auth-service/pkg/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type AuthRepository struct {
	ctx        context.Context
	collection *mongo.Collection
}

func NewAuthRepository(ctx context.Context, collection *mongo.Collection) AuthRepository {
	return AuthRepository{
		ctx:        ctx,
		collection: collection,
	}
}

func (r AuthRepository) SaveRefreshToken(guid, token string, expiredAt time.Time) error {
	hashedToken, err := utils.HashToken(token)
	if err != nil {
		return err
	}

	doc := model.RefreshToken{
		GUID:         guid,
		RefreshToken: hashedToken,
		Ttl:          expiredAt,
	}

	filter := bson.D{{"guid", guid}}
	_, err = r.collection.ReplaceOne(r.ctx, filter, doc, options.Replace().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("error while inserting refresh token to db: %v", err)
	}

	return nil
}

func (r AuthRepository) GetRefreshTokenByGUID(guid string) (*model.RefreshToken, error) {
	var refreshToken model.RefreshToken

	filter := bson.D{{"guid", guid}}
	err := r.collection.FindOne(r.ctx, filter).Decode(&refreshToken)
	if err != nil {
		return nil, fmt.Errorf("error while getting refresh token by guid: %v", err)
	}

	return &refreshToken, nil
}
