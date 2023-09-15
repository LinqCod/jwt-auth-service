package handler

import (
	"encoding/base64"
	"encoding/json"
	"github.com/linqcod/jwt-auth-service/internal/auth/model"
	"github.com/linqcod/jwt-auth-service/internal/auth/repository"
	"github.com/linqcod/jwt-auth-service/pkg/utils"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"strconv"
	"time"
)

//TODO: repo interface

type AuthHandler struct {
	authRepo repository.AuthRepository
}

func NewAuthHandler(authRepo repository.AuthRepository) AuthHandler {
	return AuthHandler{
		authRepo: authRepo,
	}
}

func (h AuthHandler) Signin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	guid := r.URL.Query().Get("guid")

	accessTokenTtl, err := time.ParseDuration(viper.GetString("ACCESS_TOKEN_EXPIRED_IN"))
	if err != nil {
		log.Printf("error while parsing ttl: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	accessToken, err := utils.CreateJWTToken(accessTokenTtl, guid, viper.GetString("ACCESS_TOKEN_PRIVATE_KEY"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	refreshTokenTtl, err := time.ParseDuration(viper.GetString("REFRESH_TOKEN_EXPIRED_IN"))
	if err != nil {
		log.Printf("error while parsing ttl: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//TODO: create refresh token
	refreshTokenExpiredAt := time.Now().Add(refreshTokenTtl)
	refreshToken, err := utils.CreateSecureToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.authRepo.SaveRefreshToken(guid, refreshToken, refreshTokenExpiredAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	accessTokenMaxAge, err := strconv.Atoi(viper.GetString("ACCESS_TOKEN_MAX_AGE"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "access_token",
		Value:  accessToken,
		MaxAge: accessTokenMaxAge * 60,
	})

	tokenResponse := model.RefreshToken{
		GUID:         guid,
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(refreshToken)),
		Ttl:          refreshTokenExpiredAt,
	}

	json.NewEncoder(w).Encode(tokenResponse)
}
