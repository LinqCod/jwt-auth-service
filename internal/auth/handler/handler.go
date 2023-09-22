package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/linqcod/jwt-auth-service/internal/auth/model"
	"github.com/linqcod/jwt-auth-service/pkg/utils"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type AuthRepository interface {
	SaveRefreshToken(guid, token string, expiredAt time.Time) error
	GetRefreshTokenByGUID(guid string) (*model.RefreshToken, error)
}

type AuthHandler struct {
	authRepo AuthRepository
}

func NewAuthHandler(authRepo AuthRepository) AuthHandler {
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

func (h AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var refreshTokenReq model.RefreshTokenRequest
	err := json.NewDecoder(r.Body).Decode(&refreshTokenReq)
	if err != nil {
		log.Printf("error while decoding request body: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	refreshToken, err := h.authRepo.GetRefreshTokenByGUID(refreshTokenReq.GUID)
	if err != nil {
		log.Printf("error while refreshing token: %v", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	decodedToken, err := base64.StdEncoding.DecodeString(refreshTokenReq.RefreshToken)
	if err != nil {
		log.Printf("error while decoding refresh token: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = utils.VerifyToken(refreshToken.RefreshToken, string(decodedToken)); err != nil {
		log.Printf("error while verifying refresh token: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if refreshToken.IsExpired() {
		http.Error(w, errors.New("error: given refresh token is expired").Error(), http.StatusForbidden)
		return
	}

	accessToken, err := r.Cookie("access_token")
	if err != nil {
		log.Printf("error while getting access token: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	payload, err := utils.ValidateToken(accessToken.Value, viper.GetString("ACCESS_TOKEN_PUBLIC_KEY"))
	if err != nil {
		log.Printf("error while validating access token: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if strings.Compare(payload.(string), refreshTokenReq.GUID) != 0 {
		log.Printf("error while validating relationship between access and refresh tokens: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	newAccessTokenTtl, err := time.ParseDuration(viper.GetString("ACCESS_TOKEN_EXPIRED_IN"))
	if err != nil {
		log.Printf("error while parsing ttl: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newAccessToken, err := utils.CreateJWTToken(newAccessTokenTtl, refreshTokenReq.GUID, viper.GetString("ACCESS_TOKEN_PRIVATE_KEY"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newRefreshTokenTtl, err := time.ParseDuration(viper.GetString("REFRESH_TOKEN_EXPIRED_IN"))
	if err != nil {
		log.Printf("error while parsing ttl: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newRefreshTokenExpiredAt := time.Now().Add(newRefreshTokenTtl)
	newRefreshToken, err := utils.CreateSecureToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.authRepo.SaveRefreshToken(refreshTokenReq.GUID, newRefreshToken, newRefreshTokenExpiredAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newAccessTokenMaxAge, err := strconv.Atoi(viper.GetString("ACCESS_TOKEN_MAX_AGE"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "access_token",
		Value:  newAccessToken,
		MaxAge: newAccessTokenMaxAge * 60,
	})

	tokenResponse := model.RefreshToken{
		GUID:         refreshTokenReq.GUID,
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(newRefreshToken)),
		Ttl:          newRefreshTokenExpiredAt,
	}

	json.NewEncoder(w).Encode(tokenResponse)
}
