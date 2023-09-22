package model

import "time"

type RefreshToken struct {
	GUID         string    `json:"guid"`
	RefreshToken string    `json:"refresh_token"`
	Ttl          time.Time `json:"ttl"`
}

type RefreshTokenRequest struct {
	GUID         string `json:"guid"`
	RefreshToken string `json:"refresh_token"`
}

func (t RefreshToken) IsExpired() bool {
	return t.Ttl.Before(time.Now())
}
