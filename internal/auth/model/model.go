package model

import "time"

type RefreshToken struct {
	GUID         string    `json:"GUID"`
	RefreshToken string    `json:"refresh_token"`
	Ttl          time.Time `json:"ttl"`
}

func (t RefreshToken) isExpired() bool {
	return t.Ttl.After(time.Now())
}
