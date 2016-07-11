package models

import (
	"time"
	"github.com/adam-hanna/goLang-jwt-auth-example/randomstrings"
	jwt "github.com/dgrijalva/jwt-go"
)

type User struct {
	Username, PasswordHash, Role string
}

// https://tools.ietf.org/html/rfc7519
type TokenClaims struct {
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

const RefreshTokenValidTime = time.Hour * 72
const AuthTokenValidTime = time.Minute * 15

func GenerateCSRFSecret() (string, error) {
	return randomstrings.GenerateRandomString(32)
}