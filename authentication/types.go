package authentication

import "github.com/dgrijalva/jwt-go"

type Error struct {
	ErrorMessage string `json:"error_message"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWTData struct {
	// Standard claims are the standard jwt claims from the IETF standard
	// https://tools.ietf.org/html/rfc7519
	jwt.StandardClaims
	Email      string `json:"email"`
	IsAdmin    bool   `json:"IsAdmin"`
	IsVerified bool   `json:"isVerified"`
	FirstName  string `json:"firstName"`
	LastName   string `json:"lastName"`
	Phone      string `json:"phone"`
}
