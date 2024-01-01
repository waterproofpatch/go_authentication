package types

import "github.com/dgrijalva/jwt-go"

type Error struct {
	ErrorMessage string `json:"error_message"`
	Code         int    `json:"code"` // 1 for generic, 2 for not verified
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	RequiresVerification bool `json:"requiresVerification"`
	AlreadyVerified      bool `json:"alreadyVerified"`
}

type JWTData struct {
	// Standard claims are the standard jwt claims from the IETF standard
	// https://tools.ietf.org/html/rfc7519
	jwt.StandardClaims
	Email      string `json:"email"`
	Username   string `json:"username"`
	IsAdmin    bool   `json:"isAdmin"`
	IsVerified bool   `json:"isVerified"`
}

// callers provide an implementation to be called when a user is registered
type RegistrationVerifyCallback func(string, string) error
