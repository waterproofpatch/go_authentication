package types

import "github.com/dgrijalva/jwt-go"

type Error struct {
	ErrorMessage string `json:"errorMessage"`
	Code         int    `json:"errorCode"`
}

type ResetRequest struct {
	Email string `json:"email"`
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
// arg1: email, arg2: verificationCode
type RegistrationVerifyCallback func(string, string) error

// callers provide an implementation to be called when a user is resetting their password
// arg1: email, arg2: reset code
type ResetPasswordCallback func(string, string) error
