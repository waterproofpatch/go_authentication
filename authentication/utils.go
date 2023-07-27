package authentication

import (
	"errors"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/thanhpk/randstr"
	"golang.org/x/crypto/bcrypt"
)

// Hash password
func HashPassword(password string) (string, error) {
	// Convert password string to byte slice
	passwordBytes := []byte(password)
	// Hash password with Bcrypt's min cost
	hashedPasswordBytes, err := bcrypt.
		GenerateFromPassword(passwordBytes, bcrypt.MinCost)
	return string(hashedPasswordBytes), err
}

// check if email is valid.
func IsValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// create a new user in a database.
func CreateUser(email string, username string, hashedPassword string, isVerified bool, isAdmin bool, verificationCode string) (*User, error) {
	db := GetDb()
	user := User{
		Email:            email,
		Password:         hashedPassword,
		IsVerified:       isVerified,
		IsAdmin:          isAdmin,
		VerificationCode: verificationCode,
		Username:         username,
	}

	log.Printf("Creating user username=%s, isVerified=%t, isAdmin=%t\n", username, isVerified, isAdmin)

	err := db.Create(&user).Error
	if err != nil {
		return nil, err
	}
	user.RegistrationDate = user.CreatedAt.Format(time.RFC1123)
	db.Save(user)
	return &user, nil
}

// Check if two passwords match using Bcrypt's CompareHashAndPassword
// which return nil on success and an error on failure.
func DoPasswordsMatch(hashedPassword, currPassword string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword), []byte(currPassword))
	return err == nil
}

// generate a pseudo-random token
func GeneratePseudorandomToken() string {
	token := randstr.Hex(32)
	return token
}

func GenerateJwtToken(user *User) (string, string, error) {
	// an extra check tightly coupled to token generation, don't generate a token if the user isn't verified.
	if !user.IsVerified {
		return "", "", errors.New("User is not yet verified.")
	}

	refreshClaims := JWTData{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 240).Unix(), // 10 days
		},

		Email: user.Email,
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(GetConfig().RefreshSecret))
	if err != nil {
		return "", "", errors.New("Failed generating refresh token!")
	}

	claims := JWTData{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},

		Email:      user.Email,
		Username:   user.Username,
		IsVerified: user.IsVerified,
		IsAdmin:    user.IsAdmin,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(GetConfig().Secret))
	if err != nil {
		return "", "", errors.New("Failed generating token!")
	}
	return tokenString, refreshTokenString, nil
}

func ParseClaims(w http.ResponseWriter, r *http.Request) (bool, *JWTData, string, Reason) {
	authToken := r.Header.Get("Authorization")
	return ParseToken(authToken, false)
}

type Reason int

const (
	NA Reason = iota
	EXPIRED
	BAD_BEARER
	INVALID_CLAIMS
)

func (r Reason) String() string {
	switch r {
	case NA:
		return "NA"
	case EXPIRED:
		return "EXPIRED"
	case BAD_BEARER:
		return "BAD_BEARER"
	case INVALID_CLAIMS:
		return "INVALID_CLAIMS"
	default:
		return "UNKNOWN"
	}
}

func ParseToken(authToken string, isRefresh bool) (bool, *JWTData, string, Reason) {
	authArr := strings.Split(authToken, " ")

	if len(authArr) != 2 {
		log.Println("Authentication header is invalid.")
		return false, nil, "Invalid Authorization bearer", BAD_BEARER
	}

	jwtToken := authArr[1]
	token, err := jwt.ParseWithClaims(jwtToken, &JWTData{}, func(token *jwt.Token) (interface{}, error) {
		if jwt.SigningMethodHS256 != token.Method {
			return nil, errors.New("Invalid signing algorithm")
		}
		if !isRefresh {
			return []byte(GetConfig().Secret), nil
		} else {
			return []byte(GetConfig().RefreshSecret), nil
		}
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok && ve.Errors&jwt.ValidationErrorExpired != 0 {
			log.Printf("Token is expired\n")
			return false, nil, "Login expired", EXPIRED
		} else {
			log.Printf("Error %v\n", err)
			return false, nil, "Invalid token", BAD_BEARER
		}
	}

	claims, ok := token.Claims.(*JWTData)
	if !ok {
		log.Printf("Failed processing claims\n")
		return false, nil, "Invalid claims", INVALID_CLAIMS
	}
	return true, claims, "", NA
}

func IsAuthorized(w http.ResponseWriter, r *http.Request) (bool, *JWTData, string, Reason) {
	// it's enough to just be able to parse the claims
	parsed, claims, errorString, reason := ParseClaims(w, r)
	return parsed, claims, errorString, reason
}
