package authentication

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/thanhpk/randstr"
	"github.com/waterproofpatch/go_authentication/helpers"
	"github.com/waterproofpatch/go_authentication/types"
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

func UpdateUserPassword(user *User, newPasswordHash string) error {
	db := GetDb()
	user.Password = newPasswordHash
	// empty string means that no reset was requested
	user.PasswordResetCode = ""

	log.Printf("Updating password for user email=%s\n", user.Email)

	err := db.Save(&user).Error
	if err != nil {
		return err
	}
	return nil
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

	helpers.GetConfig().RegistrationCallback(email, verificationCode)
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

// Generate access and refresh JWT tokens.
func GenerateJwtTokens(user *User) (string, string, error) {
	// an extra check tightly coupled to token generation, don't generate a
	// token if the user isn't verified.
	if !user.IsVerified {
		return "", "", errors.New("User is not yet verified.")
	}

	refreshClaims := types.JWTData{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 240).Unix(), // 10 days
		},

		Email: user.Email,
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(helpers.GetConfig().RefreshSecret))
	if err != nil {
		return "", "", errors.New("Failed generating refresh token!")
	}

	accessClaims := types.JWTData{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 7).Unix(),
		},

		Email:      user.Email,
		Username:   user.Username,
		IsVerified: user.IsVerified,
		IsAdmin:    user.IsAdmin,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(helpers.GetConfig().Secret))
	if err != nil {
		return "", "", errors.New("Failed generating token!")
	}
	return accessTokenString, refreshTokenString, nil
}

func MakeRefreshTokenCookie(refreshTokenString string) http.Cookie {
	fmt.Println("Making refresh token cookie")
	cookie := http.Cookie{
		// true means no scripts, http requests only. This has
		// nothing to do with https vs http
		HttpOnly: true,
		MaxAge:   60 * 60 * 24 * 7, // 7 days
		Path:     "/api",
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		Secure:   true,
		// http vs https means different URI scheme, local dev
		// has frontend on https and backend on http, prod has
		// front and backend on both https
		SameSite: http.SameSiteNoneMode,
	}
	return cookie
}

func ParseClaims(w http.ResponseWriter, r *http.Request) (bool, *types.JWTData, string, Reason) {
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

func ParseToken(authToken string, isRefresh bool) (bool, *types.JWTData, string, Reason) {
	authArr := strings.Split(authToken, " ")

	if len(authArr) != 2 {
		log.Println("Authentication header is invalid.")
		return false, nil, "Invalid Authorization bearer", BAD_BEARER
	}

	jwtToken := authArr[1]
	token, err := jwt.ParseWithClaims(jwtToken, &types.JWTData{}, func(token *jwt.Token) (interface{}, error) {
		if jwt.SigningMethodHS256 != token.Method {
			return nil, errors.New("Invalid signing algorithm")
		}
		if !isRefresh {
			return []byte(helpers.GetConfig().Secret), nil
		} else {
			return []byte(helpers.GetConfig().RefreshSecret), nil
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

	claims, ok := token.Claims.(*types.JWTData)
	if !ok {
		log.Printf("Failed processing claims\n")
		return false, nil, "Invalid claims", INVALID_CLAIMS
	}
	return true, claims, "", NA
}

func IsAuthorized(w http.ResponseWriter, r *http.Request) (bool, *types.JWTData, string, Reason) {
	// it's enough to just be able to parse the claims
	parsed, claims, errorString, reason := ParseClaims(w, r)
	return parsed, claims, errorString, reason
}

func WriteError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(&types.Error{ErrorMessage: message, Code: 1})
}

func WriteErrorWithCode(w http.ResponseWriter, message string, status int, code int) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(&types.Error{ErrorMessage: message, Code: code})
}

func GetUserByEmail(email string) (*User, error) {
	db := GetDb()
	var user *User
	return user, db.First(&user, "email = ?", email).Error
}

func GetUserById(id string) (*User, error) {
	db := GetDb()
	var user *User
	return user, db.First(&user, "ID = ?", id).Error
}

func GetUserByResetCode(resetCode string) (*User, error) {
	db := GetDb()
	var user *User
	return user, db.First(&user, "password_reset_code = ?", resetCode).Error
}

func GetUserByVerificationCode(verificationCode string) (*User, error) {
	db := GetDb()
	var user *User
	return user, db.First(&user, "verification_code = ?", verificationCode).Error
}

func GetUsers(users *[]User) error {
	db := GetDb()
	return db.Find(users).Error
}

func IsValidInput(input string) bool {
	alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`)
	return alphanumeric.MatchString(input)
}

func IsValidPassword(password string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{3,256}$`)
	return re.MatchString(password)
}
