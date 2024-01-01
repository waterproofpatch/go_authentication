package authentication

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/gorilla/mux"
	"github.com/waterproofpatch/go_authentication/helpers"
	"github.com/waterproofpatch/go_authentication/types"
)

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

func getUserByEmail(email string) (*User, error) {
	db := GetDb()
	var user *User
	return user, db.First(&user, "email = ?", email).Error
}

func getUserById(id string) (*User, error) {
	db := GetDb()
	var user *User
	return user, db.First(&user, "ID = ?", id).Error
}

func getUserByVerificationCode(verificationCode string) (*User, error) {
	db := GetDb()
	var user *User
	return user, db.First(&user, "verification_code = ?", verificationCode).Error
}

func getUsers(users *[]User) error {
	db := GetDb()
	return db.Find(users).Error
}

func isValidInput(input string) bool {
	alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9_]{3,16}$`)
	return alphanumeric.MatchString(input)
}

func isValidPassword(password string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{3,256}$`)
	return re.MatchString(password)
}

func register(w http.ResponseWriter, r *http.Request) {
	var registerRequest types.RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&registerRequest)
	if err != nil {
		WriteError(w, "Invalid request!", http.StatusBadRequest)
		return
	}
	if !isValidPassword(registerRequest.Password) {
		WriteError(w, "Invalid password!", http.StatusBadRequest)
		return
	}
	if !isValidInput(registerRequest.Username) {
		WriteError(w, "Invalid username!", http.StatusBadRequest)
		return
	}

	// check that the email is valid
	if !IsValidEmail(registerRequest.Email) {
		WriteError(w, "Invalid email!", http.StatusBadRequest)
		return
	}

	_, err = getUserByEmail(registerRequest.Email)
	if err == nil {
		WriteError(w, "Email taken", http.StatusBadRequest)
		return
	}
	hashedPassword, err := HashPassword(registerRequest.Password)
	if err != nil {
		WriteError(w, "Failed hashing password", http.StatusInternalServerError)
		return
	}
	_, err = CreateUser(registerRequest.Email,
		registerRequest.Username,
		hashedPassword,
		!helpers.GetConfig().RequireAccountVerification, // isVerified
		false, // isAdmin
		GeneratePseudorandomToken())
	if err != nil {
		WriteError(w, "Failed creating your account. This isn't your fault.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&types.RegisterResponse{
		RequiresVerification: helpers.GetConfig().RequireAccountVerification,
		AlreadyVerified:      false,
	})
}

// parse the refresh token from the supplied cookie, and if valid, issue a new
// access token and new refresh token.
func refresh(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie("RefreshToken")
	if err != nil {
		WriteError(w, "Unable to read refresh token.", http.StatusUnauthorized)
		return
	}
	tokenCookieWithBearer := fmt.Sprintf("Bearer %s", tokenCookie.Value)
	success, jwt, errorStr, reason := ParseToken(tokenCookieWithBearer, true)
	if !success {
		fmt.Printf("Failed parsing refreshToken: %s, reason=%s", errorStr, reason)
		WriteError(w, "Failed parsing refreshToken", http.StatusUnauthorized)
		return
	}
	var user *User
	user, err = getUserByEmail(jwt.Email)
	if err != nil {
		WriteError(w, "No user for email from the refresh token.", http.StatusUnauthorized)
		return
	}
	// make a new token
	accessTokenString, refreshTokenString, err := GenerateJwtTokens(user)
	if err != nil {
		WriteError(w, "Faled getting token string!", http.StatusInternalServerError)
		return
	}

	// the access token comes back to the JSON frontend, the refresh token
	// is not sent in the payload, but rather the header as a cookie, for
	// the browser to take care of
	json, err := json.Marshal(struct {
		Token string `json:"token"`
	}{
		accessTokenString,
	})
	if err != nil {
		log.Println(err)
		WriteError(w, "Failed generating a new token", http.StatusInternalServerError)
		return
	}

	refreshCookie := MakeRefreshTokenCookie(refreshTokenString)
	http.SetCookie(w, &refreshCookie)
	w.Write(json)
	return
}

// destroy the refreshtoken on the client so their browser
// doesn't hold onto it anymore.
func logout(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Destroying refresh token...")
	deleteAccessTokenCookie := http.Cookie{
		Name:     "AccessToken",
		Path:     "/api",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	deleteRefreshTokenCookie := http.Cookie{
		Name:     "RefreshToken",
		Path:     "/api",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(w, &deleteRefreshTokenCookie)
	http.SetCookie(w, &deleteAccessTokenCookie)
	return
}

func login(w http.ResponseWriter, r *http.Request) {
	var loginRequest types.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		WriteError(w, "Invalid request!", http.StatusBadRequest)
		return
	}

	var user *User
	user, err = getUserByEmail(loginRequest.Email)
	if err != nil {
		WriteError(w, "Invalid credentials!", http.StatusUnauthorized)
		return
	}

	if DoPasswordsMatch(user.Password, loginRequest.Password) {

		// only verified users can log in
		if !user.IsVerified {
			WriteErrorWithCode(w, "This account is not yet verified.", http.StatusUnauthorized, 2)
			return
		}

		accessTokenString, refreshTokenString, err := GenerateJwtTokens(user)
		if err != nil {
			WriteError(w, "Faled getting token string!", http.StatusInternalServerError)
			return
		}

		// the access token comes back to the JSON frontend,
		// the refresh token is not sent in the payload, but
		// rather the header, for the browser to take care of
		json, err := json.Marshal(struct {
			Token string `json:"token"`
		}{
			accessTokenString,
		})
		if err != nil {
			log.Println(err)
			WriteError(w, "Failed generating a new token", http.StatusInternalServerError)
			return
		}

		refreshCookie := MakeRefreshTokenCookie(refreshTokenString)
		http.SetCookie(w, &refreshCookie)
		w.Write(json)
	} else {
		WriteError(w, "Invalid credentials!", http.StatusUnauthorized)
	}
}

func users(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		break
	case "PUT":
		vars := mux.Vars(r)
		db := GetDb()
		option := r.URL.Query().Get("option")
		switch option {
		case "approve":
			verificationCode := r.URL.Query().Get("verificationCode")
			user, err := getUserByVerificationCode(verificationCode)
			if err != nil {
				WriteError(w, "Invalid verification code.", http.StatusBadRequest)
				return
			} else {
				user.IsVerified = true
				db.Save(user)
			}
			break
		case "deny":
			break
		case "revoke":
			id, hasUserId := vars["id"]
			if !hasUserId {
				WriteError(w, "Invalid user ID", http.StatusBadRequest)
				return
			}
			user, err := getUserById(id)
			if err != nil {
				WriteError(w, "Unable to find user", http.StatusBadRequest)
				return
			}

			user.IsVerified = false
			db.Save(user)
			break
		default:
			WriteError(w, "Invalid option", http.StatusBadRequest)
			return
		}
		break
	}

	var users []User
	err := getUsers(&users)
	if err != nil {
		WriteError(w, "Failed obtaining users", http.StatusBadRequest)
		return
	}
	json, err := json.Marshal(users)
	w.Write(json)
}

// attempt to verify a user by their code
// Example:
// https://<host>:<port>/api/verify?code=<code>&email=<email>
func verify(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	email := r.URL.Query().Get("email")

	user, err := getUserByVerificationCode(code)

	if user.Email != email || err != nil {
		WriteError(w, "Invalid code.", http.StatusBadRequest)
		return
	}

	// user should now be able to log in
	user.IsVerified = true
	// no sense in keeping this
	user.VerificationCode = ""

	GetDb().Save(user)

	// Redirect the user
	http.Redirect(w, r, helpers.GetConfig().RegistrationCallbackUrl, http.StatusSeeOther)
}

func InitViews(router *mux.Router) {
	router.HandleFunc("/api/verify", verify).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/login", login).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/logout", logout).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/refresh", refresh).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/register", register).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/users", AdminOnly(users)).Methods("GET", "PUT", "OPTIONS")
	router.HandleFunc("/api/users/{id:[0-9]+}", AdminOnly(users)).Methods("POST", "GET", "OPTIONS", "PUT")
}
