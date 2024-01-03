package authentication

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Email             string `json:"email"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	IsVerified        bool   `json:"isVerified"`
	IsAdmin           bool   `json:"isAdmin"`
	VerificationCode  string `json:"verificationCode"`
	PasswordResetCode string `json:"passwordResetCode"`
	RegistrationDate  string `json:"registrationDate"`
}
