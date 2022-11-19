package go_authentication

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Email            string `json:"email"`
	Password         string `json:"password"`
	IsVerified       bool   `json:"isVerified"`
	IsAdmin          bool   `json:"isAdmin"`
	VerificationCode string `json:"verificationCode"`
	RegistrationDate string `json:"registrationDate"`
}
