package go_authentication

import "github.com/gorilla/mux"

func Init(secret string, defaultAdminUser string, defaultAdminPassword string, router *mux.Router) {
	InitConfig(secret, defaultAdminUser, defaultAdminPassword)
	InitViews(router)
}
