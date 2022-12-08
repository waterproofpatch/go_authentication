package go_authentication

import "github.com/gorilla/mux"

func Init(secret string, defaultAdminUser string, defaultAdminPassword string, router *mux.Router, dbUrl string, dropTables bool) {
	InitConfig(secret, defaultAdminUser, defaultAdminPassword)
	InitViews(router)
	InitDb(dbUrl, dropTables)
}
