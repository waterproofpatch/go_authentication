package authentication

import "github.com/gorilla/mux"

func Init(secret string, defaultAdminUser string, defaultAdminPassword string, router *mux.Router, dbUrl string, dropTables bool, requireAccountVerification bool) {
	InitConfig(secret, defaultAdminUser, defaultAdminPassword, requireAccountVerification)
	InitViews(router)
	InitDb(dbUrl, dropTables)
}
