package authentication

import "github.com/gorilla/mux"

func Init(secret string,
	defaultAdminEmail string,
	defaultAdminUsername string,
	defaultAdminPassword string,
	router *mux.Router,
	dbUrl string,
	dropTables bool,
	requireAccountVerification bool) {
	InitConfig(secret,
		defaultAdminEmail,
		defaultAdminUsername,
		defaultAdminPassword,
		requireAccountVerification)
	InitViews(router)
	InitDb(dbUrl, dropTables)
}
