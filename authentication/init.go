package authentication

import "github.com/gorilla/mux"

func Init(secret string,
	refreshSecret string,
	defaultAdminEmail string,
	defaultAdminUsername string,
	defaultAdminPassword string,
	router *mux.Router,
	dbUrl string,
	dropTables bool,
	requireAccountVerification bool,
	registrationVerifyCallback RegistrationVerifyCallback,
) {
	InitConfig(secret,
		refreshSecret,
		defaultAdminEmail,
		defaultAdminUsername,
		defaultAdminPassword,
		requireAccountVerification,
		registrationVerifyCallback)
	InitViews(router)
	InitDb(dbUrl, dropTables)
}
