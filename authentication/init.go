package authentication

import (
	"github.com/gorilla/mux"
	"github.com/waterproofpatch/go_authentication/types"
)

func Init(secret string,
	refreshSecret string,
	defaultAdminEmail string,
	defaultAdminUsername string,
	defaultAdminPassword string,
	router *mux.Router,
	dbUrl string,
	dropTables bool,
	requireAccountVerification bool,
	registrationVerifyCallback types.RegistrationVerifyCallback,
	registrationCallbackUrl string,
) {
	InitConfig(secret,
		refreshSecret,
		defaultAdminEmail,
		defaultAdminUsername,
		defaultAdminPassword,
		requireAccountVerification,
		registrationVerifyCallback,
		registrationCallbackUrl)
	InitViews(router)
	InitDb(dbUrl, dropTables)
}
