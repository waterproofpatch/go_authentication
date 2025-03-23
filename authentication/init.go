package authentication

import (
	"fmt"

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
	resetPasswordCallback types.ResetPasswordCallback,
	registrationVerifyCallback types.RegistrationVerifyCallback,
	registrationCallbackUrl string,
) {
	fmt.Println("Initializing go_authentication...")
	InitConfig(secret,
		refreshSecret,
		defaultAdminEmail,
		defaultAdminUsername,
		defaultAdminPassword,
		requireAccountVerification,
		resetPasswordCallback,
		registrationVerifyCallback,
		registrationCallbackUrl)
	InitViews(router)
	InitDb(dbUrl, dropTables)
}
