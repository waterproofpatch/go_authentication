package authentication

import (
	"fmt"

	"github.com/waterproofpatch/go_authentication/helpers"
	"github.com/waterproofpatch/go_authentication/types"
)

func InitConfig(secret string,
	refreshSecret string,
	defaultAdminEmail string,
	defaultUsername string,
	defaultAdminPassword string,
	requireAccountVerification bool,
	registrationVerifyCallback types.RegistrationVerifyCallback,
	registrationCallbackUrl string,
) {
	fmt.Printf("Initing authentication config...\n")
	helpers.GetConfig().DefaultUsername = defaultUsername
	helpers.GetConfig().RequireAccountVerification = requireAccountVerification
	helpers.GetConfig().Secret = secret
	helpers.GetConfig().RefreshSecret = refreshSecret
	helpers.GetConfig().DefaultAdminEmail = defaultAdminEmail
	helpers.GetConfig().DefaultAdminPassword = defaultAdminPassword
	helpers.GetConfig().RegistrationCallback = registrationVerifyCallback
	helpers.GetConfig().RegistrationCallbackUrl = registrationCallbackUrl
}
