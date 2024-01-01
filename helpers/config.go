package helpers

import "github.com/waterproofpatch/go_authentication/types"

type Config struct {
	RequireAccountVerification bool
	DefaultAdminEmail          string
	DefaultUsername            string
	DefaultAdminPassword       string
	Secret                     string
	RefreshSecret              string
	RegistrationCallback       types.RegistrationVerifyCallback
	RegistrationCallbackUrl    string
}

var gCfg *Config

// GetConfig returns the singleton Config object.
func GetConfig() *Config {
	if gCfg == nil {
		gCfg = &Config{}
	}
	return gCfg
}
