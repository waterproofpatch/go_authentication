package authentication

import "fmt"

type Config struct {
	RequireAccountVerification bool
	DefaultAdminEmail          string
	DefaultUsername            string
	DefaultAdminPassword       string
	Secret                     string
	RefreshSecret              string
}

var gCfg *Config

// GetConfig returns the singleton Config object.
func GetConfig() *Config {
	if gCfg == nil {
		gCfg = &Config{}
	}
	return gCfg
}

func InitConfig(secret string, refreshSecret string, defaultAdminEmail string, defaultUsername string, defaultAdminPassword string, requireAccountVerification bool) {
	fmt.Printf("Initing authentication config...\n")
	GetConfig().DefaultUsername = defaultUsername
	GetConfig().RequireAccountVerification = requireAccountVerification
	GetConfig().Secret = secret
	GetConfig().RefreshSecret = refreshSecret
	GetConfig().DefaultAdminEmail = defaultAdminEmail
	GetConfig().DefaultAdminPassword = defaultAdminPassword
}
