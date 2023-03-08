package authentication

type Config struct {
	RequireAccountVerification bool
	DefaultAdminEmail          string
	DefaultUsername            string
	DefaultAdminPassword       string
	Secret                     string
}

var gCfg *Config

// GetConfig returns the singleton Config object.
func GetConfig() *Config {
	if gCfg == nil {
		gCfg = &Config{
			// like postgres://<dbuser>:<user>@<host>:<port>/<dbname>
		}
	}
	return gCfg
}

func InitConfig(secret string, defaultAdminEmail string, defaultUsername string, defaultAdminPassword string, requireAccountVerification bool) {
	GetConfig().DefaultUsername = defaultUsername
	GetConfig().RequireAccountVerification = requireAccountVerification
	GetConfig().Secret = secret
	GetConfig().DefaultAdminEmail = defaultAdminEmail
	GetConfig().DefaultAdminPassword = defaultAdminPassword
}
