package authentication

type Config struct {
	RequireAccountVerification bool
	DefaultAdminUser           string
	DefaultAdminPass           string
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

func InitConfig(secret string, defaultAdminUser string, defaultAdminPassword string, requireAccountVerification bool) {
	GetConfig().RequireAccountVerification = requireAccountVerification
	GetConfig().Secret = secret
	GetConfig().DefaultAdminUser = defaultAdminUser
	GetConfig().DefaultAdminPass = defaultAdminPassword
}
