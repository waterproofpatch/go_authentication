package go_authentication

import (
	"fmt"
	"os"
)

type Config struct {
	Port             string
	DefaultAdminUser string
	DefaultAdminPass string
	Secret           string
}

var gCfg *Config

func GetFromEnv(varName string) string {
	val, found := os.LookupEnv(varName)
	s := fmt.Sprintf("Failed finding %v", varName)
	if !found {

		panic(s)
	}
	return val
}

// GetConfig returns the singleton Config object.
func GetConfig() *Config {
	if gCfg == nil {
		gCfg = &Config{
			// like postgres://<dbuser>:<user>@<host>:<port>/<dbname>
			Secret:           GetFromEnv("SECRET"),
			DefaultAdminUser: GetFromEnv("DEFAULT_ADMIN_USER"),
			DefaultAdminPass: GetFromEnv("DEFAULT_ADMIN_PASSWORD"),
		}
	}
	return gCfg
}
