package go_authentication

import (
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var gDb *gorm.DB

func ResetDb(dropTables bool) {
	log.Printf("Resetting db...")
	db := GetDb()

	// Migrate the schema
	if dropTables {
		log.Printf("Dropping tables...")
		db.Migrator().DropTable(&User{})
	}
	db.AutoMigrate(&User{})
}

func InitDb(dbUrl string, dropTables string) {
	database, err := gorm.Open(postgres.Open(dbUrl), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Read
	gDb = database
	ResetDb(dropTables == "true")
}

// getDb returns the database object
func GetDb() *gorm.DB {
	if gDb == nil {
		panic("gDb is not initialized!")
	}
	return gDb
}
