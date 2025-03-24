package authentication

import (
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"

	"github.com/waterproofpatch/go_authentication/helpers"
	"gorm.io/gorm"
)

var gDb *gorm.DB

// initialize the database, conditionally dropping tables
func resetDb(dropTables bool) {
	log.Printf("Resetting db...")
	db := GetDb()

	// Migrate the schema
	if dropTables {
		log.Printf("Dropping tables...")
		db.Migrator().DropTable(&User{})
	}
	db.AutoMigrate(&User{})
	hashedPassword, err := HashPassword(helpers.GetConfig().DefaultAdminPassword)
	if err != nil {
		panic(err)
	}
	CreateUser(helpers.GetConfig().DefaultAdminEmail, helpers.GetConfig().DefaultUsername, hashedPassword, true, true, "")
}

// getDb returns the database object
func GetDb() *gorm.DB {
	if gDb == nil {
		panic("gDb is not initialized!")
	}
	return gDb
}

func InitDb(dbUrl string, dropTables bool, isDebug bool) {
	var database *gorm.DB
	var err error

	if !isDebug {
		fmt.Println("Getting secret...")
		dbUrl, err = GetSecret("sqlDbPassword", "plantmindrrbackv")
		if err != nil {
			fmt.Println("Error getting secret: ", err)
			panic("Error getting secret")
		}
		fmt.Println("Got secret:", dbUrl)
	} else {
		fmt.Println("Using debug mode...")
		if strings.Contains(dbUrl, "postgres") {
			fmt.Println("Using postgres server")
			database, err = gorm.Open(postgres.Open(dbUrl), &gorm.Config{})
		} else {
			fmt.Println("Using sql server")
			for i := 0; i < 5; i++ {
				err, database = connectToSqlDb(dbUrl)
				if err == nil {
					fmt.Println("Done retrying connection!")
					break
				}
				fmt.Println("Retrying connection...")
				time.Sleep(2 * time.Second)
			}
		}
	}

	if err != nil {
		fmt.Printf("failed to connect database: %s", err)
		panic("failed to connect database")
	}

	gDb = database
	resetDb(dropTables)
}

// sometimes this fails the first time if the db is suspended, so we should retry...
func connectToSqlDb(connString string) (error, *gorm.DB) {
	var db *gorm.DB
	var err error

	db, err = gorm.Open(sqlserver.Open(connString), &gorm.Config{})
	if err != nil {
		fmt.Println("Error creating connection pool: ", err.Error())
		return err, nil
	}
	fmt.Printf("Connected!")
	return nil, db
}
