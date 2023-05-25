package migrations

import (
	"auth/entity"
	"gorm.io/gorm"
	"log"
)

func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(entity.User{}); err != nil {
		log.Printf("migrate error: %v", err)
		return err
	}
	return nil
}
