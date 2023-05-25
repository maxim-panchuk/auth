package userRepository

import (
	"auth/entity"
	"auth/repository"
	"gorm.io/gorm"
	"log"
)

type repo struct {
	db *gorm.DB
}

func (r *repo) Save(userDto *entity.User) error {
	if err := r.db.Create(&userDto).Error; err != nil {
		log.Printf("user save error: %v", err)
		return err
	}
	return nil
}

func (r *repo) CheckIfExists(username string) (bool, error) {
	var user *entity.User
	if err := r.db.Model(&entity.User{}).Select("username").Where("username = ?", username).First(&user).Error; err != nil {
		log.Printf("user find one error: %v", err)
		return false, err
	}
	return true, nil
}

func (r *repo) UpdateRefreshTokenByUsername(refreshToken, username string) error {
	if err := r.db.Model(&entity.User{}).Where("username = ?", username).Update("refresh_token", refreshToken).Error; err != nil {
		log.Printf("user update error: %v", err)
		return err
	}
	return nil
}

func (r *repo) GetRefreshTokenByUsername(username string) (string, error) {
	var refreshToken string
	if err := r.db.Model(&entity.User{}).Select("refresh_token").Where("username = ?", username).First(&refreshToken).Error; err != nil {
		log.Printf("error finding refresh_token by username: %v\n", err)
		return "", err
	}
	return refreshToken, nil
}

func (r *repo) GetRoleByUsername(username string) (string, error) {
	var role string
	if err := r.db.Model(&entity.User{}).Select("role").Where("username = ?", username).First(&role).Error; err != nil {
		log.Printf("error finding role by username: %v\n", err)
		return "", err
	}
	return role, nil
}

func NewUserRepository(db *gorm.DB) repository.UserRepository {
	return &repo{
		db: db,
	}
}
