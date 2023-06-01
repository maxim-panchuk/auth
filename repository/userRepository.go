package repository

import "auth/entity"

type UserRepository interface {
	GetRefreshTokenByUsername(username string) (string, error)
	UpdateRefreshTokenByUsername(refreshToken, username string) error
	CheckIfExists(username string) (bool, error)
	Save(userDto *entity.User) error
	GetRoleByUsername(username string) (string, error)
	GetIdByUsername(username string) (int, error)
}
