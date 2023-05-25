package entity

type User struct {
	ID           int64  `gorm:"primaryKey"`
	Username     string `gorm:"unique"`
	Password     string
	Role         string
	RefreshToken string
}
