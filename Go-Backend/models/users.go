package models

import "gorm/db"

type User struct {
	Id       int64  `json:"id"`
	Email  string `json:"email"`
	User  string `json:"user"`
	Password string `json:"password"`
	
}

type Users []User

func MigrarUser() {
	db.Database.AutoMigrate(User{})
}
