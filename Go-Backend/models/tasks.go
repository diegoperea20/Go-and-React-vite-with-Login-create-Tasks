package models

import "gorm/db"

type Task struct {
	Id       int64  `json:"id"`
	User  string `json:"user"`
	Title  string `json:"title"`
	Description string `json:"description"`
}

type Tasks []Task

func MigrarTask() {
	db.Database.AutoMigrate(Task{})
}
