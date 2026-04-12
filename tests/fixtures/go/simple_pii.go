package main

import (
	"fmt"
	"log"
)

type UserProfile struct {
	Email       string
	FullName    string
	PhoneNumber string
	SSN         string
	Password    string
}

func ProcessUser(user UserProfile) {
	log.Printf("Processing user: %s", user.Email)
	fmt.Println(user.FullName)

	email := user.Email
	password := GetPassword()
	_ = password

	SaveToDB(email, user.SSN)
}

func GetPassword() string {
	return "secret"
}

func SaveToDB(email string, ssn string) {
	// db operation
}
