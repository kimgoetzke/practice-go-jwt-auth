package main

import (
	"errors"
	"github.com/google/uuid"
	"net/http"
	"strings"
)

type User struct {
	Id             string
	Name           string
	HashedPassword string
	Jwt            string
	CsrfToken      string
}

var UserNotFoundError = errors.New("user_not_found")
var UserExistsError = errors.New("user_exists")
var users = map[string]User{}

func createUser(writer http.ResponseWriter, username, password string) (User, error) {
	if userExists(username) {
		return User{}, UserExistsError
	}

	newUuid, err := uuid.NewV7()
	if err != nil {
		log.Warningf("Failed to generate UUID: %v\n", err)
		http.Error(writer, "Failed to register user", http.StatusInternalServerError)
		return User{}, err
	}

	userId := "PAR~" + strings.ReplaceAll(newUuid.String(), "-", "")
	hashedPassword, _ := hashPassword(password)
	user := User{
		Id:             userId,
		HashedPassword: hashedPassword,
		Name:           username,
	}
	users[userId] = user

	return user, nil
}

func userExists(name string) bool {
	if _, err := fetchUser(name); err != nil {
		return false
	}
	return true
}

func fetchUser(name string) (User, error) {
	for _, user := range users {
		if user.Name == name {
			return user, nil
		}
	}
	return User{}, UserNotFoundError
}
