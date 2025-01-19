package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	CsrfToken = "csrf_token"
	Jwt       = "jwt"
	Duration  = 24 * time.Hour
)

func main() {
	initialiseLogger()
	initialiseJwks()

	http.HandleFunc("/register", withoutAuth(register))
	http.HandleFunc("/login", withoutAuth(login))
	http.HandleFunc("/logout", withAuth(logout))
	http.HandleFunc("/protected", withAuth(protected))
	http.HandleFunc("/.well-known/jwks.json", withoutAuth(jwks))
	_ = http.ListenAndServe(":8080", nil)
}

func register(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := request.FormValue("username")
	password := request.FormValue("password")

	if len(username) < 3 || len(password) < 8 {
		http.Error(writer, "Invalid username and/or password", http.StatusNotAcceptable)
		return
	}

	if user, err := createUser(writer, username, password); err != nil {
		if errors.Is(err, UserExistsError) {
			http.Error(writer, "Username already taken", http.StatusConflict)
		} else {
			http.Error(writer, "Failed to register user", http.StatusInternalServerError)
		}
	} else {
		log.Infof("👤 Registered a new user with name [%s] and ID [%s]", user.Name, user.Id)
		_, _ = fmt.Fprintf(writer, "User registered successfully")
	}
}

func login(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, credentialsErr := verifyCredentials(request)
	if credentialsErr != nil {
		http.Error(writer, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	csrfToken := generateCsrfToken(32)
	jwt, jwtErr := createJwt(user)
	if jwtErr != nil {
		http.Error(writer, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     CsrfToken,
		Value:    csrfToken,
		Expires:  time.Now().Add(Duration),
		HttpOnly: false,
	})
	http.SetCookie(writer, &http.Cookie{
		Name:     Jwt,
		Value:    jwt,
		Expires:  time.Now().Add(Duration),
		HttpOnly: true,
	})
	writer.Header().Set("Authorization", fmt.Sprintf("Bearer %v", jwt))

	user.CsrfToken = csrfToken
	user.Jwt = jwt
	users[user.Id] = user

	log.Infof("🤝 User [%s] is now logged in", user.Id)
	_, _ = fmt.Fprintf(writer, "User logged in successfully")
}

func protected(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authorisedUser := getAuthorisedUser(request)
	log.Infof("🔓 User [%s] accessed protected resource", authorisedUser.Id)
	_, _ = fmt.Fprintf(writer, "Welcome, %s!", authorisedUser.Name)
}

func logout(writer http.ResponseWriter, request *http.Request) {
	authorisedUser := getAuthorisedUser(request)

	http.SetCookie(writer, &http.Cookie{
		Name:     Jwt,
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
	})
	http.SetCookie(writer, &http.Cookie{
		Name:     CsrfToken,
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: false,
	})

	user, _ := users[authorisedUser.Id]
	user.CsrfToken = ""
	user.Jwt = ""
	users[authorisedUser.Id] = user

	log.Infof("👋 User [%s] logged out successfully", authorisedUser.Id)
	_, _ = fmt.Fprintf(writer, "User logged out successfully")
}

func jwks(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jsonJwks, err := fetchJwks(request)
	if err != nil {
		http.Error(writer, "Failed to generate JWKS", http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	if _, err := writer.Write(jsonJwks); err != nil {
		log.Errorf("Failed to write JWK Set JSON: %s", err)
	}

	log.Debug("🔐 Returned JWKS")
}
