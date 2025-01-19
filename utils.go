package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"strings"
)

var (
	InvalidCredentialsError = errors.New("invalid_credentials")
	SessionError            = errors.New("session_error")
)

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func passwordMatches(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		log.Infof("Error: %v\n", err)
	}
	return err == nil
}

func verifyCredentials(request *http.Request) (User, error) {
	password := request.FormValue("password")
	username := request.FormValue("username")

	if user, exists := fetchUser(username); exists != nil {
		log.Warningf("User [%v] not found\n", username)
		return User{}, InvalidCredentialsError
	} else if !passwordMatches(password, user.HashedPassword) {
		log.Warningf("Invalid password for user [%v]\n", username)
		return User{}, InvalidCredentialsError
	} else {
		return user, nil
	}
}

func validateCsrfToken(request *http.Request, authorisedUser AuthorisedUser) error {
	csrf := request.Header.Get("X-CSRF-Token")
	user := users[authorisedUser.Id]

	if csrf == "" || csrf != user.CsrfToken {
		log.Warningf("Invalid CSRF token: Provided [%s] but expected [%s]\n", csrf, user.CsrfToken)
		return SessionError
	}
	return nil
}

func generateCsrfToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate token: %v\n", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func readOrGeneratePrivateKey() *rsa.PrivateKey {
	var err error
	keyData := os.Getenv("JWK_PRIVATE_KEY")
	if keyData == "" {
		// Generate new
		log.Debug("No private key provided, generating new key pair...")
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Error generating keys: %v", err)
		}
	} else if strings.HasSuffix(keyData, ".pem") {
		// Read from file
		log.Debugf("Reading private key from file: %s\n", keyData)
		file, err := os.ReadFile(keyData)
		if err != nil {
			log.Fatalf("Error reading key file: %v", err)
		}
		privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(file)
		if err != nil {
			log.Fatalf("Error parsing key from file: %v", err)
		}
	} else {
		// Read from env var
		log.Debugf("Using private key from environment var: %s\n", keyData)
		privateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(keyData))
		if err != nil {
			log.Fatalf("Error parsing key from environment var: %v", err)
		}
	}
	return privateKey
}

//goland:noinspection GoUnusedFunction
func prettify(value interface{}) string {
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		log.Errorf("Failed to prettify JSON: %s", err)
		return ""
	}
	return string(bytes)
}
