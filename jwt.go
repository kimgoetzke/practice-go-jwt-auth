package main

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	audience            = "audience"
	issuer              = "organisation"
	authorizationHeader = "Authorization"
)

type AuthorisedUser struct {
	Id   string
	Name string
}

type CustomClaims struct {
	UserName string `json:"usr"`
	jwt.RegisteredClaims
}

var (
	InvalidJwtError = errors.New("invalid_jwt")
	NoJwtError      = errors.New("missing_jwt")
)

var (
	jwkSet     *jwkset.MemoryJWKSet
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyId      string
)

// Initialises the JWKS. Must be called on startup. Populates jwkSet, privateKey, publicKey and keyId.
// Required to sign and validate JWTs.
func initialiseJwks() {
	privateKey = readOrGeneratePrivateKey()
	publicKey = &privateKey.PublicKey
	hash := sha256.New()
	hash.Write(publicKey.N.Bytes())
	keyId = base64.URLEncoding.EncodeToString(hash.Sum(nil))

	options := jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{
			KID: keyId,
		},
	}

	var err error
	jwk, err := jwkset.NewJWKFromKey(publicKey, options)
	if err != nil {
		log.Fatalf("Failed to create JWK from key: %s", err)
	}
	marshalledJwk := jwk.Marshal()
	//log.Debugf("Using key: %s", prettify(marshalledJwk))
	ctx := context.Background()
	jwkSet = jwkset.NewMemoryStorage()
	err = jwkSet.KeyWrite(ctx, jwk)
	if err != nil {
		log.Fatalf("Failed to store RSA key: %s", err)
	}

	log.Debugf("Stored key [%s] in memory", marshalledJwk.KID)
}

// Creates and signs the JWT using the private key. Adds the kid header to the JWT, so the public key can be found
// in the JWKS when validating the JWT.
func createJwt(user User) (string, error) {
	claims := CustomClaims{
		user.Name,
		jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.Id,
			Audience:  []string{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(Duration)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	unsignedJwt := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	unsignedJwt.Header["kid"] = keyId
	if signedJwt, err := unsignedJwt.SignedString(privateKey); err != nil {
		log.Errorf("Failed to sign JWT: %v\n", err)
		return "", err
	} else {
		return signedJwt, nil
	}
}

// Validates the JWT provided in the authorizationHeader header of the request.
// It returns the AuthorisedUser if the JWT is valid, otherwise it returns an error.
func validateJwt(request *http.Request) (AuthorisedUser, error) {
	tokenString := strings.TrimPrefix(request.Header.Get(authorizationHeader), "Bearer")
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		log.Warning("Validation failed: No JWT provided")
		return AuthorisedUser{}, NoJwtError
	}

	// Parse the JWT without verifying its signature, just to separate error logging.
	// This block can be commented out without affecting the functionality.
	_, _, err := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}),
		jwt.WithAudience(audience),
		jwt.WithIssuer(issuer),
	).ParseUnverified(tokenString, &CustomClaims{})
	if err != nil {
		log.Warningf("Failed to parse JWT: %v\n", err)
		return AuthorisedUser{}, InvalidJwtError
	}

	baseUrl := os.Getenv("JWKS_BASE_URL")
	if baseUrl == "" {
		baseUrl = "http://localhost:8080"
	}

	jwks, err := keyfunc.NewDefault([]string{baseUrl + "/.well-known/jwks.json"})
	if err != nil {
		log.Errorf("Failed to fetch JWKS: %v\n", err)
		return AuthorisedUser{}, err
	}

	verifiedToken, err := jwt.ParseWithClaims(
		tokenString,
		&CustomClaims{},
		jwks.Keyfunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}),
		jwt.WithAudience(audience),
		jwt.WithIssuer(issuer),
	)
	if err != nil {
		log.Warningf("Failed to verify JWT signature: %v\n", err)
		return AuthorisedUser{}, err
	}

	if claims, ok := verifiedToken.Claims.(*CustomClaims); ok && verifiedToken.Valid {
		//log.Debugf("JWT is valid: %v\n", prettify(claims))
		authorisedUser := AuthorisedUser{
			Id:   claims.Subject,
			Name: claims.UserName,
		}
		return authorisedUser, nil
	}

	log.Warningf("Invalid JWT: %v\n", err)
	return AuthorisedUser{}, err
}

// Used to return the JWT Key Set in JSON-format. Set when initialiseJwks is called on startup.
func fetchJwks(request *http.Request) (json.RawMessage, error) {
	jsonJwks, err := jwkSet.JSONPublic(request.Context())
	if err != nil {
		log.Errorf("Failed to get JWK Set JSON: %s", err)
		return nil, err
	}
	return jsonJwks, nil
}
