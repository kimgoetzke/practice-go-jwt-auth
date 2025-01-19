package main

import (
	"context"
	"net/http"
	"runtime/debug"
)

type contextKey struct{}

var authorisedUserKey = &contextKey{}

var middleware = []func(http.HandlerFunc) http.HandlerFunc{
	recoveryMiddleware,
	requestLoggingMiddleware,
}

func withoutAuth(f func(writer http.ResponseWriter, request *http.Request)) func(writer http.ResponseWriter, request *http.Request) {
	for _, m := range middleware {
		f = m(f)
	}
	return f
}

func withAuth(f func(writer http.ResponseWriter, request *http.Request)) func(writer http.ResponseWriter, request *http.Request) {
	for _, m := range append([]func(http.HandlerFunc) http.HandlerFunc{authMiddleware}, middleware...) {
		f = m(f)
	}
	return f
}

func recoveryMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Errorf("[Recovery] %v\n%s\n", err, string(debug.Stack()))
				log.Infof("Returning status code [%v] to client", http.StatusInternalServerError)
				http.Error(writer, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next(writer, request)
	}
}

func requestLoggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		log.Debugf("Received [%s] %s\n", request.Method, request.URL.Path)
		next(writer, request)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		authorisedUser, jwtErr := validateJwt(request)
		if jwtErr != nil {
			http.Error(writer, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if csrfErr := validateCsrfToken(request, authorisedUser); csrfErr != nil {
			http.Error(writer, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(request.Context(), authorisedUserKey, &authorisedUser)
		request = request.WithContext(ctx)
		log.Debugf("User [%s] is authorised", authorisedUser.Id)
		next(writer, request)
	}
}

func getAuthorisedUser(request *http.Request) *AuthorisedUser {
	ctx := request.Context()
	if authorisedUser, ok := ctx.Value(authorisedUserKey).(*AuthorisedUser); ok {
		return authorisedUser
	}
	log.Errorf("Failed to retrieve authorised user from context: %v", ctx)
	return nil
}
